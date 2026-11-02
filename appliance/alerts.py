"""Suricata eve.json -> SQLite Threat Alert ingester (PBI-14).

Reads Suricata `alert` events from eve.json (and its rotated `eve.json-<ts>`
files), writes Threat Alerts into the `alerts` table, and persists the read
position transactionally so no event is stored twice across restarts.

Design notes:
- Only `event_type == "alert"` events are ingested. Decoder-event alerts may have
  no addresses/ports; those fields are then NULL and the alert links to no device.
- Severity from the matched rule priority (eve `alert.severity`):
  1 -> Critical, 2 -> High, 3 -> Medium, >=4 -> Low.
- Device linking matches src/dst against the device inventory; both match ->
  source device (the other IP is still stored); neither -> device_mac NULL.
- Deduplication: the same rule firing for the same device again within the
  window (default 5 min, from the last event) updates the existing alert
  (occurrence_count++ / last_event_time bumped; event_time kept). For alerts
  with no device, the key is rule + src_ip + dst_ip so unknown hosts never merge.
- Resume safety: the read checkpoint (file identity st_dev/st_ino + byte offset)
  is written in the SAME transaction as the alert upserts. Rotation is handled by
  draining each file by inode; rotated files are deleted only by the reaper, and
  only once fully consumed. Truncation/gaps are logged explicitly.

eve.json rotation itself is done by appliance/suricata/rotate-eve.sh (PBI-13);
this daemon only follows it (drains + reaps).
"""
import glob
import json
import logging
import os
import signal
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timedelta

DB_PATH = os.getenv("ASSAS_DB_PATH", "/home/assas/assas/assas.db")
EVE_PATH = os.getenv("ASSAS_EVE_PATH", "/var/log/suricata/eve.json")
DEDUP_WINDOW_SECONDS = int(os.getenv("ASSAS_ALERT_DEDUP_WINDOW", "300"))
POLL_SECONDS = float(os.getenv("ASSAS_ALERT_POLL_SECONDS", "2"))
# How many fully-consumed rotated eve files to keep (for debugging) before the
# reaper deletes them. The reaper NEVER touches an unconsumed file.
KEEP_CONSUMED_ROTATED = int(os.getenv("ASSAS_ALERT_KEEP_ROTATED", "3"))

log = logging.getLogger("assas.alerts")

_SEVERITY = {1: "Critical", 2: "High", 3: "Medium"}

ALERTS_DDL = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_mac       TEXT,
    alert_type       TEXT NOT NULL DEFAULT 'Threat',
    title            TEXT NOT NULL,
    rule_id          INTEGER,
    event_time       TEXT NOT NULL,
    src_ip           TEXT,
    dst_ip           TEXT,
    src_port         INTEGER,
    dst_port         INTEGER,
    severity         TEXT NOT NULL,
    state            TEXT NOT NULL DEFAULT 'New',
    explanation      TEXT,
    model_version    TEXT,
    anomaly_score    REAL,
    threshold        REAL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    last_event_time  TEXT NOT NULL
)
"""

STATE_DDL = """
CREATE TABLE IF NOT EXISTS alert_ingest_state (
    st_dev      INTEGER NOT NULL,
    st_ino      INTEGER NOT NULL,
    path        TEXT,
    offset      INTEGER NOT NULL DEFAULT 0,
    size_at_eof INTEGER,
    consumed    INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT,
    PRIMARY KEY (st_dev, st_ino)
)
"""

INDEX_DDL = (
    "CREATE INDEX IF NOT EXISTS idx_alerts_last_event ON alerts(last_event_time)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_mac, last_event_time)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(rule_id, device_mac)",
)


def ensure_schema(conn):
    with conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(ALERTS_DDL)
        conn.execute(STATE_DDL)
        for ddl in INDEX_DDL:
            conn.execute(ddl)


# --------------------------------------------------------------------------- #
# Pure helpers (unit-tested directly)
# --------------------------------------------------------------------------- #
def severity_label(priority):
    """Map a Suricata rule priority to a severity label (>=4 or unknown -> Low)."""
    try:
        p = int(priority)
    except (TypeError, ValueError):
        return "Low"
    return _SEVERITY.get(p, "Low")


def local_naive_iso(ts):
    """Suricata timestamp -> server-local naive ISO-8601 to the second.

    Matches the DB's existing TEXT-timestamp convention. Returns None if the
    timestamp is missing or unparseable.
    """
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt.replace(microsecond=0).isoformat(sep="T")


def parse_alert_event(obj):
    """Return the alert fields we store, or None if not an alert event."""
    if obj.get("event_type") != "alert":
        return None
    a = obj.get("alert") or {}
    return {
        "title": a.get("signature") or "Suricata alert",
        "rule_id": a.get("signature_id"),
        "severity": severity_label(a.get("severity")),
        "event_time": local_naive_iso(obj.get("timestamp")),
        "src_ip": obj.get("src_ip"),
        "dst_ip": obj.get("dest_ip"),
        "src_port": obj.get("src_port"),
        "dst_port": obj.get("dest_port"),
    }


def link_device(conn, src_ip, dst_ip):
    """Match src/dst IPs against the device inventory.

    one side -> that device; both -> source device; neither -> None.
    The caller still stores both IPs on the alert, so the other IP is retained.
    """
    def mac_for(ip):
        if not ip:
            return None
        row = conn.execute(
            "SELECT mac FROM devices "
            "WHERE ? IN (last_ipv4, last_ipv6_global, last_ipv6_ll, ip) LIMIT 1",
            (ip,),
        ).fetchone()
        return row[0] if row else None

    src_mac = mac_for(src_ip)
    dst_mac = mac_for(dst_ip)
    if src_mac and dst_mac:
        return src_mac  # both match -> link to the source device
    return src_mac or dst_mac


def _parse_iso(s):
    return datetime.fromisoformat(s) if s else None


def upsert_alert(conn, a, device_mac, window_seconds):
    """Insert a new Threat Alert, or merge into an existing one within the window."""
    event_time = a["event_time"] or local_naive_iso(
        datetime.now().isoformat(timespec="seconds")
    )
    if device_mac is not None:
        row = conn.execute(
            "SELECT alert_id, last_event_time FROM alerts "
            "WHERE alert_type='Threat' AND device_mac=? AND rule_id IS ? "
            "ORDER BY last_event_time DESC LIMIT 1",
            (device_mac, a["rule_id"]),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT alert_id, last_event_time FROM alerts "
            "WHERE alert_type='Threat' AND device_mac IS NULL AND rule_id IS ? "
            "AND src_ip IS ? AND dst_ip IS ? "
            "ORDER BY last_event_time DESC LIMIT 1",
            (a["rule_id"], a["src_ip"], a["dst_ip"]),
        ).fetchone()

    if row is not None:
        alert_id, last_et = row
        et_dt, last_dt = _parse_iso(event_time), _parse_iso(last_et)
        if et_dt and last_dt and abs(et_dt - last_dt) <= timedelta(seconds=window_seconds):
            new_last = max(last_dt, et_dt).replace(microsecond=0).isoformat(sep="T")
            conn.execute(
                "UPDATE alerts SET occurrence_count = occurrence_count + 1, "
                "last_event_time=? WHERE alert_id=?",
                (new_last, alert_id),
            )
            return "merged"

    conn.execute(
        "INSERT INTO alerts (device_mac, alert_type, title, rule_id, event_time, "
        "src_ip, dst_ip, src_port, dst_port, severity, state, occurrence_count, "
        "last_event_time) VALUES (?, 'Threat', ?, ?, ?, ?, ?, ?, ?, ?, 'New', 1, ?)",
        (
            device_mac, a["title"], a["rule_id"], event_time,
            a["src_ip"], a["dst_ip"], a["src_port"], a["dst_port"],
            a["severity"], event_time,
        ),
    )
    return "inserted"


def split_complete_lines(data):
    """Return (complete_lines, bytes_consumed). A trailing partial line (no
    newline yet) is left unconsumed so it is re-read when complete."""
    parts = data.split(b"\n")
    complete = parts[:-1]  # the last element is after the final '\n' (partial or '')
    consumed = sum(len(p) + 1 for p in complete)
    return complete, consumed


# --------------------------------------------------------------------------- #
# File processing (checkpoint written in the same transaction as the alerts)
# --------------------------------------------------------------------------- #
def process_file(conn, path, window_seconds):
    """Read new complete lines from `path`, ingest alerts, persist the offset.

    Returns (st_dev, st_ino, new_offset, size) or None if the file is absent
    (e.g. the brief window right after rotation before Suricata reopens).
    """
    try:
        st = os.stat(path)
    except FileNotFoundError:
        log.debug("eve file %s not present yet (post-rotation window); skipping", path)
        return None

    dev, ino, size = st.st_dev, st.st_ino, st.st_size
    row = conn.execute(
        "SELECT offset FROM alert_ingest_state WHERE st_dev=? AND st_ino=?",
        (dev, ino),
    ).fetchone()
    offset = row[0] if row else 0

    if offset > size:
        log.warning(
            "TRUNCATION/GAP on %s (st_dev=%s st_ino=%s): stored offset %d > size %d; "
            "re-reading from 0", path, dev, ino, offset, size,
        )
        offset = 0

    if offset == size:
        return dev, ino, offset, size  # nothing new

    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read()
    complete, consumed = split_complete_lines(data)
    new_offset = offset + consumed

    with conn:  # ONE transaction: all upserts + the checkpoint
        for raw in complete:
            s = raw.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError:
                log.warning("skipping malformed eve line in %s", path)
                continue
            a = parse_alert_event(obj)
            if a is None:
                continue
            device_mac = link_device(conn, a["src_ip"], a["dst_ip"])
            upsert_alert(conn, a, device_mac, window_seconds)
        conn.execute(
            "INSERT INTO alert_ingest_state (st_dev, st_ino, path, offset, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(st_dev, st_ino) DO UPDATE SET offset=excluded.offset, "
            "path=excluded.path, updated_at=excluded.updated_at",
            (dev, ino, path, new_offset, datetime.now().replace(microsecond=0).isoformat(sep="T")),
        )
    return dev, ino, new_offset, size


def mark_consumed(conn, dev, ino, size):
    with conn:
        conn.execute(
            "UPDATE alert_ingest_state SET consumed=1, size_at_eof=? "
            "WHERE st_dev=? AND st_ino=?",
            (size, dev, ino),
        )


def rotated_files(eve_path):
    """Rotated eve files, chronological (names are UTC timestamps -> lexical sort)."""
    return sorted(glob.glob(glob.escape(eve_path) + "-*"))


def reap(conn, eve_path, keep=KEEP_CONSUMED_ROTATED):
    """Delete fully-consumed rotated eve files, keeping the most recent `keep`.

    NEVER touches a file that is not marked consumed in alert_ingest_state, which
    is the retention guarantee: unread rotated files are always preserved.
    """
    consumed = {
        (r[0], r[1])
        for r in conn.execute(
            "SELECT st_dev, st_ino FROM alert_ingest_state WHERE consumed=1"
        ).fetchall()
    }
    candidates = []
    for p in rotated_files(eve_path):
        try:
            st = os.stat(p)
        except FileNotFoundError:
            continue
        if (st.st_dev, st.st_ino) in consumed:
            candidates.append((p, st.st_dev, st.st_ino))
    to_delete = candidates[:-keep] if keep > 0 else candidates
    for p, dev, ino in to_delete:
        try:
            os.remove(p)
            log.info("reaped fully-consumed rotated eve file %s", p)
        except OSError as exc:
            log.warning("could not remove %s: %s", p, exc)
            continue
        with conn:
            conn.execute(
                "DELETE FROM alert_ingest_state WHERE st_dev=? AND st_ino=?", (dev, ino)
            )


def run_once(conn, eve_path, window_seconds):
    """One pass: drain every rotated file, then the live file; then reap."""
    rotated = rotated_files(eve_path)
    for p in rotated:
        res = process_file(conn, p, window_seconds)
        if res is not None:
            dev, ino, new_offset, size = res
            if new_offset >= size:  # rotated file fully read -> safe to reap later
                mark_consumed(conn, dev, ino, size)
    process_file(conn, eve_path, window_seconds)  # live file last; never "consumed"
    reap(conn, eve_path)


def _open_db():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def main():
    logging.basicConfig(
        level=os.getenv("ASSAS_ALERT_LOGLEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    running = {"on": True}

    def _stop(signum, _frame):
        log.info("received signal %s, shutting down", signum)
        running["on"] = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    log.info(
        "assas-alerts starting: db=%s eve=%s window=%ss poll=%ss keep=%d",
        DB_PATH, EVE_PATH, DEDUP_WINDOW_SECONDS, POLL_SECONDS, KEEP_CONSUMED_ROTATED,
    )
    with closing(_open_db()) as conn:
        ensure_schema(conn)
        while running["on"]:
            try:
                run_once(conn, EVE_PATH, DEDUP_WINDOW_SECONDS)
            except sqlite3.OperationalError as exc:
                log.warning("db busy/locked, retrying next cycle: %s", exc)
            except Exception:  # keep the daemon alive; log and continue
                log.exception("unexpected error in ingest cycle")
            time.sleep(POLL_SECONDS)
    log.info("assas-alerts stopped")


if __name__ == "__main__":
    main()
