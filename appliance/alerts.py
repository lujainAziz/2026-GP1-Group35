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
  The matched side is stored as device_role ('source' / 'target'); it is NULL
  for unlinked and MAC-attributed alerts.
- Classtype: eve gives `alert.category` (the classtype DESCRIPTION). It is
  stored as-is and mapped back to the short classtype name through Suricata's
  classification.config; an unknown/ambiguous description or a missing file
  stores classtype NULL (the API then shows the fallback title).
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
import ipaddress
import json
import logging
import os
import re
import signal
import sqlite3
import subprocess
import time
from contextlib import closing
from datetime import datetime, timedelta

DB_PATH = os.getenv("ASSAS_DB_PATH", "/home/assas/assas/assas.db")
EVE_PATH = os.getenv("ASSAS_EVE_PATH", "/var/log/suricata/eve.json")
# The file Suricata loads (assas.yaml `classification-file`).
CLASSIFICATION_PATH = os.getenv(
    "ASSAS_CLASSIFICATION_PATH", "/etc/suricata/classification.config"
)
DEDUP_WINDOW_SECONDS = int(os.getenv("ASSAS_ALERT_DEDUP_WINDOW", "300"))
POLL_SECONDS = float(os.getenv("ASSAS_ALERT_POLL_SECONDS", "2"))
# How many fully-consumed rotated eve files to keep (for debugging) before the
# reaper deletes them. The reaper NEVER touches an unconsumed file.
KEEP_CONSUMED_ROTATED = int(os.getenv("ASSAS_ALERT_KEEP_ROTATED", "3"))
# Address-evidence window for linking (device_addresses, written by discovery):
# an alert links only when its event time falls inside
# [first_seen - PRE_SLACK, last_seen + GRACE] of the ownership evidence.
# PRE_SLACK covers evidence lagging first use of a fresh (privacy) address;
# GRACE covers a deprecated RFC 4941 address still receiving traffic.
ADDR_PRE_SLACK_HOURS = int(os.getenv("ASSAS_ADDR_PRE_SLACK_HOURS", "2"))
ADDR_GRACE_HOURS = int(os.getenv("ASSAS_ADDR_GRACE_HOURS", "24"))
# Discovery-lag repair: recent unlinked alerts are re-tried against newly
# arrived evidence. Bounded window — historical alerts are never mass-rewritten.
RELINK_WINDOW_HOURS = int(os.getenv("ASSAS_ALERT_RELINK_HOURS", "24"))
# A rotated file is only reaped once it has been quiescent (unmodified) for this
# many seconds AND no process still holds it open (see _file_in_use). This, with
# the grow-check, prevents deleting a file Suricata is still writing to after the
# rename but before it honours the reopen signal.
REAP_GRACE_SECONDS = float(os.getenv("ASSAS_ALERT_REAP_GRACE", "10"))

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
    last_event_time  TEXT NOT NULL,
    category         TEXT,
    classtype        TEXT,
    device_role      TEXT
)
"""

# Columns added after the table first shipped; ensure_alert_columns adds them
# to an existing table (existing rows keep NULL: fallback title, no role line).
ADDED_ALERT_COLUMNS = (
    ("category", "TEXT"),      # eve alert.category (classtype description)
    ("classtype", "TEXT"),     # short classtype name, NULL when unresolved
    ("device_role", "TEXT"),   # 'source' / 'target' / NULL
)

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
    ensure_alert_columns(conn)


def ensure_alert_columns(conn):
    """Add ADDED_ALERT_COLUMNS to an existing alerts table (idempotent).

    Also called by the API at startup, which may run before the ingester has
    migrated. A missing alerts table is left alone (the ingester creates it).
    """
    with conn:
        have = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if not have:
            return
        for column, sql_type in ADDED_ALERT_COLUMNS:
            if column not in have:
                try:
                    conn.execute(f"ALTER TABLE alerts ADD COLUMN {column} {sql_type}")
                except sqlite3.OperationalError as exc:
                    # Another process added it between PRAGMA and ALTER.
                    if "duplicate column" not in str(exc).lower():
                        raise


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
    if not ts or not isinstance(ts, str):
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt.replace(microsecond=0).isoformat(sep="T")


def _as_int(value):
    """Coerce a JSON value to int, or None (ports/rule ids arrive as numbers)."""
    if isinstance(value, bool):  # bool is an int subclass; not a valid id/port
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def parse_alert_event(obj):
    """Return the alert fields we store, or None if not an alert event.

    Validates structure before access: a structurally-invalid record (e.g. a
    bare ``null``/list/scalar JSON line, or a non-object ``alert``) returns None
    instead of raising, so one bad record is skipped rather than stalling the
    whole file (the offset still advances past it).
    """
    if not isinstance(obj, dict) or obj.get("event_type") != "alert":
        return None
    a = obj.get("alert")
    if not isinstance(a, dict):
        # A real Suricata alert event always carries an `alert` object; without a
        # usable one there is nothing to store, so skip rather than invent a
        # blank alert.
        return None
    sig = a.get("signature")
    # Ethernet header (eve-log `ethernet: yes`): used ONLY to attribute events
    # that carry no IP addresses (e.g. truncated-packet decoder events). Not
    # stored in the alerts table.
    eth = obj.get("ether")
    ether_src = ether_dst = None
    if isinstance(eth, dict):
        if isinstance(eth.get("src_mac"), str):
            ether_src = eth["src_mac"].lower()
        if isinstance(eth.get("dest_mac"), str):
            ether_dst = eth["dest_mac"].lower()
    cat = a.get("category")
    return {
        "title": sig if isinstance(sig, str) and sig.strip() else "Suricata alert",
        # Classtype description; absent for rules with no classtype.
        "category": cat.strip() if isinstance(cat, str) and cat.strip() else None,
        "rule_id": _as_int(a.get("signature_id")),
        "severity": severity_label(a.get("severity")),
        "event_time": local_naive_iso(obj.get("timestamp")),
        "src_ip": obj.get("src_ip") if isinstance(obj.get("src_ip"), str) else None,
        "dst_ip": obj.get("dest_ip") if isinstance(obj.get("dest_ip"), str) else None,
        "src_port": _as_int(obj.get("src_port")),
        "dst_port": _as_int(obj.get("dest_port")),
        "ether_src": ether_src,
        "ether_dst": ether_dst,
    }


# Same shape Suricata accepts: shortname, description (may contain commas), priority.
_CLASSIFICATION_RE = re.compile(
    r"^\s*config\s+classification\s*:\s*([A-Za-z0-9_-]+)\s*,\s*(.+?)\s*,\s*(\d+)\s*$"
)


def parse_classification_config(text):
    """classification.config text -> {description: short classtype name}.

    A description shared by two different classtypes maps to None, since eve's
    `category` could not tell them apart. Comments and malformed lines are
    skipped.
    """
    by_desc = {}
    for line in text.splitlines():
        m = _CLASSIFICATION_RE.match(line)
        if not m:
            continue
        name, desc = m.group(1), m.group(2).strip()
        if desc in by_desc and by_desc[desc] not in (None, name):
            by_desc[desc] = None
        elif desc not in by_desc:
            by_desc[desc] = name
    return by_desc


# Reloaded when the file's mtime changes (suricata-update may rewrite it).
_classification_cache = {"path": None, "mtime": None, "map": {}}
_classification_warned = set()


def _warn_once(key, msg, *args):
    if key not in _classification_warned:
        _classification_warned.add(key)
        log.warning(msg, *args)


def classification_map(path=None):
    """The description -> classtype map for `path`; {} if the file is unreadable."""
    path = path or CLASSIFICATION_PATH
    try:
        mtime = os.stat(path).st_mtime
    except OSError as exc:
        _warn_once(("missing", path), "classification file %s unavailable (%s); "
                   "alerts get classtype NULL (fallback title)", path, exc)
        return {}
    c = _classification_cache
    if c["path"] != path or c["mtime"] != mtime:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                c["map"] = parse_classification_config(f.read())
        except OSError as exc:
            _warn_once(("unreadable", path), "could not read classification file "
                       "%s (%s); alerts get classtype NULL", path, exc)
            return {}
        c["path"], c["mtime"] = path, mtime
    return c["map"]


def classtype_for(category, path=None):
    """Short classtype name for an eve `category`, or None if unresolvable."""
    if not category:
        return None
    mapping = classification_map(path)
    if not mapping:
        return None
    if category not in mapping:
        _warn_once(("unknown", category), "eve category %r not in classification "
                   "file; classtype NULL", category)
        return None
    if mapping[category] is None:
        _warn_once(("ambiguous", category), "eve category %r maps to more than one "
                   "classtype; classtype NULL", category)
    return mapping[category]


def _addr_forms(ip):
    """Textual forms an address may be stored under.

    Suricata writes IPv6 zero-padded exploded ('2001:16a2:...:0cf3:...'), while
    the inventory's last_* columns hold the kernel's compressed form
    ('...:cf3:...'). Both forms are matched so format differences never break a
    link. Returns a list with the original string as a fallback.
    """
    try:
        addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return [ip]
    return sorted({str(addr), addr.exploded.lower(), str(ip)})


def link_device(conn, src_ip, dst_ip, event_time=None):
    """The linked device MAC only; see link_device_with_role."""
    return link_device_with_role(conn, src_ip, dst_ip, event_time)[0]


def link_device_with_role(conn, src_ip, dst_ip, event_time=None):
    """Match src/dst IPs against the inventory and the address-evidence set.

    Returns (mac, role): one side -> that device, role 'source' or 'target';
    both -> source device, role 'source'; neither -> (None, None).
    The caller still stores both IPs on the alert, so the other IP is retained.

    Two sources are consulted per address:
      - the devices last_* columns (latest address of each family), and
      - the device_addresses evidence table (full set, written by discovery
        from ARP/DHCP/NDP/guarded traffic). Evidence counts only when the
        alert's event time falls inside
        [first_seen - ADDR_PRE_SLACK_HOURS, last_seen + ADDR_GRACE_HOURS],
        so a stale record never claims a new event and a replayed old event is
        not attributed to the address's current owner. A missing table (older
        discovery) is treated as no rows.

    The link is made ONLY when exactly one device owns the address; a conflict
    (more than one MAC) or absence of evidence leaves the alert unlinked
    (device_mac NULL) with the reason logged. Network-prefix membership alone
    is never used. Multicast/broadcast/unspecified addresses and the
    appliance's own and gateway IPs (excluded_ips_now) are never link targets;
    the other side is still resolved.
    """
    def resolve(ip):
        if not ip or _is_excluded_ip(ip):
            return None
        # The evidence table is AUTHORITATIVE for any address it knows: when
        # the address has evidence rows, only the time-windowed evidence may
        # link it — the legacy last_* columns must not bypass an expired or
        # conflicting ownership window (a rotated-out address can linger in
        # last_ipv6_global). Columns are a fallback only for addresses with no
        # evidence at all (older discovery / pre-evidence data).
        macs = set()
        evidence_covers_addr = False
        try:
            # device_addresses stores IPv4 dotted / IPv6 exploded lowercase.
            try:
                parsed = ipaddress.ip_address(str(ip).split("%", 1)[0])
                norm = str(parsed) if parsed.version == 4 else parsed.exploded.lower()
            except ValueError:
                norm = None
            if norm:
                evidence_covers_addr = conn.execute(
                    "SELECT 1 FROM device_addresses WHERE addr=? LIMIT 1", (norm,)
                ).fetchone() is not None
                if evidence_covers_addr:
                    if event_time:
                        # datetime() on BOTH sides: it renders a space
                        # separator, while event times use 'T' — mixing the two
                        # breaks the textual comparison.
                        rows = conn.execute(
                            "SELECT DISTINCT mac FROM device_addresses WHERE addr=? "
                            f"AND datetime(first_seen, '-{ADDR_PRE_SLACK_HOURS} hours') <= datetime(?) "
                            f"AND datetime(last_seen, '+{ADDR_GRACE_HOURS} hours') >= datetime(?)",
                            (norm, event_time, event_time),
                        ).fetchall()
                    else:
                        rows = conn.execute(
                            "SELECT DISTINCT mac FROM device_addresses WHERE addr=?",
                            (norm,),
                        ).fetchall()
                    macs.update(r[0] for r in rows)
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc).lower():
                raise
            evidence_covers_addr = False
        if not evidence_covers_addr:
            for form in _addr_forms(ip):
                macs.update(
                    r[0] for r in conn.execute(
                        "SELECT DISTINCT mac FROM devices "
                        "WHERE ? IN (last_ipv4, last_ipv6_global, last_ipv6_ll, ip)",
                        (form,),
                    ).fetchall()
                )
        if len(macs) == 1:
            return macs.pop()
        if len(macs) > 1:
            log.warning(
                "ambiguous device link for IP: %d devices claim it; leaving alert "
                "unlinked (device_mac NULL)", len(macs),
            )
        return None

    src_mac = resolve(src_ip)
    dst_mac = resolve(dst_ip)
    if src_mac:
        return src_mac, "source"  # src only, or both match -> the source device
    if dst_mac:
        return dst_mac, "target"
    return None, None


_LOCAL_MACS = None
# Gateway-MAC cache: refreshed periodically; an empty (failed) resolution is
# retried on a short interval and NEVER stored as permanent truth.
GATEWAY_REFRESH_SECONDS = int(os.getenv("ASSAS_GATEWAY_REFRESH", "300"))
GATEWAY_RETRY_SECONDS = int(os.getenv("ASSAS_GATEWAY_RETRY", "60"))
_gateway_cache = {"macs": set(), "known": False, "ts": 0.0}
_gateway_warned = {"on": False}


def local_appliance_macs():
    """MACs of the appliance's own interfaces — never link candidates."""
    global _LOCAL_MACS
    if _LOCAL_MACS is None:
        macs = set()
        try:
            for name in os.listdir("/sys/class/net"):
                try:
                    with open(f"/sys/class/net/{name}/address") as f:
                        m = f.read().strip().lower()
                    if m and m != "00:00:00:00:00:00":
                        macs.add(m)
                except OSError:
                    continue
        except OSError:
            pass
        _LOCAL_MACS = macs
    return _LOCAL_MACS


def parse_default_routes(out):
    """[(next_hop_ip, dev)] from `ip [-6] route show default` output."""
    routes = []
    for line in out.splitlines():
        parts = line.split()
        if not line.startswith("default") or "via" not in parts:
            continue
        ip_ = parts[parts.index("via") + 1]
        dev = parts[parts.index("dev") + 1] if "dev" in parts else None
        routes.append((ip_, dev))
    return routes


def parse_neighbor_mac(out, ip_, dev=None):
    """MAC of `ip_` from `ip [-6] neigh show` output, on `dev` when given.

    INCOMPLETE/FAILED/NONE entries prove nothing and are skipped.
    """
    for line in out.splitlines():
        parts = line.split()
        if not parts or parts[0] != ip_ or "lladdr" not in parts:
            continue
        if dev and "dev" in parts and parts[parts.index("dev") + 1] != dev:
            continue
        if parts[-1].upper() in ("INCOMPLETE", "FAILED", "NONE"):
            continue
        return parts[parts.index("lladdr") + 1].lower()
    return None


def _resolve_gateway_macs(conn):
    """Gateway MAC(s) from BOTH default routes (IPv4 + IPv6) via the kernel
    neighbor tables on the route's interface; the inventory is only a
    supplementary source, never the sole one (its gateway row may be absent,
    and the IPv6 next-hop — typically link-local — is not an inventory key)."""
    macs = set()
    v4_ips = []
    for args in (["ip", "route", "show", "default"],
                 ["ip", "-6", "route", "show", "default"]):
        try:
            out = subprocess.check_output(args, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        for ip_, dev in parse_default_routes(out):
            if ":" not in ip_:
                v4_ips.append(ip_)
            neigh_cmd = (["ip", "-6", "neigh", "show"] if ":" in ip_
                         else ["ip", "neigh", "show"])
            try:
                nout = subprocess.check_output(neigh_cmd, text=True, timeout=5)
            except (OSError, subprocess.SubprocessError):
                continue
            m = parse_neighbor_mac(nout, ip_, dev)
            if m:
                macs.add(m)
    if v4_ips:
        ph = ",".join("?" for _ in v4_ips)
        try:
            macs.update(
                r[0].lower() for r in conn.execute(
                    f"SELECT DISTINCT mac FROM devices "
                    f"WHERE last_ipv4 IN ({ph}) OR ip IN ({ph})",
                    (*v4_ips, *v4_ips),
                ).fetchall() if r[0]
            )
        except sqlite3.OperationalError:
            pass
    return macs


def gateway_macs_now(conn, now=None):
    """(gateway_macs, known) with a TTL cache.

    A successful resolution is reused for GATEWAY_REFRESH_SECONDS; a failed
    (empty) one only for GATEWAY_RETRY_SECONDS — gateway information is
    refreshed periodically and a failure is never cached forever.
    """
    now = time.time() if now is None else now
    ttl = GATEWAY_REFRESH_SECONDS if _gateway_cache["known"] else GATEWAY_RETRY_SECONDS
    if now - _gateway_cache["ts"] >= ttl:
        macs = _resolve_gateway_macs(conn)
        _gateway_cache["macs"] = macs
        _gateway_cache["known"] = bool(macs)
        _gateway_cache["ts"] = now
    return _gateway_cache["macs"], _gateway_cache["known"]


# Excluded-IP cache (appliance's own addresses + gateway next hops): same TTL
# policy as the gateway cache, since DHCP can change the appliance's address.
_excluded_ip_cache = {"ips": set(), "known": False, "ts": 0.0}


def parse_interface_addrs(out):
    """Addresses (and IPv4 `brd` broadcasts) from `ip -o addr show` output."""
    ips = set()
    for line in out.splitlines():
        parts = line.split()
        for key in ("inet", "inet6", "brd"):
            if key not in parts or parts.index(key) + 1 >= len(parts):
                continue
            value = parts[parts.index(key) + 1].split("/", 1)[0].split("%", 1)[0]
            try:
                ips.add(ipaddress.ip_address(value))
            except ValueError:
                continue
    return ips


def _resolve_excluded_ips():
    """The appliance's own interface addresses plus the default-route next
    hops (IPv4 + IPv6): never link targets for IP-based attribution."""
    ips = set()
    try:
        ips |= parse_interface_addrs(
            subprocess.check_output(["ip", "-o", "addr", "show"], text=True, timeout=5))
    except (OSError, subprocess.SubprocessError):
        pass
    for args in (["ip", "route", "show", "default"],
                 ["ip", "-6", "route", "show", "default"]):
        try:
            out = subprocess.check_output(args, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        for ip_, _dev in parse_default_routes(out):
            try:
                ips.add(ipaddress.ip_address(ip_.split("%", 1)[0]))
            except ValueError:
                continue
    return ips


def excluded_ips_now(now=None):
    """Appliance + gateway IPs with a TTL cache. A failed (empty) resolution
    excludes nothing and is retried on the short interval."""
    now = time.time() if now is None else now
    ttl = GATEWAY_REFRESH_SECONDS if _excluded_ip_cache["known"] else GATEWAY_RETRY_SECONDS
    if now - _excluded_ip_cache["ts"] >= ttl:
        ips = _resolve_excluded_ips()
        _excluded_ip_cache["ips"] = ips
        _excluded_ip_cache["known"] = bool(ips)
        _excluded_ip_cache["ts"] = now
    return _excluded_ip_cache["ips"]


def _is_excluded_ip(ip):
    """Multicast, broadcast, unspecified, the appliance itself or a gateway:
    such an address never identifies a device to link an alert to."""
    try:
        addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified:
        return True
    if addr.version == 4 and addr == ipaddress.IPv4Address("255.255.255.255"):
        return True
    return addr in excluded_ips_now()


def _is_multicast_mac(mac):
    """Multicast/broadcast (group bit set) — or malformed — MACs are not candidates."""
    try:
        return bool(int(mac.split(":", 1)[0], 16) & 1)
    except (ValueError, AttributeError):
        return True


def link_device_by_mac(conn, ether_src, ether_dst, gateway_macs=None):
    """Attribute an ADDRESS-LESS event by its frame MACs.

    Used ONLY when the event carries no IP addresses at all — never to override
    or second-guess IP-based linking (including an IP-ownership conflict).
    A side is a candidate only if it is a known inventory device; gateway
    MAC(s), multicast/broadcast frames and the appliance's own interfaces are
    excluded. Two distinct candidate devices on one frame is ambiguous → NULL.
    Identifying the MAC does not assert the device CRAFTED the malformed frame
    — only which known device the frame involves.
    """
    if gateway_macs is None:
        gw_macs, known = gateway_macs_now(conn)
        if not known:
            # Without gateway knowledge a lone candidate could BE the router:
            # the device choice is ambiguous, so stay unlinked (fail-safe).
            if not _gateway_warned["on"]:
                _gateway_warned["on"] = True
                log.warning("gateway MAC(s) undetermined; MAC attribution "
                            "suspended until resolution succeeds")
            return None
        _gateway_warned["on"] = False
    else:
        gw_macs = set(gateway_macs)
    local = local_appliance_macs()

    def candidate(mac):
        if not mac or _is_multicast_mac(mac):
            return None
        mac = mac.lower()
        if mac in gw_macs or mac in local:
            return None
        row = conn.execute("SELECT 1 FROM devices WHERE mac=?", (mac,)).fetchone()
        return mac if row else None

    src = candidate(ether_src)
    dst = candidate(ether_dst)
    if src and dst and src != dst:
        log.warning("MAC attribution ambiguous (two inventory devices on one "
                    "frame); leaving alert unlinked")
        return None
    return src or dst


def relink_recent(conn, window_hours=None, now_iso=None):
    """Retry linking RECENT unlinked alerts once ownership evidence arrives.

    Discovery can lag an address's first use (a fresh privacy IPv6 may alert
    before NDP/ARP evidence lands). This pass re-runs link_device for alerts
    with device_mac NULL whose last_event_time lies within the bounded window,
    and sets ONLY device_mac (and its device_role) on a reliable single match. occurrence_count,
    event times and states are never touched; events are not re-read; alerts
    older than the window are never rewritten.
    """
    hours = RELINK_WINDOW_HOURS if window_hours is None else window_hours
    now_iso = now_iso or datetime.now().replace(microsecond=0).isoformat(sep="T")
    try:
        rows = conn.execute(
            "SELECT alert_id, src_ip, dst_ip, event_time FROM alerts "
            "WHERE alert_type='Threat' AND device_mac IS NULL "
            "AND datetime(last_event_time) >= datetime(?, ?)",
            (now_iso, f"-{hours} hours"),
        ).fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return 0
        raise
    linked = 0
    for alert_id, src, dst, event_time in rows:
        mac, role = link_device_with_role(conn, src, dst, event_time)
        if mac:
            with conn:
                cur = conn.execute(
                    "UPDATE alerts SET device_mac=?, device_role=? "
                    "WHERE alert_id=? AND device_mac IS NULL",
                    (mac, role, alert_id),
                )
                linked += cur.rowcount
    if linked:
        log.info("relinked %d recent alert(s) after new address evidence", linked)
    return linked


def _parse_iso(s):
    return datetime.fromisoformat(s) if s else None


def upsert_alert(conn, a, device_mac, window_seconds, device_role=None):
    """Insert a new Threat Alert, or merge into an existing one within the window.

    A merge leaves category/classtype/device_role as first stored: like the
    stored IPs, the role describes the alert's first event.
    """
    event_time = a["event_time"] or local_naive_iso(
        datetime.now().isoformat(timespec="seconds")
    )
    # PBI-22 criterion 7: 'Resolved' is a terminal state. The merge candidate is
    # the SINGLE most-recent matching alert (by last_event_time), regardless of
    # state; its state then decides. If that newest match is Resolved, the stream
    # is closed and the event starts a fresh, independent alert (new id, state
    # 'New') — even if an OLDER matching alert is still open and inside the
    # window (we must not re-attach to it). Only a newest match that is open
    # (New/Reviewed) and within the window absorbs the recurrence.
    if device_mac is not None:
        row = conn.execute(
            "SELECT alert_id, event_time, last_event_time, state FROM alerts "
            "WHERE alert_type='Threat' AND device_mac=? AND rule_id IS ? "
            "ORDER BY last_event_time DESC LIMIT 1",
            (device_mac, a["rule_id"]),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT alert_id, event_time, last_event_time, state FROM alerts "
            "WHERE alert_type='Threat' AND device_mac IS NULL AND rule_id IS ? "
            "AND src_ip IS ? AND dst_ip IS ? "
            "ORDER BY last_event_time DESC LIMIT 1",
            (a["rule_id"], a["src_ip"], a["dst_ip"]),
        ).fetchone()

    if row is not None and str(row[3]).lower() != "resolved":
        alert_id, first_et, last_et = row[0], row[1], row[2]
        et_dt, first_dt, last_dt = _parse_iso(event_time), _parse_iso(first_et), _parse_iso(last_et)
        if et_dt and last_dt and abs(et_dt - last_dt) <= timedelta(seconds=window_seconds):
            # Keep the chronological span even if events arrive out of order:
            # first = earliest seen, last = latest seen.
            new_first = min(first_dt or et_dt, et_dt).replace(microsecond=0).isoformat(sep="T")
            new_last = max(last_dt, et_dt).replace(microsecond=0).isoformat(sep="T")
            conn.execute(
                "UPDATE alerts SET occurrence_count = occurrence_count + 1, "
                "event_time=?, last_event_time=? WHERE alert_id=?",
                (new_first, new_last, alert_id),
            )
            return "merged"

    conn.execute(
        "INSERT INTO alerts (device_mac, alert_type, title, rule_id, event_time, "
        "src_ip, dst_ip, src_port, dst_port, severity, state, occurrence_count, "
        "last_event_time, category, classtype, device_role) "
        "VALUES (?, 'Threat', ?, ?, ?, ?, ?, ?, ?, ?, 'New', 1, ?, ?, ?, ?)",
        (
            device_mac, a["title"], a["rule_id"], event_time,
            a["src_ip"], a["dst_ip"], a["src_port"], a["dst_port"],
            a["severity"], event_time,
            a.get("category"), a.get("classtype"),
            device_role if device_mac is not None else None,
        ),
    )
    return "inserted"


def ingest_alert(conn, a, window_seconds):
    """Resolve classtype, link the device (with its role), and upsert one alert."""
    a = dict(a, classtype=classtype_for(a.get("category")))
    if a["src_ip"] is None and a["dst_ip"] is None:
        # Address-less event (e.g. truncated packet): MAC attribution. No role:
        # the frame MAC does not show which side started the activity.
        device_mac = link_device_by_mac(conn, a["ether_src"], a["ether_dst"])
        role = None
    else:
        device_mac, role = link_device_with_role(
            conn, a["src_ip"], a["dst_ip"], a["event_time"])
    return upsert_alert(conn, a, device_mac, window_seconds, role)


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
    # Open FIRST, then take the identity/size from the SAME open descriptor via
    # os.fstat. Using os.stat(path) and opening the path separately is racy: a
    # rotation between the two steps would read the new file's bytes but record
    # them under the old inode's checkpoint (an event lost, another counted
    # twice). fstat on the held fd makes identity, size and the bytes we read all
    # refer to one file.
    try:
        f = open(path, "rb")
    except FileNotFoundError:
        log.debug("eve file %s not present yet (post-rotation window); skipping", path)
        return None

    with f:
        st = os.fstat(f.fileno())
        dev, ino, size = st.st_dev, st.st_ino, st.st_size
        row = conn.execute(
            "SELECT offset FROM alert_ingest_state WHERE st_dev=? AND st_ino=?",
            (dev, ino),
        ).fetchone()
        offset = row[0] if row else 0

        if offset > size:
            return _resume_at_eof(conn, path, dev, ino, offset, size)

        if offset == size:
            return dev, ino, offset, size  # nothing new

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
            except (json.JSONDecodeError, UnicodeDecodeError):
                # json.loads(bytes) auto-detects encoding and raises
                # UnicodeDecodeError (not JSONDecodeError) on malformed bytes;
                # catch both so one bad line is skipped, not fatal. The line's
                # bytes are still counted in `consumed`, so the offset advances
                # past it and the daemon never stalls on it.
                log.warning("skipping malformed eve line (bad JSON) in %s", path)
                continue
            try:
                a = parse_alert_event(obj)
            except (AttributeError, TypeError, ValueError, KeyError) as exc:
                # Valid JSON but an unexpected shape (e.g. a bare null/list, or a
                # non-object `alert`). Skip the record; DO NOT catch DB errors
                # here, which must roll the transaction back and be retried.
                log.warning("skipping structurally-invalid eve record in %s (%s)", path, type(exc).__name__)
                continue
            if a is None:
                continue
            ingest_alert(conn, a, window_seconds)
        conn.execute(
            "INSERT INTO alert_ingest_state (st_dev, st_ino, path, offset, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(st_dev, st_ino) DO UPDATE SET offset=excluded.offset, "
            "path=excluded.path, updated_at=excluded.updated_at",
            (dev, ino, path, new_offset, datetime.now().replace(microsecond=0).isoformat(sep="T")),
        )
    return dev, ino, new_offset, size


def _resume_at_eof(conn, path, dev, ino, offset, size):
    """Handle stored offset > current size (in-place truncation or inode reuse).

    Re-reading from 0 would re-ingest already-stored events and duplicate
    alerts, so we DO NOT do that: log the gap explicitly and resume forward at
    the current EOF. Persist the clamped offset so the gap is not re-logged
    every cycle.
    """
    log.warning(
        "TRUNCATION/GAP on %s (st_dev=%s st_ino=%s): stored offset %d > size %d; "
        "resuming at EOF (no re-read, no re-ingest); events in the gap are not recovered",
        path, dev, ino, offset, size,
    )
    offset = size
    with conn:
        conn.execute(
            "INSERT INTO alert_ingest_state (st_dev, st_ino, path, offset, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(st_dev, st_ino) DO UPDATE SET offset=excluded.offset, "
            "path=excluded.path, updated_at=excluded.updated_at",
            (dev, ino, path, offset,
             datetime.now().replace(microsecond=0).isoformat(sep="T")),
        )
    return dev, ino, offset, size


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


def _current_identity_size(path):
    """(st_dev, st_ino, st_size, st_mtime) from an open fd, or None if gone.

    Uses the held descriptor (like process_file) so identity, size and mtime
    describe the same file even if a rotation races the check.
    """
    try:
        with open(path, "rb") as f:
            st = os.fstat(f.fileno())
            return st.st_dev, st.st_ino, st.st_size, st.st_mtime
    except FileNotFoundError:
        return None


def _file_in_use(dev, ino):
    """True if any process currently holds (dev, ino) open (Linux /proc scan).

    This is the authoritative "still being written" guard: Suricata keeps the
    renamed file open until it honours the reopen signal, so while that fd exists
    the file must not be reaped. Returns False when /proc is unavailable (so the
    mtime grace stays the guard on non-Linux); the ingester runs as root, so it
    can read other processes' fds. It is a conservative check — any open handle
    (read or write) blocks reaping.
    """
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        return False
    for pid in pids:
        fddir = "/proc/%s/fd" % pid
        try:
            fds = os.listdir(fddir)
        except OSError:
            continue  # process gone / not permitted
        for fd in fds:
            try:
                st = os.stat("%s/%s" % (fddir, fd))  # follows the symlink to the target
            except OSError:
                continue
            if st.st_dev == dev and st.st_ino == ino:
                return True
    return False


def reap(conn, eve_path, keep=KEEP_CONSUMED_ROTATED, grace=REAP_GRACE_SECONDS, now=None):
    """Delete fully-consumed rotated eve files, keeping the most recent `keep`.

    NEVER touches a file that is not marked consumed in alert_ingest_state, and a
    candidate is only deleted when ALL of these hold (checked again right before
    unlink): (1) its current size does not exceed our read offset — if it GREW
    (the writer appended after the rename, before honouring the reopen) the
    consumed flag is revoked so the next cycle drains it; (2) it has been
    quiescent (unmodified) for `grace` seconds; and (3) no process still holds it
    open (_file_in_use). (2)+(3) guarantee the writer is finished with the file,
    so deletion cannot race a late write — a stale double size-check alone would
    not. Checking the current size twice is not sufficient on its own.
    """
    now = time.time() if now is None else now
    # dev/ino -> (offset, size_at_eof) for every file we think is fully read.
    consumed = {
        (r[0], r[1]): (r[2], r[3])
        for r in conn.execute(
            "SELECT st_dev, st_ino, offset, COALESCE(size_at_eof, offset) "
            "FROM alert_ingest_state WHERE consumed=1"
        ).fetchall()
    }

    def revoke(dev, ino):
        with conn:
            conn.execute(
                "UPDATE alert_ingest_state SET consumed=0 WHERE st_dev=? AND st_ino=?",
                (dev, ino),
            )

    def safe_to_delete(p, dev, ino):
        """Re-validate a candidate against growth, quiescence and open handles."""
        ident = _current_identity_size(p)
        if ident is None:
            return None  # vanished; caller clears the state row
        cur_dev, cur_ino, cur_size, cur_mtime = ident
        offset = consumed.get((dev, ino), (0, 0))[0]
        if (cur_dev, cur_ino) != (dev, ino):
            return False
        if cur_size > offset:
            log.warning(
                "rotated file %s grew after being marked consumed (size %d > offset %d); "
                "clearing consumed flag to re-drain, not deleting", p, cur_size, offset,
            )
            revoke(dev, ino)
            return False
        if now - cur_mtime < grace:
            log.debug("holding %s: modified %.1fs ago (< grace %.0fs)", p, now - cur_mtime, grace)
            return False
        if _file_in_use(dev, ino):
            log.debug("holding %s: a process still has it open (writer not finished)", p)
            return False
        return True

    candidates = []
    for p in rotated_files(eve_path):
        ident = _current_identity_size(p)
        if ident is None:
            continue
        dev, ino = ident[0], ident[1]
        if (dev, ino) not in consumed:
            continue
        if safe_to_delete(p, dev, ino):
            candidates.append((p, dev, ino))
    to_delete = candidates[:-keep] if keep > 0 else candidates
    for p, dev, ino in to_delete:
        # Final re-check immediately before unlinking (the window since the first
        # pass): growth, quiescence and open-handle must all still hold.
        verdict = safe_to_delete(p, dev, ino)
        if verdict is None:
            with conn:
                conn.execute(
                    "DELETE FROM alert_ingest_state WHERE st_dev=? AND st_ino=?", (dev, ino)
                )
            continue
        if not verdict:
            continue
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
    relink_recent(conn)  # discovery-lag repair for recent unlinked alerts
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
