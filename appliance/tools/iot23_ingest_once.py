#!/usr/bin/env python3
"""Ingest an offline Suricata eve.json into a TEST database once, then exit
(IoT-23 offline test, IOT23_OFFLINE_TEST.md).

Uses the real ingester code (appliance/alerts.py: parsing, severity, classtype,
device linking, 5-minute dedup, read checkpoint) for one pass over the eve
file and its rotated eve.json-* files, instead of the never-ending daemon loop.
Dedup and first/last detection use the packet timestamps in eve.json.

Refuses the real database and any eve.json in the live Suricata log folder
(the ingester's reaper deletes consumed rotated files next to the eve file).
A second run on the same database reads nothing new: the checkpoint is stored
in the test database (alert_ingest_state).
"""
import argparse
import os
import sqlite3
import sys
from contextlib import closing

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import alerts  # noqa: E402
from iot23_common import UnsafePath, check_test_db, check_test_eve, fail  # noqa: E402


def _totals(conn):
    n, events, linked = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(occurrence_count), 0), "
        "COALESCE(SUM(device_mac IS NOT NULL), 0) FROM alerts WHERE alert_type='Threat'"
    ).fetchone()
    return n, events, linked


def ingest_once(conn, eve_path, window_seconds):
    """One ingest pass. Returns a summary dict (counts are deltas for this run)."""
    if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='devices'").fetchone():
        # Without it every cycle fails with "no such table: devices".
        raise ValueError("the test database has no devices table; "
                         "prepare it with iot23_seed_devices.py first")
    alerts.ensure_schema(conn)
    before = _totals(conn)
    alerts.run_once(conn, eve_path, window_seconds)
    after = _totals(conn)
    st = os.stat(eve_path)
    row = conn.execute("SELECT offset FROM alert_ingest_state WHERE st_dev=? AND st_ino=?",
                       (st.st_dev, st.st_ino)).fetchone()
    inserted = after[0] - before[0]
    events = after[1] - before[1]
    return {
        "inserted": inserted,
        "merged": events - inserted,
        "events": events,
        "linked_total": after[2],
        "alerts_total": after[0],
        "unread_bytes": st.st_size - (row[0] if row else 0),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Ingest an offline Suricata eve.json (from suricata -r) into a "
                    "TEST database with the real Assas alert ingester, once, then exit. "
                    "The real database and the live Suricata log folder are refused.",
        epilog="Example: %(prog)s --db /home/assas/b1test/test.db "
               "--eve /home/assas/b1test/run1/eve.json",
    )
    ap.add_argument("--db", required=True,
                    help="test database prepared with iot23_seed_devices.py")
    ap.add_argument("--eve", required=True,
                    help="eve.json written by suricata -r -l <test folder>")
    ap.add_argument("--classification", default=alerts.CLASSIFICATION_PATH,
                    help="classification.config Suricata used (default: %(default)s)")
    ap.add_argument("--window", type=int, default=alerts.DEDUP_WINDOW_SECONDS,
                    help="dedup window in seconds (default: %(default)s, as on the device)")
    args = ap.parse_args(argv)

    try:
        check_test_db(args.db)
        check_test_eve(args.eve)
    except UnsafePath as exc:
        return fail(exc)
    if not os.path.exists(args.db):
        return fail(f"{args.db} does not exist; prepare it with iot23_seed_devices.py")
    if not os.path.exists(args.eve):
        return fail(f"{args.eve} does not exist")

    alerts.CLASSIFICATION_PATH = args.classification
    with closing(sqlite3.connect(args.db, timeout=10.0)) as conn:
        try:
            s = ingest_once(conn, args.eve, args.window)
        except (ValueError, sqlite3.Error) as exc:
            return fail(exc)
        except MemoryError:
            # Memory cap hit (iot23_batch.sh runs this under ulimit -v); the
            # transaction is rolled back, so the test database is unchanged.
            return fail(f"out of memory while ingesting {args.eve}")
    print(f"alert events read: {s['events']}  new alerts: {s['inserted']}  "
          f"merged into existing: {s['merged']}")
    print(f"test database now: {s['alerts_total']} alert(s), {s['linked_total']} linked to a device")
    if s["unread_bytes"]:
        print(f"note: {s['unread_bytes']} byte(s) at the end of {args.eve} are an "
              "incomplete line (Suricata still writing?) and were not read")
    return 0


if __name__ == "__main__":
    sys.exit(main())
