#!/usr/bin/env python3
"""Detection-evaluation measurement (Sprint 2, EVALUATION.md §2–3).

Counts RAW Suricata alert events (pre-deduplication, straight from eve.json and
its rotated files) inside a replay time window, matched to the replayed capture
by its own lab addresses — an alert merely co-occurring with the window does
not count. Read-only; writes nothing to production data.

Usage:
  measure_detection.py --start 2026-11-06T12:00:00 --stop 2026-11-06T12:20:00 \
      --addr 192.168.1.195 [--addr ...] [--eve /var/log/suricata/eve.json] \
      [--save evidence-slice.jsonl]

Output: per-sid counts (sid, signature, matched events) + the total, to stdout;
optionally saves the matching raw lines for the evidence folder.
"""
import argparse
import glob
import json
import sys
from collections import Counter


def event_matches(obj, start, stop, addrs):
    """True for an alert event inside [start, stop] touching the capture's addresses."""
    if not isinstance(obj, dict) or obj.get("event_type") != "alert":
        return False
    ts = obj.get("timestamp", "")
    if not isinstance(ts, str) or not (start <= ts[:19] <= stop):
        return False
    if not addrs:
        return True
    return obj.get("src_ip") in addrs or obj.get("dest_ip") in addrs


def measure(paths, start, stop, addrs):
    counts = Counter()
    names = {}
    matched_lines = []
    for path in paths:
        try:
            handle = open(path, "rb")
        except OSError:
            continue
        with handle:
            for raw in handle:
                if b'"alert"' not in raw:
                    continue
                try:
                    obj = json.loads(raw)
                except ValueError:
                    continue
                if not event_matches(obj, start, stop, addrs):
                    continue
                alert = obj.get("alert") or {}
                sid = alert.get("signature_id")
                counts[sid] += 1
                names.setdefault(sid, alert.get("signature", ""))
                matched_lines.append(raw)
    return counts, names, matched_lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", required=True, help="window start, local ISO (YYYY-MM-DDTHH:MM:SS)")
    ap.add_argument("--stop", required=True, help="window stop, local ISO")
    ap.add_argument("--addr", action="append", default=[],
                    help="capture lab address (repeatable); empty = window only")
    ap.add_argument("--eve", default="/var/log/suricata/eve.json")
    ap.add_argument("--save", help="write the matching raw eve lines here (evidence slice)")
    args = ap.parse_args()

    paths = sorted(glob.glob(glob.escape(args.eve) + "*"))
    counts, names, lines = measure(paths, args.start, args.stop, set(args.addr))

    print(f"window {args.start} .. {args.stop}  addresses={sorted(args.addr) or 'ANY'}")
    for sid, n in counts.most_common():
        print(f"  sid={sid:<9} events={n:<6} {names.get(sid, '')[:60]}")
    print(f"TOTAL raw matched alert events: {sum(counts.values())} across {len(counts)} signature(s)")
    if args.save:
        with open(args.save, "wb") as f:
            f.writelines(lines)
        print(f"evidence slice saved: {args.save} ({len(lines)} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
