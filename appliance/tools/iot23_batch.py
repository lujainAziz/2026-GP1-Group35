#!/usr/bin/env python3
"""Helpers for the IoT-23 batch runner (iot23_batch.sh, IOT23_OFFLINE_TEST.md).

Subcommands (all read-only except `result` and `summary`, which write inside the
batch output folder):
  table    TABLE                         the validated scenario table, tab separated
  select   --kind malware|benign DIR     the scenario's PCAP(s), one per line
  ip       PCAP                          the host IP in the file name, if any
  mac      --pcap P --ip IP              the host's source MAC (pure-Python reader)
  hint     --pcap P                      most frequent LAN source IPs (for a missing IP)
  result   --out F --scenario ... --eve E... --db D --host-ip IP... --mac M...
                                         one scenario's result.json
  summary  --table T --out-dir O         results/summary.csv + category comparison

The Python PCAP reader handles classic pcap (us/ns, both byte orders) and pcapng
(EPB/SPB) with Ethernet (and 802.1Q) frames.
"""
import argparse
import csv
import fnmatch
import ipaddress
import json
import os
import re
import sqlite3
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import addr_scope  # noqa: E402

# Partial cuts that sit next to a malware scenario's main capture.
MALWARE_EXCLUDE = ("*.irc.pcap", "port*", "*-port-23*", "test.pcap", "telnet.pcap",
                   "*.only15000000*", "104.248.*")

_IP_IN_NAME = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d])")
_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

# Provisional detection categories (the earlier evaluation's definitions are not
# in the repo). Computed from the raw alert events touching the host.
STRONG_CLASSTYPES = {"trojan-activity", "command-and-control", "targeted-activity"}
CATEGORIES = ("Strong", "Indirect", "Weak", "Not detected")

SUMMARY_FIELDS = (
    "scenario", "kind", "label", "status", "host_ips", "host_macs", "pcaps",
    "pcap_bytes", "suricata_seconds", "run_seconds", "raw_alert_events",
    "raw_host_events", "stored_alerts", "merged", "linked_host_alerts",
    "distinct_sids", "top5_sids", "category", "earlier_category",
)


# ---------------------------------------------------------------- scenarios

def read_table(path):
    """Scenario table -> list of dicts. Columns: kind scenario label earlier host_ip.
    '-' means empty; '#' starts a comment; label and earlier use '_' for spaces."""
    rows = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 5:
                raise ValueError(f"{path}:{n}: expected 5 columns, got {len(parts)}")
            kind, scen, label, earlier, host_ip = (None if p == "-" else p for p in parts)
            if kind not in ("malware", "benign"):
                raise ValueError(f"{path}:{n}: kind must be malware or benign")
            if not re.match(r"^[A-Za-z0-9._-]+$", scen or ""):
                raise ValueError(f"{path}:{n}: bad scenario name {scen!r}")
            earlier = earlier.replace("_", " ") if earlier else None
            if earlier and earlier not in CATEGORIES:
                raise ValueError(f"{path}:{n}: earlier category must be one of {CATEGORIES}")
            ips = host_ip.split(",") if host_ip else []
            for ip in ips:
                ipaddress.ip_address(ip)
            label = label.replace("_", " ") if label else ""
            rows.append({"kind": kind, "scenario": scen, "label": label,
                         "earlier": earlier, "host_ips": ips})
    return rows


def _is_excluded(name):
    return any(fnmatch.fnmatch(name, pat) for pat in MALWARE_EXCLUDE)


def select_pcaps(scen_dir, kind):
    """(selected, skipped). Malware: the largest *.pcap that is not a partial cut.
    Benign: every *.pcap below the folder."""
    found = []
    for root, dirs, files in os.walk(scen_dir):
        dirs.sort()
        for name in sorted(files):
            if name.endswith(".pcap"):
                found.append(os.path.join(root, name))
    if kind == "benign":
        return found, []
    keep = [p for p in found if not _is_excluded(os.path.basename(p))]
    skipped = [p for p in found if p not in keep]
    if not keep:
        return [], skipped
    keep.sort(key=lambda p: (-os.path.getsize(p), p))
    return keep[:1], skipped + keep[1:]


def ip_from_name(path):
    """The last IPv4 address in the file name, or None."""
    for cand in reversed(_IP_IN_NAME.findall(os.path.basename(path))):
        try:
            return str(ipaddress.IPv4Address(cand))
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------- pcap reader

class PcapError(Exception):
    pass


def _pcap_frames(f, head):
    magic_le = struct.unpack("<I", head)[0]
    if magic_le in (0xA1B2C3D4, 0xA1B23C4D):
        e = "<"
    elif struct.unpack(">I", head)[0] in (0xA1B2C3D4, 0xA1B23C4D):
        e = ">"
    else:
        raise PcapError("not a pcap/pcapng file")
    rest = f.read(20)
    if len(rest) < 20:
        raise PcapError("truncated pcap header")
    linktype = struct.unpack(e + "I", rest[16:20])[0] & 0x0FFFFFFF
    rec = struct.Struct(e + "IIII")
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        _s, _u, incl, _orig = rec.unpack(h)
        data = f.read(incl)
        if len(data) < incl:
            return
        yield linktype, data


def _pcapng_frames(f, head):
    e = "<"
    links = []
    block_type = struct.unpack("<I", head)[0]
    while True:
        raw_len = f.read(4)
        if len(raw_len) < 4:
            return
        if block_type == 0x0A0D0D0A:
            bom = f.read(4)
            if bom == b"\x4d\x3c\x2b\x1a":
                e = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                e = ">"
            else:
                raise PcapError("bad pcapng byte-order magic")
            blen = struct.unpack(e + "I", raw_len)[0]
            if blen < 16:
                raise PcapError("bad pcapng section header")
            body = bom + f.read(blen - 16)
            links = []
        else:
            blen = struct.unpack(e + "I", raw_len)[0]
            if blen < 12:
                raise PcapError("bad pcapng block length")
            body = f.read(blen - 12)
        if len(body) < blen - 12:
            return
        f.read(4)  # trailing length
        if block_type == 1 and len(body) >= 2:
            links.append(struct.unpack(e + "H", body[:2])[0])
        elif block_type == 6 and len(body) >= 20:
            iface, _hi, _lo, cap, _orig = struct.unpack(e + "IIIII", body[:20])
            if iface < len(links):
                yield links[iface], body[20:20 + cap]
        elif block_type == 3 and len(body) >= 4 and links:
            yield links[0], body[4:]
        nxt = f.read(4)
        if len(nxt) < 4:
            return
        block_type = struct.unpack(e + "I", nxt)[0]


def iter_frames(path):
    """(linktype, frame bytes) for each packet."""
    with open(path, "rb") as f:
        head = f.read(4)
        if len(head) < 4:
            return
        gen = _pcapng_frames(f, head) if head == b"\x0a\x0d\x0d\x0a" else _pcap_frames(f, head)
        yield from gen


def ether_ipv4_src(linktype, frame):
    """(src MAC, src IPv4) of an Ethernet IPv4 frame, else None."""
    if linktype != 1 or len(frame) < 14:
        return None
    etype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    while etype in (0x8100, 0x88A8) and len(frame) >= off + 4:
        etype = struct.unpack("!H", frame[off + 2:off + 4])[0]
        off += 4
    if etype != 0x0800 or len(frame) < off + 20:
        return None
    mac = ":".join(f"{b:02x}" for b in frame[6:12])
    return mac, str(ipaddress.IPv4Address(frame[off + 12:off + 16]))


def find_mac(path, ip, want=50, max_frames=20_000_000):
    """Most common source MAC of frames sent from `ip` (after `want` matches).
    Returns (mac or None, Counter of all MACs seen)."""
    seen = Counter()
    for i, (lt, frame) in enumerate(iter_frames(path)):
        if i >= max_frames:
            break
        got = ether_ipv4_src(lt, frame)
        if got and got[1] == ip:
            seen[got[0]] += 1
            if sum(seen.values()) >= want:
                break
    for mac, _n in seen.most_common():
        if not int(mac[:2], 16) & 1:
            return mac, seen
    return None, seen


def lan_sources(path, max_frames=200_000):
    """Counter of (LAN source IPv4, MAC) in the first frames."""
    c = Counter()
    for i, (lt, frame) in enumerate(iter_frames(path)):
        if i >= max_frames:
            break
        got = ether_ipv4_src(lt, frame)
        if got and addr_scope.is_lan_scoped(got[1]):
            c[(got[1], got[0])] += 1
    return c


# ---------------------------------------------------------------- results

def eve_stats(paths, host_ips, classtype_of=None):
    """Raw alert counts from eve files: totals, per-sid, and host-touching events."""
    hosts = set(host_ips)
    sids = Counter()
    host = {"events": 0, "strong": 0, "high": 0}
    total = 0
    for path in paths:
        with open(path, "rb") as f:
            for raw in f:
                if b'"alert"' not in raw:
                    continue
                try:
                    obj = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(obj, dict) or obj.get("event_type") != "alert":
                    continue
                a = obj.get("alert") if isinstance(obj.get("alert"), dict) else {}
                total += 1
                sids[a.get("signature_id")] += 1
                if obj.get("src_ip") not in hosts and obj.get("dest_ip") not in hosts:
                    continue
                host["events"] += 1
                ct = classtype_of(a.get("category")) if classtype_of else None
                sig = str(a.get("signature") or "").upper()
                if ct in STRONG_CLASSTYPES or "TROJAN" in sig or "MALWARE" in sig:
                    host["strong"] += 1
                if isinstance(a.get("severity"), int) and a["severity"] <= 2:
                    host["high"] += 1
    return total, sids, host


def category_for(host):
    """Provisional category from host-touching raw alerts (see IOT23_OFFLINE_TEST.md)."""
    if not host["events"]:
        return "Not detected"
    if host["strong"]:
        return "Strong"
    if host["high"]:
        return "Indirect"
    return "Weak"


def db_stats(db_path, macs):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        n, events = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(occurrence_count), 0) FROM alerts "
            "WHERE alert_type='Threat'").fetchone()
        marks = ",".join("?" for _ in macs) or "NULL"
        linked = conn.execute(
            f"SELECT COUNT(*) FROM alerts WHERE alert_type='Threat' AND device_mac IN ({marks}) "
            "AND device_role IN ('source', 'target')", tuple(macs)).fetchone()[0]
    finally:
        conn.close()
    return {"stored_alerts": n, "merged": events - n, "linked_host_alerts": linked}


def write_result(args):
    res = {"scenario": args.scenario, "kind": args.kind, "label": args.label or "",
           "status": args.status, "host_ips": ";".join(args.host_ip),
           "host_macs": ";".join(args.mac), "pcaps": len(args.pcap),
           "pcap_bytes": sum(os.path.getsize(p) for p in args.pcap if os.path.exists(p)),
           "suricata_seconds": args.suricata_seconds, "run_seconds": args.run_seconds}
    if args.status == "done":
        import alerts
        if args.classification:
            alerts.CLASSIFICATION_PATH = args.classification
        total, sids, host = eve_stats(args.eve, args.host_ip, alerts.classtype_for)
        res.update(db_stats(args.db, args.mac))
        res.update({
            "raw_alert_events": total, "raw_host_events": host["events"],
            "distinct_sids": len(sids),
            "top5_sids": ";".join(f"{s}:{n}" for s, n in sids.most_common(5)),
            "category": category_for(host),
        })
    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    os.replace(tmp, args.out)
    return res


def build_summary(table, out_dir):
    """results/summary.csv in table order; returns the category differences."""
    rows, diffs = [], []
    for t in read_table(table):
        path = os.path.join(out_dir, t["scenario"], "result.json")
        try:
            with open(path, encoding="utf-8") as f:
                res = json.load(f)
        except (OSError, ValueError):
            res = {"scenario": t["scenario"], "kind": t["kind"], "label": t["label"],
                   "status": "not run"}
        res["earlier_category"] = t["earlier"] or ""
        rows.append(res)
        new = res.get("category")
        if res.get("status") == "done":
            if not t["earlier"]:
                diffs.append((t["scenario"], "(none recorded)", new))
            elif t["earlier"] != new:
                diffs.append((t["scenario"], t["earlier"], new))
    os.makedirs(os.path.join(out_dir, "results"), exist_ok=True)
    dst = os.path.join(out_dir, "results", "summary.csv")
    with open(dst + ".tmp", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in SUMMARY_FIELDS})
    os.replace(dst + ".tmp", dst)
    return dst, rows, diffs


# ---------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("table")
    p.add_argument("table")
    p = sub.add_parser("select")
    p.add_argument("--kind", required=True, choices=("malware", "benign"))
    p.add_argument("dir")
    p = sub.add_parser("ip")
    p.add_argument("pcap")
    p = sub.add_parser("mac")
    p.add_argument("--pcap", required=True)
    p.add_argument("--ip", required=True)
    p = sub.add_parser("hint")
    p.add_argument("--pcap", required=True)
    p = sub.add_parser("result")
    p.add_argument("--out", required=True)
    p.add_argument("--scenario", required=True)
    p.add_argument("--kind", required=True)
    p.add_argument("--label", default="")
    p.add_argument("--status", required=True)
    p.add_argument("--pcap", action="append", default=[])
    p.add_argument("--eve", action="append", default=[])
    p.add_argument("--db")
    p.add_argument("--host-ip", action="append", default=[])
    p.add_argument("--mac", action="append", default=[])
    p.add_argument("--suricata-seconds", type=int, default=0)
    p.add_argument("--run-seconds", type=int, default=0)
    p.add_argument("--classification")
    p = sub.add_parser("summary")
    p.add_argument("--table", required=True)
    p.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)

    try:
        if args.cmd == "table":
            for t in read_table(args.table):
                print("	".join((t["kind"], t["scenario"], t["label"] or "-",
                                 ",".join(t["host_ips"]) or "-")))
            return 0
        if args.cmd == "select":
            sel, skipped = select_pcaps(args.dir, args.kind)
            for s in skipped:
                print(f"skip: {s}", file=sys.stderr)
            for path in sel:
                print(path)
            return 0 if sel else 1
        if args.cmd == "ip":
            ip = ip_from_name(args.pcap)
            if ip:
                print(ip)
            return 0 if ip else 1
        if args.cmd == "mac":
            mac, seen = find_mac(args.pcap, args.ip)
            if len(seen) > 1:
                print(f"note: {args.ip} sent from several MACs: {dict(seen)}", file=sys.stderr)
            if not mac or not _MAC_RE.match(mac):
                return 1
            print(mac)
            return 0
        if args.cmd == "hint":
            for (ip, mac), n in lan_sources(args.pcap).most_common(5):
                print(f"  {ip:<16} {mac}  {n} frames")
            return 0
        if args.cmd == "result":
            write_result(args)
            return 0
        if args.cmd == "summary":
            dst, rows, diffs = build_summary(args.table, args.out_dir)
            print(f"summary: {dst} ({sum(r.get('status') == 'done' for r in rows)}/"
                  f"{len(rows)} scenarios done)")
            changed = [d for d in diffs if d[1] != "(none recorded)"]
            missing = [d[0] for d in diffs if d[1] == "(none recorded)"]
            if changed:
                print("category differences (scenario: earlier -> this run):")
                for scen, old, new in changed:
                    print(f"  {scen}: {old} -> {new}")
            else:
                print("no category differences among the finished scenarios")
            if missing:
                print("no earlier category recorded for: " + ", ".join(missing))
            return 0
    except (OSError, ValueError, PcapError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
