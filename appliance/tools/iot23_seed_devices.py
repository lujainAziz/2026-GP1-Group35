#!/usr/bin/env python3
"""Prepare a TEST database for the IoT-23 offline test (IOT23_OFFLINE_TEST.md).

1. --schema-from: copy the table/index definitions (no rows) from a database,
   opened read-only. Copying from the real database gives the exact device
   schema without copying devices, alerts or pairing tokens.
2. --device MAC,IP[,NAME]: add one inventory row per infected dataset host.

The alert ingester links a LAN-scoped address to a device through the devices
columns (ip / last_ipv4 / last_ipv6_*) only when that address has NO
device_addresses evidence rows, and that column match has no time window, so
2018-2019 packet timestamps still link. This script therefore writes devices
rows only and refuses an IP that has evidence rows or another owner.

Refuses the real database path as the target.

Example:
  iot23_seed_devices.py --db /home/assas/b1test/test.db \\
      --schema-from /home/assas/assas/assas.db \\
      --device 00:00:5e:00:53:01,192.168.1.195,"IoT-23 34-1 (Mirai)"
"""
import argparse
import ipaddress
import os
import re
import sqlite3
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import addr_scope  # noqa: E402
from iot23_common import UnsafePath, check_test_db, fail  # noqa: E402

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def parse_device(spec):
    """'MAC,IP[,NAME]' -> (mac, ip, name). Raises ValueError with a reason."""
    parts = [p.strip() for p in spec.split(",", 2)]
    if len(parts) < 2:
        raise ValueError(f"{spec!r}: expected MAC,IP[,NAME]")
    mac = parts[0].lower().replace("-", ":")
    if not _MAC_RE.match(mac):
        raise ValueError(f"{spec!r}: bad MAC {parts[0]!r}")
    if int(mac[:2], 16) & 1:
        raise ValueError(f"{spec!r}: {mac} is a multicast/broadcast MAC")
    try:
        ip = str(ipaddress.ip_address(parts[1]))
    except ValueError:
        raise ValueError(f"{spec!r}: bad IP {parts[1]!r}") from None
    if not addr_scope.is_lan_scoped(ip):
        raise ValueError(f"{spec!r}: {ip} is not a LAN address; the ingester "
                         "links it only through device_addresses evidence")
    name = parts[2] if len(parts) > 2 and parts[2] else None
    return mac, ip, name


def copy_schema(dst, src_path):
    """Create src's tables/indexes/views/triggers (no rows) that dst lacks.
    Returns the number of objects created."""
    src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True, timeout=5.0)
    try:
        objects = src.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE sql IS NOT NULL AND name NOT GLOB 'sqlite_*' "
            "ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 ELSE 2 END, rowid"
        ).fetchall()
    finally:
        src.close()
    have = {r[0] for r in dst.execute("SELECT name FROM sqlite_master").fetchall()}
    created = 0
    with dst:
        for _type, name, sql in objects:
            if name not in have:
                dst.execute(sql)
                created += 1
    return created


def _ip_column(ip):
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return "last_ipv4"
    return "last_ipv6_ll" if addr.is_link_local else "last_ipv6_global"


def seed_devices(conn, devices, seen):
    """Upsert the device rows. Refuses an IP with evidence rows or a second owner."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)").fetchall()}
    if not cols:
        raise ValueError("the test database has no devices table; "
                         "run with --schema-from first")
    macs_by_ip = {}
    for mac, ip, _name in devices:
        if macs_by_ip.setdefault(ip, mac) != mac:
            raise ValueError(f"{ip} given for two MACs; the alert would stay unlinked")
    try:
        evidence = conn.execute("SELECT DISTINCT addr FROM device_addresses").fetchall()
    except sqlite3.OperationalError:
        evidence = []
    evidence = {r[0] for r in evidence}
    with conn:
        for mac, ip, name in devices:
            norm = ip if ":" not in ip else ipaddress.ip_address(ip).exploded
            if norm in evidence:
                raise ValueError(f"{ip} has device_addresses rows; they override "
                                 "the devices columns, so remove them first")
            other = conn.execute(
                "SELECT mac FROM devices WHERE mac<>? AND ? IN "
                "(ip, last_ipv4, last_ipv6_global, last_ipv6_ll)", (mac, ip),
            ).fetchone() if {"last_ipv4", "last_ipv6_global", "last_ipv6_ll"} <= cols else None
            if other:
                raise ValueError(f"{ip} already belongs to {other[0]} in the test database")
            row = {"mac": mac, "ip": ip, "first_seen": seen, "last_seen": seen,
                   "status": "offline"}
            if _ip_column(ip) in cols:
                row[_ip_column(ip)] = ip
            if name and "user_name" in cols:
                row["user_name"] = name
            row = {k: v for k, v in row.items() if k in cols}
            names = ", ".join(row)
            updates = ", ".join(f"{k}=excluded.{k}" for k in row if k != "mac")
            conn.execute(
                f"INSERT INTO devices ({names}) VALUES ({', '.join('?' for _ in row)}) "
                f"ON CONFLICT(mac) DO UPDATE SET {updates}",
                tuple(row.values()),
            )
    return len(devices)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Create/prepare a TEST database for the IoT-23 offline test: "
                    "copy the schema (no rows) and add the infected dataset hosts "
                    "as devices. Never use the real database as --db.",
        epilog="Example: %(prog)s --db /home/assas/b1test/test.db "
               "--schema-from /home/assas/assas/assas.db "
               "--device 00:00:5e:00:53:01,192.168.1.195,\"IoT-23 34-1\"",
    )
    ap.add_argument("--db", required=True,
                    help="test database to create or update (the real database is refused)")
    ap.add_argument("--schema-from", metavar="DB",
                    help="copy table/index definitions (no rows) from this database, "
                         "opened read-only; normally the real database")
    ap.add_argument("--device", action="append", default=[], metavar="MAC,IP[,NAME]",
                    help="infected host from the dataset (repeatable); IP must be a "
                         "LAN address, MAC is the host's MAC seen in the PCAP")
    ap.add_argument("--seen", metavar="ISO",
                    help="first_seen/last_seen to store (local ISO); default now")
    args = ap.parse_args(argv)

    try:
        check_test_db(args.db)
        devices = [parse_device(s) for s in args.device]
    except (UnsafePath, ValueError) as exc:
        return fail(exc)
    if not args.schema_from and not devices:
        return fail("nothing to do: give --schema-from and/or --device")
    if args.schema_from and not os.path.exists(args.schema_from):
        return fail(f"--schema-from {args.schema_from} does not exist")

    seen = args.seen or datetime.now().replace(microsecond=0).isoformat(sep="T")
    conn = sqlite3.connect(args.db, timeout=10.0)
    try:
        if args.schema_from:
            print(f"schema: {copy_schema(conn, args.schema_from)} object(s) created "
                  f"from {args.schema_from} (no rows copied)")
        if devices:
            seed_devices(conn, devices, seen)
            for mac, ip, name in devices:
                print(f"device: {mac}  {ip}  {name or ''}")
    except (ValueError, sqlite3.Error) as exc:
        return fail(exc)
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
