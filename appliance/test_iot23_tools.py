"""Tests for the IoT-23 offline test tools (tools/IOT23_OFFLINE_TEST.md)."""
import json
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "tools"))
import alerts
import iot23_common as common
import iot23_ingest_once as ingest
import iot23_seed_devices as seed

MAC = "00:00:5e:00:53:01"          # documentation MAC (RFC 7042)
INFECTED = "192.168.1.195"         # IoT-23 Malware-34-1 infected host
C2 = "198.51.100.8"                # documentation address standing in for a C2

# The ingester stores file identity (st_dev, st_ino) as SQLite INTEGERs. Windows
# volume IDs can exceed that (test_alerts.py fails there the same way); the
# ingester runs on Linux, so the file-reading tests run there.
linux_file_ids = pytest.mark.skipif(
    max(os.stat(__file__).st_dev, os.stat(__file__).st_ino) >= 2 ** 63,
    reason="file IDs too large for SQLite INTEGER on this OS; run on the device")


@pytest.fixture(autouse=True)
def _no_host_excluded_ips(monkeypatch):
    # Never read the test host's real interface/gateway addresses.
    monkeypatch.setitem(alerts._excluded_ip_cache, "ips", set())
    monkeypatch.setitem(alerts._excluded_ip_cache, "known", True)
    monkeypatch.setitem(alerts._excluded_ip_cache, "ts", 9e18)


def make_source_db(path):
    """A stand-in for the device database, with rows that must NOT be copied."""
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE devices (mac TEXT PRIMARY KEY, ip TEXT, vendor TEXT, "
                 "first_seen TEXT, last_seen TEXT, status TEXT, user_name TEXT, "
                 "last_ipv4 TEXT, last_ipv6_global TEXT, last_ipv6_ll TEXT)")
    conn.execute("CREATE TABLE device_addresses (mac TEXT NOT NULL, addr TEXT NOT NULL, "
                 "family TEXT NOT NULL, source TEXT NOT NULL, first_seen TEXT NOT NULL, "
                 "last_seen TEXT NOT NULL, PRIMARY KEY (mac, addr))")
    conn.execute("CREATE INDEX idx_device_addresses_addr ON device_addresses(addr)")
    conn.execute("CREATE TABLE paired_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                 "token_hash TEXT)")
    conn.execute(alerts.ALERTS_DDL)
    conn.execute("INSERT INTO devices (mac, ip) VALUES ('02:00:00:00:00:99', '192.168.1.50')")
    conn.execute("INSERT INTO paired_sessions (token_hash) VALUES ('secret')")
    conn.commit()
    conn.close()


def prepared_db(tmp_path):
    src = tmp_path / "source.db"
    make_source_db(src)
    db = tmp_path / "test.db"
    assert seed.main(["--db", str(db), "--schema-from", str(src),
                      "--device", f"{MAC},{INFECTED},IoT-23 34-1",
                      "--seen", "2026-11-23T10:00:00"]) == 0
    return db


def ev(ts, sid=2024001, src=INFECTED, dst=C2, severity=2):
    return {"event_type": "alert", "timestamp": ts, "src_ip": src, "dest_ip": dst,
            "src_port": 40000, "dest_port": 23, "proto": "TCP",
            "alert": {"signature_id": sid, "signature": f"SIG {sid}", "severity": severity}}


def write_eve(path, events):
    path.write_text("".join(json.dumps(e) + "\n" for e in events))


# --------------------------------------------------------------------------- #
# Safety guards
# --------------------------------------------------------------------------- #
def test_check_test_db_refuses_real_path_and_hard_link(tmp_path):
    real = tmp_path / "assas.db"
    real.write_bytes(b"")
    with pytest.raises(common.UnsafePath):
        common.check_test_db(str(real), real_paths=[str(real)])
    with pytest.raises(common.UnsafePath):  # same file through another spelling
        common.check_test_db(str(tmp_path / "x" / ".." / "assas.db"), real_paths=[str(real)])
    link = tmp_path / "alias.db"
    os.link(real, link)
    with pytest.raises(common.UnsafePath):
        common.check_test_db(str(link), real_paths=[str(real)])
    assert common.check_test_db(str(tmp_path / "test.db"), real_paths=[str(real)])


def test_check_test_eve_refuses_live_log_folder(tmp_path):
    live = tmp_path / "suricata"
    with pytest.raises(common.UnsafePath):
        common.check_test_eve(str(live / "eve.json"), live_dirs=[str(live)])
    with pytest.raises(common.UnsafePath):
        common.check_test_eve(str(live / "sub" / "eve.json"), live_dirs=[str(live)])
    assert common.check_test_eve(str(tmp_path / "run1" / "eve.json"), live_dirs=[str(live)])
    # a sibling folder whose name merely starts the same is not the live folder
    assert common.check_test_eve(str(tmp_path / "suricata2" / "eve.json"), live_dirs=[str(live)])


def test_both_tools_refuse_the_real_database(tmp_path, monkeypatch, capsys):
    real = tmp_path / "assas.db"
    make_source_db(real)
    before = real.read_bytes()
    monkeypatch.setattr(common, "REAL_DB_PATH", str(real))
    assert seed.main(["--db", str(real), "--device", f"{MAC},{INFECTED}"]) == 2
    eve = tmp_path / "run1" / "eve.json"
    eve.parent.mkdir()
    write_eve(eve, [ev("2018-12-21T15:50:14.000000+0000")])
    assert ingest.main(["--db", str(real), "--eve", str(eve)]) == 2
    assert "real Assas database" in capsys.readouterr().err
    assert real.read_bytes() == before


def test_ingest_refuses_live_eve(tmp_path, monkeypatch, capsys):
    live = tmp_path / "suricata"
    live.mkdir()
    write_eve(live / "eve.json", [ev("2018-12-21T15:50:14.000000+0000")])
    monkeypatch.setattr(common, "LIVE_EVE_DIR", str(live))
    db = prepared_db(tmp_path)
    assert ingest.main(["--db", str(db), "--eve", str(live / "eve.json")]) == 2
    assert "live Suricata log folder" in capsys.readouterr().err


def test_help_texts(capsys):
    for tool in (seed, ingest):
        with pytest.raises(SystemExit) as exc:
            tool.main(["--help"])
        assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "TEST database" in out and "--schema-from" in out and "--eve" in out


# --------------------------------------------------------------------------- #
# Seeding
# --------------------------------------------------------------------------- #
def test_parse_device():
    assert seed.parse_device("00-00-5E-00-53-01, 192.168.100.113, Hakai host") == \
        (MAC, "192.168.100.113", "Hakai host")
    assert seed.parse_device(f"{MAC},{INFECTED}") == (MAC, INFECTED, None)
    for bad in ("nonsense", f"{MAC}", f"zz:00:5e:00:53:01,{INFECTED}",
                f"01:00:5e:00:53:01,{INFECTED}",       # multicast MAC
                f"{MAC},999.1.1.1", f"{MAC},{C2}"):     # bad IP / not a LAN address
        with pytest.raises(ValueError):
            seed.parse_device(bad)


def test_schema_copied_without_rows(tmp_path):
    db = prepared_db(tmp_path)
    conn = sqlite3.connect(db)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert {"devices", "device_addresses", "paired_sessions", "alerts",
            "idx_device_addresses_addr"} <= names
    assert conn.execute("SELECT COUNT(*) FROM paired_sessions").fetchone()[0] == 0
    assert conn.execute("SELECT mac, ip, last_ipv4, user_name, status FROM devices").fetchall() == \
        [(MAC, INFECTED, INFECTED, "IoT-23 34-1", "offline")]
    conn.close()


def test_seed_is_repeatable(tmp_path):
    db = prepared_db(tmp_path)
    assert seed.main(["--db", str(db), "--schema-from", str(tmp_path / "source.db"),
                      "--device", f"{MAC},{INFECTED},renamed"]) == 0
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*), MAX(user_name) FROM devices").fetchone() == (1, "renamed")
    conn.close()


def test_seed_refuses_ambiguous_or_evidence_covered_ip(tmp_path):
    db = prepared_db(tmp_path)
    # two MACs for one IP in one call
    assert seed.main(["--db", str(db), "--device", f"02:00:00:00:00:01,192.168.1.10",
                      "--device", f"02:00:00:00:00:02,192.168.1.10"]) == 2
    # IP already owned by another device
    assert seed.main(["--db", str(db), "--device", f"02:00:00:00:00:03,{INFECTED}"]) == 2
    # evidence rows would override the devices columns
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO device_addresses VALUES (?, '192.168.1.20', 'ipv4', 'arp', "
                 "'2026-01-01T00:00:00', '2026-01-01T00:00:00')", (MAC,))
    conn.commit()
    conn.close()
    assert seed.main(["--db", str(db), "--device", f"{MAC},192.168.1.20"]) == 2


def test_seed_without_schema_fails_cleanly(tmp_path):
    assert seed.main(["--db", str(tmp_path / "empty.db"), "--device", f"{MAC},{INFECTED}"]) == 2


# --------------------------------------------------------------------------- #
# Ingest
# --------------------------------------------------------------------------- #
@linux_file_ids
def test_ingest_links_dedups_with_packet_times(tmp_path, capsys):
    db = prepared_db(tmp_path)
    eve = tmp_path / "run1" / "eve.json"
    eve.parent.mkdir()
    write_eve(eve, [
        ev("2018-12-21T15:50:14.000000+0000"),
        ev("2018-12-21T15:52:00.000000+0000"),
        ev("2018-12-21T15:56:30.000000+0000"),             # 4.5 min after the last: merged
        ev("2018-12-21T16:10:00.000000+0000"),             # > 5 min gap: new alert
        ev("2018-12-21T15:51:00.000000+0000", sid=2010935, src=C2, dst=INFECTED, severity=1),
        ev("2018-12-21T15:53:00.000000+0000", sid=999, src="198.51.100.5", dst=C2),
        {"event_type": "stats", "timestamp": "2018-12-21T15:55:00.000000+0000"},
    ])
    assert ingest.main(["--db", str(db), "--eve", str(eve), "--classification",
                        str(tmp_path / "missing.config")]) == 0
    out = capsys.readouterr().out
    assert "alert events read: 6  new alerts: 4  merged into existing: 2" in out
    assert "4 alert(s), 3 linked" in out

    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT rule_id, device_mac, device_role, severity, occurrence_count, "
        "event_time, last_event_time FROM alerts ORDER BY alert_id").fetchall()
    t = alerts.local_naive_iso
    assert rows == [  # alert ids follow file order
        (2024001, MAC, "source", "Medium", 3,
         t("2018-12-21T15:50:14+00:00"), t("2018-12-21T15:56:30+00:00")),
        (2024001, MAC, "source", "Medium", 1,
         t("2018-12-21T16:10:00+00:00"), t("2018-12-21T16:10:00+00:00")),
        (2010935, MAC, "target", "High", 1,
         t("2018-12-21T15:51:00+00:00"), t("2018-12-21T15:51:00+00:00")),
        (999, None, None, "Medium", 1,
         t("2018-12-21T15:53:00+00:00"), t("2018-12-21T15:53:00+00:00")),
    ]
    conn.close()

    # A second run reads nothing new (checkpoint kept in the test database).
    assert ingest.main(["--db", str(db), "--eve", str(eve)]) == 0
    assert "alert events read: 0  new alerts: 0" in capsys.readouterr().out


def test_ingest_requires_devices_table(tmp_path, capsys):
    db = tmp_path / "bare.db"
    sqlite3.connect(db).close()
    eve = tmp_path / "eve.json"
    write_eve(eve, [ev("2018-12-21T15:50:14.000000+0000")])
    assert ingest.main(["--db", str(db), "--eve", str(eve)]) == 2
    assert "no devices table" in capsys.readouterr().err


@linux_file_ids
def test_ingest_reports_incomplete_last_line(tmp_path, capsys):
    db = prepared_db(tmp_path)
    eve = tmp_path / "eve.json"
    eve.write_text(json.dumps(ev("2018-12-21T15:50:14.000000+0000")) + "\n" + '{"event_type": "al')
    assert ingest.main(["--db", str(db), "--eve", str(eve)]) == 0
    assert "incomplete line" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Large eve.json: bounded memory (the device froze on a 6.9 GB eve.json)
# --------------------------------------------------------------------------- #
PAD = "x" * 400


def write_big_eve(path, lines=60_000, alert_every=600):
    """~30 MB of mostly non-alert events with an alert every `alert_every` lines,
    2 minutes apart over two sids (so the 5-minute dedup merges them), plus stats records that
    contain the word "alert" like Suricata's do. Returns the alert count."""
    n = 0
    with open(path, "w") as f:
        for i in range(lines):
            if i % alert_every == 0:
                m = 2 * n
                ts = f"2018-12-21T{10 + m // 60:02d}:{m % 60:02d}:00.000000+0000"
                f.write(json.dumps(ev(ts, sid=2024001 + n % 2)) + "\n")
                n += 1
            elif i % 5000 == 1:
                f.write(json.dumps({"event_type": "stats", "stats": {"detect": {"alert": n}}}) + "\n")
            else:
                f.write(json.dumps({"event_type": "flow", "src_ip": INFECTED, "pad": PAD}) + "\n")
    return n


def alert_rows(db):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(
            "SELECT rule_id, device_mac, device_role, severity, occurrence_count, "
            "event_time, last_event_time, state FROM alerts ORDER BY alert_id").fetchall()
    finally:
        conn.close()


@linux_file_ids
def test_ingest_streams_large_eve_and_alert_lines_give_same_result(tmp_path, capsys):
    import tracemalloc

    (tmp_path / "full").mkdir()
    (tmp_path / "cut").mkdir()
    eve = tmp_path / "full" / "eve.json"
    n = write_big_eve(eve)
    size = eve.stat().st_size
    assert size > 25_000_000

    db_full = prepared_db(tmp_path / "full")
    tracemalloc.start()
    try:
        assert ingest.main(["--db", str(db_full), "--eve", str(eve)]) == 0
        _cur, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # The old whole-file read held the file twice (bytes + split list).
    assert peak < size // 5, f"peak {peak} bytes for a {size}-byte eve.json"
    out = capsys.readouterr().out
    assert f"alert events read: {n} " in out

    # What iot23_batch.sh does above IOT23_EVE_FILTER_MB (grep -F '"alert"').
    cut = tmp_path / "cut" / "alert-lines.json"
    with open(eve, "rb") as src, open(cut, "wb") as dst:
        dst.writelines(line for line in src if b'"alert"' in line)
    db_cut = prepared_db(tmp_path / "cut")
    assert ingest.main(["--db", str(db_cut), "--eve", str(cut)]) == 0
    rows = alert_rows(db_full)
    assert rows and rows == alert_rows(db_cut)
    assert sum(r[4] for r in rows) == n and len(rows) < n  # dedup merged some
