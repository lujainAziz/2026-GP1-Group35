"""Tests for the IoT-23 batch runner helpers (tools/iot23_batch.py)."""
import csv
import json
import os
import sqlite3
import struct
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "tools"))
import iot23_batch as batch

TOOLS = os.path.join(os.path.dirname(__file__), "tools")
MAC = "00:00:5e:00:53:01"          # documentation MAC (RFC 7042)
OTHER_MAC = "00:00:5e:00:53:02"
HOST = "192.168.1.195"


def eth_ipv4(src_mac, src_ip, dst_ip="198.51.100.8", vlan=False):
    mac = bytes(int(b, 16) for b in src_mac.split(":"))
    ip = bytes([0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0])
    ip += bytes(int(x) for x in src_ip.split(".")) + bytes(int(x) for x in dst_ip.split("."))
    tag = b"\x81\x00\x00\x05" if vlan else b""
    return b"\xff" * 6 + mac + tag + b"\x08\x00" + ip


def write_pcap(path, frames, endian="<", magic=0xA1B2C3D4):
    with open(path, "wb") as f:
        f.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1))
        for fr in frames:
            f.write(struct.pack(endian + "IIII", 0, 0, len(fr), len(fr)) + fr)


def _block(btype, body):
    body += b"\0" * (-len(body) % 4)
    n = len(body) + 12
    return struct.pack("<II", btype, n) + body + struct.pack("<I", n)


def write_pcapng(path, frames):
    with open(path, "wb") as f:
        f.write(_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        f.write(_block(1, struct.pack("<HHI", 1, 0, 65535)))
        for fr in frames:
            f.write(_block(6, struct.pack("<IIIII", 0, 0, 0, len(fr), len(fr)) + fr))


def test_scenario_table_in_repo_parses():
    rows = batch.read_table(os.path.join(TOOLS, "iot23_scenarios.txt"))
    names = [r["scenario"] for r in rows]
    assert len(rows) == 23 and len(set(names)) == 23
    assert sum(r["kind"] == "malware" for r in rows) == 20
    assert {r["scenario"] for r in rows if r["kind"] == "benign"} == {
        "CTU-Honeypot-Capture-4-1", "CTU-Honeypot-Capture-5-1", "CTU-Honeypot-Capture-7-1"}
    assert all(len(r["host_ips"]) == 1 and r["label"] for r in rows)
    by_name = {r["scenario"]: r for r in rows}
    assert by_name["CTU-IoT-Malware-Capture-1-1"]["label"] == "Hide and Seek"
    assert by_name["CTU-Honeypot-Capture-7-1"]["host_ips"] == ["192.168.1.158"]


def test_read_table_columns(tmp_path):
    t = tmp_path / "t.txt"
    t.write_text("# comment\nmalware  CTU-X-1  Mirai  Not_detected  -\n"
                 "benign CTU-Y-1 - - 192.168.1.5,192.168.1.6  # trailing\n")
    a, b = batch.read_table(str(t))
    assert a == {"kind": "malware", "scenario": "CTU-X-1", "label": "Mirai",
                 "earlier": "Not detected", "host_ips": []}
    assert b["host_ips"] == ["192.168.1.5", "192.168.1.6"] and b["label"] == ""
    for bad in ("other CTU-X-1 - - -", "malware ../x - - -", "malware X - Great -",
                "malware X - - 999.1.1.1", "malware X -"):
        t.write_text(bad + "\n")
        with pytest.raises(ValueError):
            batch.read_table(str(t))


def test_select_main_malware_pcap(tmp_path):
    d = tmp_path / "CTU-IoT-Malware-Capture-39-1"
    d.mkdir()
    sizes = {"2018-12-21-15-50-14-192.168.1.195.pcap": 50,
             "2018-12-21-15-50-14-192.168.1.195.irc.pcap": 900,
             "port23.pcap": 900, "x-port-23.pcap": 900, "test.pcap": 900,
             "telnet.pcap": 900, "a.only15000000.pcap": 900, "104.248.1.1.pcap": 900,
             "small.pcap": 10, "notes.txt": 900}
    for name, n in sizes.items():
        (d / name).write_bytes(b"x" * n)
    sel, skipped = batch.select_pcaps(str(d), "malware")
    assert [os.path.basename(p) for p in sel] == ["2018-12-21-15-50-14-192.168.1.195.pcap"]
    assert len(skipped) == 8          # 7 partial cuts + the smaller leftover
    assert batch.select_pcaps(str(d / "missing"), "malware") == ([], [])


def test_select_all_benign_pcaps(tmp_path):
    d = tmp_path / "CTU-Honeypot-Capture-7-1"
    (d / "Somfy-01").mkdir(parents=True)
    (d / "Somfy-02").mkdir()
    (d / "Somfy-01" / "a.pcap").write_bytes(b"x")
    (d / "Somfy-02" / "test.pcap").write_bytes(b"x")
    (d / "Somfy-02" / "readme.md").write_bytes(b"x")
    sel, skipped = batch.select_pcaps(str(d), "benign")
    assert [os.path.relpath(p, d) for p in sel] == [os.path.join("Somfy-01", "a.pcap"),
                                                    os.path.join("Somfy-02", "test.pcap")]
    assert skipped == []


def test_ip_from_name():
    assert batch.ip_from_name("/x/2018-12-21-15-50-14-192.168.1.195.pcap") == HOST
    assert batch.ip_from_name("2018-07-31-15-15-09-192.168.100.113.pcap") == "192.168.100.113"
    assert batch.ip_from_name("2019-07-03-15-15-47-first_start_somfy_gateway.pcap") is None
    assert batch.ip_from_name("2018-05-21_capture.pcap") is None
    assert batch.ip_from_name("999.168.1.1.pcap") is None


@pytest.mark.parametrize("writer", [
    lambda p, fr: write_pcap(p, fr),
    lambda p, fr: write_pcap(p, fr, endian=">"),
    lambda p, fr: write_pcap(p, fr, magic=0xA1B23C4D),
    write_pcapng,
])
def test_find_mac(tmp_path, writer):
    p = str(tmp_path / "c.pcap")
    frames = [eth_ipv4(OTHER_MAC, "192.168.1.1"), eth_ipv4(MAC, HOST, vlan=True)]
    frames += [eth_ipv4(MAC, HOST)] * 5 + [eth_ipv4(OTHER_MAC, HOST)]
    writer(p, frames)
    mac, seen = batch.find_mac(p, HOST)
    assert mac == MAC and seen[OTHER_MAC] == 1
    assert batch.find_mac(p, "192.168.1.250")[0] is None
    assert batch.lan_sources(p)[(HOST, MAC)] == 6


def test_find_mac_rejects_non_pcap(tmp_path):
    p = tmp_path / "x.pcap"
    p.write_bytes(b"not a pcap at all")
    with pytest.raises(batch.PcapError):
        batch.find_mac(str(p), HOST)


def alert(sid, src=HOST, dst="198.51.100.8", sev=3, cat="Misc activity", sig="ET INFO x"):
    return json.dumps({"event_type": "alert", "src_ip": src, "dest_ip": dst,
                       "alert": {"signature_id": sid, "severity": sev,
                                 "category": cat, "signature": sig}})


def test_eve_stats_and_category(tmp_path):
    eve = tmp_path / "eve.json"
    lines = [alert(1), alert(1), alert(2, src="10.0.0.9", dst="10.0.0.8", sev=1),
             json.dumps({"event_type": "flow"}), "not json"]
    eve.write_text("\n".join(lines) + "\n")
    total, sids, host = batch.eve_stats([str(eve)], [HOST])
    assert total == 3 and sids.most_common(1) == [(1, 2)] and len(sids) == 2
    assert host == {"events": 2, "strong": 0, "high": 0}
    assert batch.category_for(host) == "Weak"
    assert batch.category_for({"events": 0, "strong": 0, "high": 0}) == "Not detected"
    assert batch.category_for({"events": 3, "strong": 0, "high": 1}) == "Indirect"

    eve.write_text(alert(3, dst=HOST, src="198.51.100.9", sev=1,
                         cat="A Network Trojan was detected", sig="ET MALWARE Mirai") + "\n")
    _t, _s, host = batch.eve_stats([str(eve)], [HOST],
                                   {"A Network Trojan was detected": "trojan-activity"}.get)
    assert host == {"events": 1, "strong": 1, "high": 1}
    assert batch.category_for(host) == "Strong"


def make_db(path):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE alerts (alert_id INTEGER PRIMARY KEY, alert_type TEXT, "
                 "device_mac TEXT, device_role TEXT, occurrence_count INTEGER)")
    conn.executemany("INSERT INTO alerts (alert_type, device_mac, device_role, occurrence_count) "
                     "VALUES (?,?,?,?)", [("Threat", MAC, "source", 5),
                                          ("Threat", MAC, "target", 1),
                                          ("Threat", None, None, 2),
                                          ("Threat", OTHER_MAC, "source", 1),
                                          ("Anomaly", MAC, "source", 9)])
    conn.commit()
    conn.close()


def test_db_stats(tmp_path):
    db = str(tmp_path / "test.db")
    make_db(db)
    assert batch.db_stats(db, [MAC]) == {"stored_alerts": 4, "merged": 5,
                                         "linked_host_alerts": 2}
    assert batch.db_stats(db, [])["linked_host_alerts"] == 0


def test_result_and_summary(tmp_path):
    out = tmp_path / "out"
    table = tmp_path / "t.txt"
    table.write_text("malware CTU-A-1 Mirai Indirect -\n"
                     "malware CTU-B-1 Torii - -\n"
                     "benign CTU-C-1 Somfy Not_detected 192.168.1.9\n"
                     "malware CTU-D-1 Hakai - -\n")
    for scen in ("CTU-A-1", "CTU-B-1", "CTU-C-1"):
        (out / scen).mkdir(parents=True)
    db = str(out / "CTU-A-1" / "test.db")
    make_db(db)
    eve = out / "CTU-A-1" / "eve.json"
    eve.write_text(alert(7) + "\n" + alert(7) + "\n" + alert(8) + "\n")
    pcap = tmp_path / "a.pcap"
    pcap.write_bytes(b"x" * 123)
    common = ["--kind", "malware", "--label", "Mirai", "--db", db, "--host-ip", HOST,
              "--mac", MAC, "--pcap", str(pcap)]
    assert batch.main(["result", "--out", str(out / "CTU-A-1" / "result.json"),
                       "--scenario", "CTU-A-1", "--status", "done", "--eve", str(eve),
                       "--suricata-seconds", "4", "--run-seconds", "6",
                       "--classification", str(tmp_path / "none.config")] + common) == 0
    assert batch.main(["result", "--out", str(out / "CTU-B-1" / "result.json"),
                       "--scenario", "CTU-B-1", "--status", "need_ip"] + common) == 0
    for scen, cat in (("CTU-B-1", None), ("CTU-C-1", "Not detected")):
        if cat:
            (out / scen / "result.json").write_text(json.dumps(
                {"scenario": scen, "kind": "benign", "status": "done", "category": cat}))

    dst, rows, diffs = batch.build_summary(str(table), str(out))
    assert diffs == [("CTU-A-1", "Indirect", "Weak")]
    with open(dst, newline="") as f:
        got = list(csv.DictReader(f))
    assert [r["scenario"] for r in got] == ["CTU-A-1", "CTU-B-1", "CTU-C-1", "CTU-D-1"]
    a = got[0]
    assert (a["status"], a["pcap_bytes"], a["raw_alert_events"], a["raw_host_events"],
            a["stored_alerts"], a["merged"], a["linked_host_alerts"], a["distinct_sids"],
            a["top5_sids"], a["category"], a["earlier_category"]) == (
        "done", "123", "3", "3", "4", "5", "2", "2", "7:2;8:1", "Weak", "Indirect")
    assert got[1]["status"] == "need_ip" and got[1]["stored_alerts"] == ""
    assert got[3]["status"] == "not run"


def test_table_cli(tmp_path, capsys):
    t = tmp_path / "t.txt"
    t.write_text("benign CTU-C-1 - - 192.168.1.9,192.168.1.10\n")
    assert batch.main(["table", str(t)]) == 0
    assert capsys.readouterr().out == "benign\tCTU-C-1\t-\t192.168.1.9,192.168.1.10\n"
