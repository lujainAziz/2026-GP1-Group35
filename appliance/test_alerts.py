"""Unit tests for the Suricata eve.json -> SQLite Threat Alert ingester (PBI-14).

Offline and deterministic: eve events are synthesised as JSON lines (no Suricata
binary needed), which also lets us control file identity/rotation/offsets to test
resume safety, multi-rotation recovery, and the reaper precisely.
"""
import json
import os
import sqlite3

import pytest

import alerts


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
def make_conn(tmp_path):
    conn = sqlite3.connect(tmp_path / "test.db")
    alerts.ensure_schema(conn)
    conn.execute(
        "CREATE TABLE devices (mac TEXT PRIMARY KEY, ip TEXT, last_ipv4 TEXT, "
        "last_ipv6_global TEXT, last_ipv6_ll TEXT)"
    )
    conn.commit()
    return conn


def eve_alert(sig="ET TEST Rule", sid=1000, sev=2, src=None, dst=None,
              sp=None, dp=None, ts="2026-11-02T10:00:00+0300"):
    o = {"event_type": "alert", "timestamp": ts,
         "alert": {"signature": sig, "signature_id": sid, "severity": sev}}
    if src is not None:
        o["src_ip"] = src
    if dst is not None:
        o["dest_ip"] = dst
    if sp is not None:
        o["src_port"] = sp
    if dp is not None:
        o["dest_port"] = dp
    return json.dumps(o) + "\n"


def write(path, *lines):
    path.write_text("".join(lines))
    return path


def count(conn, where="1", args=()):
    return conn.execute(f"SELECT COUNT(*) FROM alerts WHERE {where}", args).fetchone()[0]


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("prio,label", [
    (1, "Critical"), (2, "High"), (3, "Medium"),
    (4, "Low"), (5, "Low"), (0, "Low"), (None, "Low"), ("x", "Low"),
])
def test_severity_label(prio, label):
    assert alerts.severity_label(prio) == label


def test_local_naive_iso_strips_tz_to_seconds():
    assert alerts.local_naive_iso("2026-11-02T15:40:44.894939+0300") == "2026-11-02T15:40:44"
    assert alerts.local_naive_iso(None) is None
    assert alerts.local_naive_iso("not-a-date") is None


def test_parse_alert_event_with_and_without_addresses():
    full = alerts.parse_alert_event(json.loads(
        eve_alert(sig="ET SCAN", sid=42, sev=1, src="10.0.0.5", dst="8.8.8.8", sp=1234, dp=53)))
    assert full == {
        "title": "ET SCAN", "rule_id": 42, "severity": "Critical",
        "event_time": "2026-11-02T10:00:00",
        "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "src_port": 1234, "dst_port": 53,
        "ether_src": None, "ether_dst": None,
    }
    # decoder-event alert: no addresses/ports
    decoder = alerts.parse_alert_event(json.loads(eve_alert(sig="SURICATA IPv6", sid=2200013, sev=3)))
    assert decoder["src_ip"] is None and decoder["dst_ip"] is None
    assert decoder["src_port"] is None and decoder["severity"] == "Medium"
    # non-alert events are ignored
    assert alerts.parse_alert_event({"event_type": "stats"}) is None


def test_split_complete_lines_leaves_partial():
    complete, consumed = alerts.split_complete_lines(b"a\nbb\n")
    assert complete == [b"a", b"bb"] and consumed == 5
    complete, consumed = alerts.split_complete_lines(b"a\npart")
    assert complete == [b"a"] and consumed == 2  # 'part' left unconsumed


# --------------------------------------------------------------------------- #
# Device linking
# --------------------------------------------------------------------------- #
def test_link_device_one_both_neither(tmp_path):
    conn = make_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('aa:aa','10.0.0.5')")
    conn.execute("INSERT INTO devices(mac,last_ipv6_global) VALUES('bb:bb','2001:db8::6')")
    conn.commit()
    assert alerts.link_device(conn, "10.0.0.5", "8.8.8.8") == "aa:aa"   # src only
    assert alerts.link_device(conn, "8.8.8.8", "10.0.0.5") == "aa:aa"   # dst only
    assert alerts.link_device(conn, "10.0.0.5", "2001:db8::6") == "aa:aa"  # both -> source
    assert alerts.link_device(conn, "9.9.9.9", "1.1.1.1") is None       # neither
    assert alerts.link_device(conn, None, None) is None


ADDR_TABLE_DDL = (
    "CREATE TABLE device_addresses (mac TEXT NOT NULL, addr TEXT NOT NULL, "
    "family TEXT NOT NULL, source TEXT NOT NULL, first_seen TEXT NOT NULL, "
    "last_seen TEXT NOT NULL, PRIMARY KEY (mac, addr))"
)


def add_addr_table(conn, rows=()):
    conn.execute(ADDR_TABLE_DDL)
    conn.executemany(
        "INSERT INTO device_addresses VALUES (?,?,?,?,?,?)", rows)
    conn.commit()


def test_link_device_missing_address_table_falls_back(tmp_path):
    # Older discovery (no device_addresses table): behaviour identical to the
    # column-only matching, no error.
    conn = make_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('aa:aa','10.0.0.5')")
    conn.commit()
    assert alerts.link_device(conn, "10.0.0.5", "8.8.8.8", "2026-11-05T10:00:00") == "aa:aa"
    assert alerts.link_device(conn, "9.9.9.9", None, "2026-11-05T10:00:00") is None


def test_link_device_multi_address_ipv4_and_rotating_ipv6(tmp_path):
    # One device with an IPv4 and TWO global IPv6 addresses (privacy rotation):
    # the evidence set links both, even though the devices columns only hold the
    # newest address. Addresses are stored exploded lowercase (eve.json form).
    conn = make_conn(tmp_path)
    conn.execute(
        "INSERT INTO devices(mac,last_ipv4,last_ipv6_global) "
        "VALUES('dd:dd','192.168.100.50','2001:16a2:0000:0000:0000:0000:0000:0b0b')")
    old6 = "2001:16a2:0000:0000:0000:0000:0000:0a0a"
    new6 = "2001:16a2:0000:0000:0000:0000:0000:0b0b"
    add_addr_table(conn, [
        ("dd:dd", "192.168.100.50", "ipv4", "arp", "2026-11-01T00:00:00", "2026-11-05T12:00:00"),
        ("dd:dd", old6, "ipv6", "ndp", "2026-11-01T00:00:00", "2026-11-03T00:00:00"),
        ("dd:dd", new6, "ipv6", "ndp", "2026-11-04T00:00:00", "2026-11-05T12:00:00"),
    ])
    # rotated-out address still links for an event inside ITS window
    assert alerts.link_device(conn, old6, "8.8.8.8", "2026-11-02T10:00:00") == "dd:dd"
    # current address links
    assert alerts.link_device(conn, "2606:4700::1", new6, "2026-11-05T10:00:00") == "dd:dd"
    # IPv4 links via the table too
    assert alerts.link_device(conn, "192.168.100.50", "8.8.8.8", "2026-11-05T10:00:00") == "dd:dd"
    # an event long after the old address's evidence window stays unlinked
    assert alerts.link_device(conn, old6, "8.8.8.8", "2026-11-05T10:00:00") is None


def test_link_device_evidence_window_boundaries(tmp_path):
    # Window = [first_seen - 2h, last_seen + 24h]; both bounds tested both sides.
    conn = make_conn(tmp_path)
    addr = "2001:16a2:0000:0000:0000:0000:0000:0c0c"
    add_addr_table(conn, [
        ("ee:ee", addr, "ipv6", "ndp", "2026-11-04T10:00:00", "2026-11-04T12:00:00"),
    ])
    link = lambda t: alerts.link_device(conn, "2606:4700::1", addr, t)
    assert link("2026-11-04T08:01:00") == "ee:ee"   # first - 1h59m: inside pre-slack
    assert link("2026-11-04T07:59:00") is None      # first - 2h01m: replayed old event
    assert link("2026-11-05T11:59:00") == "ee:ee"   # last + 23h59m: inside grace
    assert link("2026-11-05T12:01:00") is None      # last + 24h01m: expired


def test_columns_cannot_bypass_an_expired_evidence_window(tmp_path):
    # A rotated-out address can linger in devices.last_ipv6_global. When the
    # evidence table KNOWS the address but its ownership window has expired for
    # the event time, the stale column entry must not link the alert anyway.
    conn = make_conn(tmp_path)
    stale = "2001:16a2:0000:0000:0000:0000:0000:0f0f"
    conn.execute(
        "INSERT INTO devices(mac,last_ipv6_global) VALUES('dd:dd', ?)", (stale,))
    conn.commit()
    add_addr_table(conn, [
        ("dd:dd", stale, "ipv6", "ndp", "2026-11-01T00:00:00", "2026-11-02T00:00:00"),
    ])
    # inside the evidence window: links
    assert alerts.link_device(conn, "2606:4700::1", stale, "2026-11-01T12:00:00") == "dd:dd"
    # days after last evidence: the column alone must NOT bypass the window
    assert alerts.link_device(conn, "2606:4700::1", stale, "2026-11-05T12:00:00") is None


def test_columns_still_link_addresses_without_any_evidence(tmp_path):
    # The evidence table exists but has no rows for this address (pre-evidence
    # data): the legacy column match remains the fallback.
    conn = make_conn(tmp_path)
    conn.execute(
        "INSERT INTO devices(mac,last_ipv4) VALUES('ee:ff','192.168.100.80')")
    conn.commit()
    add_addr_table(conn, [
        ("other", "2001:16a2:0000:0000:0000:0000:0000:1111", "ipv6", "ndp",
         "2026-11-01T00:00:00", "2026-11-05T00:00:00"),
    ])
    assert alerts.link_device(conn, "192.168.100.80", "8.8.8.8", "2026-11-05T10:00:00") == "ee:ff"


def test_link_device_ownership_conflict_stays_unlinked(tmp_path):
    # Two MACs with overlapping evidence for one address -> never guess.
    conn = make_conn(tmp_path)
    addr = "2001:16a2:0000:0000:0000:0000:0000:0d0d"
    add_addr_table(conn, [
        ("aa:aa", addr, "ipv6", "ndp", "2026-11-04T00:00:00", "2026-11-05T00:00:00"),
        ("bb:bb", addr, "ipv6", "span", "2026-11-04T00:00:00", "2026-11-05T00:00:00"),
    ])
    assert alerts.link_device(conn, "2606:4700::1", addr, "2026-11-04T12:00:00") is None


def test_link_device_normalizes_column_address_forms(tmp_path):
    # eve.json writes IPv6 zero-padded exploded; the inventory column holds the
    # kernel's compressed form. The same address must match regardless of form.
    conn = make_conn(tmp_path)
    conn.execute(
        "INSERT INTO devices(mac,last_ipv6_global) VALUES('cc:cc','2001:16a2:dea6:2200:6854:6bc7:cf3:1d4c')")
    conn.commit()
    exploded = "2001:16a2:dea6:2200:6854:6bc7:0cf3:1d4c"
    assert alerts.link_device(conn, "2606:4700::1", exploded, "2026-11-05T10:00:00") == "cc:cc"


def test_relink_recent_repairs_discovery_lag_without_touching_counts(tmp_path):
    conn = make_conn(tmp_path)
    addr = "2001:16a2:0000:0000:0000:0000:0000:0e0e"
    # Two unlinked alerts on that address: one recent, one old (outside window).
    with conn:
        conn.execute(
            "INSERT INTO alerts (device_mac, alert_type, title, rule_id, event_time, "
            "src_ip, dst_ip, severity, state, occurrence_count, last_event_time) "
            "VALUES (NULL,'Threat','ET X',1,?, '2606:4700::1', ?, 'Medium','New',7,?)",
            ("2026-11-05T10:00:00", addr, "2026-11-05T10:00:00"))
        conn.execute(
            "INSERT INTO alerts (device_mac, alert_type, title, rule_id, event_time, "
            "src_ip, dst_ip, severity, state, occurrence_count, last_event_time) "
            "VALUES (NULL,'Threat','ET X',1,?, '2606:4700::1', ?, 'Medium','Reviewed',3,?)",
            ("2026-11-01T10:00:00", addr, "2026-11-01T10:00:00"))
    # Evidence arrives AFTER the alerts were stored (discovery lag).
    add_addr_table(conn, [
        ("dd:dd", addr, "ipv6", "ndp", "2026-11-05T09:30:00", "2026-11-05T12:00:00"),
    ])
    linked = alerts.relink_recent(conn, window_hours=24, now_iso="2026-11-05T12:00:00")
    assert linked == 1
    rows = conn.execute(
        "SELECT device_mac, occurrence_count, state, event_time FROM alerts ORDER BY alert_id"
    ).fetchall()
    # recent alert linked; occurrence/state/event_time untouched
    assert rows[0] == ("dd:dd", 7, "New", "2026-11-05T10:00:00")
    # old alert outside the bounded window: never rewritten
    assert rows[1][0] is None and rows[1][1] == 3 and rows[1][2] == "Reviewed"
    # idempotent: second pass changes nothing
    assert alerts.relink_recent(conn, window_hours=24, now_iso="2026-11-05T12:00:00") == 0


def test_link_device_ambiguous_ip_reuse_stays_unlinked(tmp_path):
    # Review #4: DHCP reuse leaves an offline device and the current device both
    # claiming one IP. Linking to the first match would mislink to the stale
    # device; on ambiguity we keep device_mac NULL instead of guessing.
    conn = make_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('old:dev','10.0.0.9')")
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('new:dev','10.0.0.9')")
    conn.commit()
    assert alerts.link_device(conn, "10.0.0.9", "8.8.8.8") is None
    # a uniquely-owned address still links
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('solo','10.0.0.5')")
    conn.commit()
    assert alerts.link_device(conn, "10.0.0.5", "8.8.8.8") == "solo"


# --------------------------------------------------------------------------- #
# Deduplication
# --------------------------------------------------------------------------- #
def test_dedup_merge_within_window_then_new_outside(tmp_path):
    conn = make_conn(tmp_path)
    a = alerts.parse_alert_event(json.loads(eve_alert(sid=7, ts="2026-11-02T10:00:00+0300")))
    b = alerts.parse_alert_event(json.loads(eve_alert(sid=7, ts="2026-11-02T10:02:00+0300")))
    c = alerts.parse_alert_event(json.loads(eve_alert(sid=7, ts="2026-11-02T10:10:00+0300")))
    with conn:
        alerts.upsert_alert(conn, a, "dev1", 300)
        alerts.upsert_alert(conn, b, "dev1", 300)  # +2 min -> merge
    row = conn.execute("SELECT occurrence_count, event_time, last_event_time FROM alerts").fetchone()
    assert row == (2, "2026-11-02T10:00:00", "2026-11-02T10:02:00")
    with conn:
        alerts.upsert_alert(conn, c, "dev1", 300)  # +8 min from last -> new row
    assert count(conn) == 2


def test_dedup_null_device_grouped_by_rule_and_ips(tmp_path):
    conn = make_conn(tmp_path)
    # same rule, no device, but different unknown hosts -> must NOT merge
    h1 = alerts.parse_alert_event(json.loads(eve_alert(sid=9, src="203.0.113.1", dst="198.51.100.1")))
    h2 = alerts.parse_alert_event(json.loads(eve_alert(sid=9, src="203.0.113.2", dst="198.51.100.1")))
    h1b = alerts.parse_alert_event(json.loads(
        eve_alert(sid=9, src="203.0.113.1", dst="198.51.100.1", ts="2026-11-02T10:01:00+0300")))
    with conn:
        alerts.upsert_alert(conn, h1, None, 300)
        alerts.upsert_alert(conn, h2, None, 300)   # different src -> separate alert
        alerts.upsert_alert(conn, h1b, None, 300)  # same rule+src+dst -> merge into h1
    assert count(conn) == 2
    assert count(conn, "occurrence_count=2") == 1


# --------------------------------------------------------------------------- #
# Resume safety
# --------------------------------------------------------------------------- #
def test_process_file_resume_no_double_ingest(tmp_path):
    conn = make_conn(tmp_path)
    eve = tmp_path / "eve.json"
    write(eve, eve_alert(sid=1), eve_alert(sid=2))
    alerts.process_file(conn, str(eve), 300)
    assert count(conn) == 2
    alerts.process_file(conn, str(eve), 300)  # no new bytes
    assert count(conn) == 2
    # append one more complete line
    with open(eve, "a") as f:
        f.write(eve_alert(sid=3))
    alerts.process_file(conn, str(eve), 300)
    assert count(conn) == 3


def test_resume_across_restart_same_db(tmp_path):
    conn = make_conn(tmp_path)
    eve = tmp_path / "eve.json"
    write(eve, eve_alert(sid=1), eve_alert(sid=2))
    alerts.process_file(conn, str(eve), 300)
    conn.close()
    # "restart": brand-new connection to the same DB file
    conn2 = sqlite3.connect(tmp_path / "test.db")
    alerts.process_file(conn2, str(eve), 300)  # must not re-ingest
    assert count(conn2) == 2


def test_partial_trailing_line_waits(tmp_path):
    conn = make_conn(tmp_path)
    eve = tmp_path / "eve.json"
    full = eve_alert(sid=1)
    eve.write_text(full + '{"event_type":"alert","timestamp":"2026-11-02T10:00:00+0300","alert":{"sig')
    alerts.process_file(conn, str(eve), 300)
    assert count(conn) == 1  # only the complete line
    # complete the partial line
    with open(eve, "a") as f:
        f.write('nature":"X","signature_id":2,"severity":2}}\n')
    alerts.process_file(conn, str(eve), 300)
    assert count(conn) == 2


def test_truncation_logs_gap_and_does_not_reingest(tmp_path, caplog):
    # Regression for the live defect: offset>size must NOT re-read from 0 (that
    # re-ingested events and duplicated alerts). It logs a gap and resumes at EOF.
    conn = make_conn(tmp_path)
    eve = tmp_path / "eve.json"
    write(eve, eve_alert(sid=1), eve_alert(sid=2))
    alerts.process_file(conn, str(eve), 300)
    assert count(conn) == 2
    before_ids = {r[0] for r in conn.execute("SELECT alert_id FROM alerts")}
    # shrink in place (same inode) below the stored offset, with fresh content
    with open(eve, "w") as f:
        f.write(eve_alert(sid=3))
    with caplog.at_level("WARNING"):
        alerts.process_file(conn, str(eve), 300)
    assert any("TRUNCATION/GAP" in r.message for r in caplog.records)
    # no re-ingest, no duplicate rows; offset clamped to EOF
    assert count(conn) == 2
    assert {r[0] for r in conn.execute("SELECT alert_id FROM alerts")} == before_ids
    st = os.stat(eve)
    off = conn.execute("SELECT offset FROM alert_ingest_state WHERE st_ino=?",
                       (st.st_ino,)).fetchone()[0]
    assert off == st.st_size
    # resume-forward still works: a later appended event is ingested (the gap
    # content, sid 3, is intentionally not recovered)
    with open(eve, "a") as f:
        f.write(eve_alert(sid=4))
    alerts.process_file(conn, str(eve), 300)
    assert count(conn) == 3
    assert 3 not in {r[0] for r in conn.execute("SELECT rule_id FROM alerts")}  # sid 3 skipped


def test_bad_encoding_line_is_skipped_not_fatal(tmp_path):
    # Regression for the live crash-loop: json.loads(bytes) raises
    # UnicodeDecodeError (not JSONDecodeError) on malformed bytes; it must be
    # skipped, not stall the daemon, and the offset must advance past it.
    conn = make_conn(tmp_path)
    eve = tmp_path / "eve.json"
    with open(eve, "wb") as f:
        f.write(eve_alert(sid=1).encode())
        f.write(b"\xff\xff\xff\xff\n")          # invalid UTF-8 -> UnicodeDecodeError
        f.write(eve_alert(sid=2).encode())
    alerts.process_file(conn, str(eve), 300)     # must not raise
    assert count(conn) == 2                      # both valid alerts ingested
    st = os.stat(eve)
    off = conn.execute("SELECT offset FROM alert_ingest_state WHERE st_ino=?",
                       (st.st_ino,)).fetchone()[0]
    assert off == st.st_size                     # advanced past the bad line (no stall)


# --------------------------------------------------------------------------- #
# Rotation: multi-file recovery + reaper
# --------------------------------------------------------------------------- #
def test_multi_rotation_restart_recovery(tmp_path):
    conn = make_conn(tmp_path)
    eve = tmp_path / "eve.json"
    # two rotated files present at startup + the live file (as if rotations
    # happened while the ingester was stopped)
    write(tmp_path / "eve.json-20261102-100000", eve_alert(sid=1), eve_alert(sid=2))
    write(tmp_path / "eve.json-20261102-100500", eve_alert(sid=3), eve_alert(sid=4))
    write(eve, eve_alert(sid=5))
    alerts.run_once(conn, str(eve), 300)
    sids = [r[0] for r in conn.execute("SELECT rule_id FROM alerts ORDER BY alert_id")]
    assert sids == [1, 2, 3, 4, 5]          # every event once, in order
    alerts.run_once(conn, str(eve), 300)    # second pass: nothing new
    assert count(conn) == 5


def test_reaper_preserves_unread_and_deletes_consumed(tmp_path):
    conn = make_conn(tmp_path)
    eve = tmp_path / "eve.json"
    r_consumed = write(tmp_path / "eve.json-20261102-100000", eve_alert(sid=1))
    r_unread = write(tmp_path / "eve.json-20261102-100500", eve_alert(sid=2))
    write(eve, eve_alert(sid=3))
    # Mark only the first rotated file consumed; leave the second untracked/unread.
    st = os.stat(r_consumed)
    with conn:
        conn.execute(
            "INSERT INTO alert_ingest_state(st_dev,st_ino,path,offset,consumed) "
            "VALUES (?,?,?,?,1)", (st.st_dev, st.st_ino, str(r_consumed), st.st_size))
    alerts.reap(conn, str(eve), keep=0, grace=0)
    assert not r_consumed.exists()   # consumed -> deleted
    assert r_unread.exists()         # NOT consumed -> preserved (retention guarantee)
    assert eve.exists()              # live file never reaped


def test_reaper_keeps_recent_consumed(tmp_path):
    conn = make_conn(tmp_path)
    eve = tmp_path / "eve.json"
    files = []
    for ts in ("100000", "100500", "101000"):
        p = write(tmp_path / f"eve.json-20261102-{ts}", eve_alert(sid=1))
        st = os.stat(p)
        with conn:
            conn.execute(
                "INSERT INTO alert_ingest_state(st_dev,st_ino,path,offset,consumed) "
                "VALUES (?,?,?,?,1)", (st.st_dev, st.st_ino, str(p), st.st_size))
        files.append(p)
    alerts.reap(conn, str(eve), keep=2, grace=0)
    assert not files[0].exists()     # oldest consumed deleted
    assert files[1].exists() and files[2].exists()  # two most recent kept


def test_missing_eve_file_tolerated(tmp_path):
    conn = make_conn(tmp_path)
    # right after rotation eve.json may briefly not exist
    assert alerts.process_file(conn, str(tmp_path / "eve.json"), 300) is None


# --------------------------------------------------------------------------- #
# Review #2: a rotated file that grows AFTER being marked consumed must not be
# deleted (the writer kept appending past the rename); its consumed flag is
# revoked so the tail is drained on the next cycle.
# --------------------------------------------------------------------------- #
def test_reaper_revokes_consumed_when_file_grows(tmp_path):
    conn = make_conn(tmp_path)
    eve = tmp_path / "eve.json"
    rot = write(tmp_path / "eve.json-20261102-090000", eve_alert(sid=10))
    dev, ino, new_off, size = alerts.process_file(conn, str(rot), 300)
    alerts.mark_consumed(conn, dev, ino, size)
    # writer appends after we considered it fully read
    with open(rot, "a") as f:
        f.write(eve_alert(sid=99))
    alerts.reap(conn, str(eve), keep=0, grace=0)     # keep=0 would normally delete it
    assert rot.exists()                               # grown file preserved
    consumed = conn.execute(
        "SELECT consumed FROM alert_ingest_state WHERE st_dev=? AND st_ino=?",
        (dev, ino)).fetchone()[0]
    assert consumed == 0                              # flag revoked
    alerts.run_once(conn, str(eve), 300)              # next cycle drains the tail
    sids = sorted(r[0] for r in conn.execute("SELECT rule_id FROM alerts"))
    assert sids == [10, 99]                           # appended event not lost


def test_reaper_does_not_delete_file_still_open_by_a_writer(tmp_path):
    # Review #2 (concurrent writer): while any process still holds the rotated
    # file open (as Suricata does until it honours the reopen signal), it must
    # NOT be reaped even though size==offset and grace has passed. Checking the
    # size twice is not enough; the open-handle check is the real guarantee.
    conn = make_conn(tmp_path)
    eve = tmp_path / "eve.json"
    rot = write(tmp_path / "eve.json-20261102-070000", eve_alert(sid=12))
    dev, ino, new_off, size = alerts.process_file(conn, str(rot), 300)
    alerts.mark_consumed(conn, dev, ino, size)
    holder = open(rot, "a")                            # writer still has it open
    try:
        alerts.reap(conn, str(eve), keep=0, grace=0)
        assert rot.exists()                            # not deleted while open
    finally:
        holder.close()
    alerts.reap(conn, str(eve), keep=0, grace=0)
    assert not rot.exists()                            # reaped once closed


def test_reaper_holds_until_quiescent(tmp_path):
    # A fully-read rotated file is held until it has been unmodified for `grace`
    # seconds (writer finished), then reaped.
    conn = make_conn(tmp_path)
    eve = tmp_path / "eve.json"
    rot = write(tmp_path / "eve.json-20261102-060000", eve_alert(sid=13))
    dev, ino, new_off, size = alerts.process_file(conn, str(rot), 300)
    alerts.mark_consumed(conn, dev, ino, size)
    alerts.reap(conn, str(eve), keep=0, grace=30)      # just written -> held
    assert rot.exists()
    # backdate mtime past the grace window -> now quiescent
    old = os.stat(rot).st_mtime - 120
    os.utime(rot, (old, old))
    alerts.reap(conn, str(eve), keep=0, grace=30)
    assert not rot.exists()


# --------------------------------------------------------------------------- #
# Review #5: valid JSON but a non-object record (null/list/scalar, or an `alert`
# that is not an object) must be skipped, not crash the cycle; the offset still
# advances so later valid alerts are not stalled.
# --------------------------------------------------------------------------- #
def test_structurally_invalid_records_skipped_not_fatal(tmp_path):
    conn = make_conn(tmp_path)
    eve = tmp_path / "eve.json"
    write(
        eve,
        "null\n", "[1,2,3]\n", "123\n",
        '{"event_type":"alert","timestamp":"2026-11-02T10:00:00+0300","alert":"x"}\n',
        eve_alert(sig="GOOD", sid=42),
    )
    alerts.process_file(conn, str(eve), 300)          # must not raise
    sids = [r[0] for r in conn.execute("SELECT rule_id FROM alerts")]
    assert sids == [42]                               # only the well-formed alert
    st = os.stat(eve)
    off = conn.execute("SELECT offset FROM alert_ingest_state WHERE st_ino=?",
                       (st.st_ino,)).fetchone()[0]
    assert off == st.st_size                          # advanced past every line (no stall)


def test_merge_keeps_chronological_first_last_out_of_order(tmp_path):
    # An older event arriving after a newer one (within the window) must widen
    # the span: event_time = earliest, last_event_time = latest.
    conn = make_conn(tmp_path)
    later = alerts.parse_alert_event(json.loads(eve_alert(sid=5, ts="2026-11-02T10:02:00+0300")))
    older = alerts.parse_alert_event(json.loads(eve_alert(sid=5, ts="2026-11-02T10:00:00+0300")))
    with conn:
        alerts.upsert_alert(conn, later, "dev1", 300)
        alerts.upsert_alert(conn, older, "dev1", 300)
    row = conn.execute("SELECT occurrence_count, event_time, last_event_time FROM alerts").fetchone()
    assert row == (2, "2026-11-02T10:00:00", "2026-11-02T10:02:00")


# --------------------------------------------------------------------------- #
# MAC attribution for ADDRESS-LESS events (eve-log ethernet: yes)
# --------------------------------------------------------------------------- #
GW_IP = "192.168.100.1"


def _mac_conn(tmp_path):
    conn = make_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('e6:42:65:03:0d:8f','192.168.100.238')")
    conn.execute(f"INSERT INTO devices(mac,last_ipv4) VALUES('fc:1b:d1:30:cb:6c','{GW_IP}')")  # gateway
    conn.commit()
    return conn


def test_parse_alert_event_extracts_ether():
    o = json.loads(eve_alert(sig="SURICATA IPv6 truncated packet", sid=2200013, sev=3))
    o.pop("src_ip", None); o.pop("dest_ip", None)
    o["ether"] = {"src_mac": "E6:42:65:03:0D:8F", "dest_mac": "FC:1B:D1:30:CB:6C"}
    a = alerts.parse_alert_event(o)
    assert a["ether_src"] == "e6:42:65:03:0d:8f"   # lowercased
    assert a["ether_dst"] == "fc:1b:d1:30:cb:6c"
    assert a["src_ip"] is None and a["dst_ip"] is None


def test_mac_link_both_directions(tmp_path):
    conn = _mac_conn(tmp_path)
    # outbound: device -> gateway
    assert alerts.link_device_by_mac(
        conn, "e6:42:65:03:0d:8f", "fc:1b:d1:30:cb:6c", gateway_ips={GW_IP}) == "e6:42:65:03:0d:8f"
    # inbound: gateway -> device
    assert alerts.link_device_by_mac(
        conn, "fc:1b:d1:30:cb:6c", "e6:42:65:03:0d:8f", gateway_ips={GW_IP}) == "e6:42:65:03:0d:8f"


def test_mac_link_gateway_and_multicast_excluded(tmp_path):
    conn = _mac_conn(tmp_path)
    # gateway -> multicast: no candidate at all
    assert alerts.link_device_by_mac(
        conn, "fc:1b:d1:30:cb:6c", "33:33:00:00:00:01", gateway_ips={GW_IP}) is None
    # broadcast source is never a candidate
    assert alerts.link_device_by_mac(
        conn, "ff:ff:ff:ff:ff:ff", "e6:42:65:03:0d:8f", gateway_ips={GW_IP}) == "e6:42:65:03:0d:8f"


def test_mac_link_unknown_device_stays_null(tmp_path):
    conn = _mac_conn(tmp_path)
    assert alerts.link_device_by_mac(
        conn, "aa:aa:aa:aa:aa:01", "fc:1b:d1:30:cb:6c", gateway_ips={GW_IP}) is None


def test_mac_link_two_devices_is_ambiguous(tmp_path):
    conn = _mac_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('8a:64:ec:43:21:f3','192.168.100.239')")
    conn.commit()
    assert alerts.link_device_by_mac(
        conn, "e6:42:65:03:0d:8f", "8a:64:ec:43:21:f3", gateway_ips={GW_IP}) is None


def test_mac_link_appliance_interfaces_excluded(tmp_path, monkeypatch):
    conn = _mac_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('9c:69:d3:4b:c7:f7','192.168.100.236')")
    conn.commit()
    monkeypatch.setattr(alerts, "_LOCAL_MACS", {"9c:69:d3:4b:c7:f7"})
    assert alerts.link_device_by_mac(
        conn, "9c:69:d3:4b:c7:f7", "e6:42:65:03:0d:8f", gateway_ips={GW_IP}) == "e6:42:65:03:0d:8f"
    assert alerts.link_device_by_mac(
        conn, "9c:69:d3:4b:c7:f7", "fc:1b:d1:30:cb:6c", gateway_ips={GW_IP}) is None


def test_mac_never_overrides_ip_linking(tmp_path, monkeypatch):
    # An event WITH IP addresses whose IP ownership is conflicted must stay
    # NULL even when the frame MAC names a known device.
    conn = _mac_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('old:dev','10.0.0.9')")
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('new:dev','10.0.0.9')")
    conn.commit()
    monkeypatch.setattr(alerts, "_GATEWAY_IPS", {GW_IP})
    eve = tmp_path / "eve.json"
    o = json.loads(eve_alert(sid=7777, src="10.0.0.9", dst="8.8.8.8"))
    o["ether"] = {"src_mac": "e6:42:65:03:0d:8f", "dest_mac": "fc:1b:d1:30:cb:6c"}
    write(eve, json.dumps(o) + "\n")
    alerts.process_file(conn, str(eve), 300)
    row = conn.execute("SELECT device_mac FROM alerts WHERE rule_id=7777").fetchone()
    assert row == (None,)  # IP conflict not bypassed by the MAC


def test_mac_linked_ingest_creates_new_row_and_preserves_old_null_row(tmp_path, monkeypatch):
    # End-to-end: an address-less event with ether links to the device at
    # insert time, merges with its own kind, and never touches the historical
    # NULL-keyed row of the same rule.
    conn = _mac_conn(tmp_path)
    monkeypatch.setattr(alerts, "_GATEWAY_IPS", {GW_IP})
    with conn:
        conn.execute(
            "INSERT INTO alerts (device_mac, alert_type, title, rule_id, event_time, "
            "severity, state, occurrence_count, last_event_time) "
            "VALUES (NULL,'Threat','SURICATA IPv6 truncated packet',2200013,"
            "'2026-11-05T00:56:28','Medium','New',64,'2026-11-05T03:08:11')")
    eve = tmp_path / "eve.json"
    def no_addr_event(ts):
        o = json.loads(eve_alert(sig="SURICATA IPv6 truncated packet", sid=2200013, sev=3, ts=ts))
        o.pop("src_ip", None); o.pop("dest_ip", None)
        o["ether"] = {"src_mac": "e6:42:65:03:0d:8f", "dest_mac": "fc:1b:d1:30:cb:6c"}
        return json.dumps(o) + "\n"
    write(eve, no_addr_event("2026-11-05T04:00:00+0300"),
               no_addr_event("2026-11-05T04:01:00+0300"))
    alerts.process_file(conn, str(eve), 300)
    rows = conn.execute(
        "SELECT device_mac, occurrence_count FROM alerts WHERE rule_id=2200013 "
        "ORDER BY alert_id").fetchall()
    assert rows[0] == (None, 64)                       # old NULL row untouched
    assert rows[1] == ("e6:42:65:03:0d:8f", 2)         # new linked row, merged
