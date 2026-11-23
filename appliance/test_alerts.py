"""Unit tests for the Suricata eve.json -> SQLite Threat Alert ingester (PBI-14).

Offline and deterministic: eve events are synthesised as JSON lines (no Suricata
binary needed), which also lets us control file identity/rotation/offsets to test
resume safety, multi-rotation recovery, and the reaper precisely.
"""
import ipaddress
import json
import os
import sqlite3

import pytest

import alerts


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def _no_host_excluded_ips(monkeypatch):
    # Never read the test host's real interface/gateway addresses: tests that
    # need exclusions set the cache themselves.
    monkeypatch.setitem(alerts._excluded_ip_cache, "ips", set())
    monkeypatch.setitem(alerts._excluded_ip_cache, "known", True)
    monkeypatch.setitem(alerts._excluded_ip_cache, "ts", 9e18)


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
    (1, "High"), (2, "Medium"), (3, "Low"),
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
        eve_alert(sig="ET SCAN", sid=42, sev=1, src="10.0.0.5", dst="198.51.100.8", sp=1234, dp=53)))
    assert full == {
        "title": "ET SCAN", "category": None, "rule_id": 42, "severity": "High",
        "priority": 1, "event_time": "2026-11-02T10:00:00",
        "src_ip": "10.0.0.5", "dst_ip": "198.51.100.8", "src_port": 1234, "dst_port": 53,
        "ether_src": None, "ether_dst": None,
    }
    # decoder-event alert: no addresses/ports
    decoder = alerts.parse_alert_event(json.loads(eve_alert(sig="SURICATA IPv6", sid=2200013, sev=3)))
    assert decoder["src_ip"] is None and decoder["dst_ip"] is None
    assert decoder["src_port"] is None and decoder["severity"] == "Low"
    assert decoder["priority"] == 3
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
    assert alerts.link_device(conn, "10.0.0.5", "198.51.100.8") == "aa:aa"   # src only
    assert alerts.link_device(conn, "198.51.100.8", "10.0.0.5") == "aa:aa"   # dst only
    assert alerts.link_device(conn, "10.0.0.5", "2001:db8::6") == "aa:aa"  # both -> source
    assert alerts.link_device(conn, "198.51.100.9", "198.51.100.11") is None       # neither
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
    assert alerts.link_device(conn, "10.0.0.5", "198.51.100.8", "2026-11-05T10:00:00") == "aa:aa"
    assert alerts.link_device(conn, "198.51.100.9", None, "2026-11-05T10:00:00") is None


def test_link_device_multi_address_ipv4_and_rotating_ipv6(tmp_path):
    # One device with an IPv4 and TWO global IPv6 addresses (privacy rotation):
    # the evidence set links both, even though the devices columns only hold the
    # newest address. Addresses are stored exploded lowercase (eve.json form).
    conn = make_conn(tmp_path)
    conn.execute(
        "INSERT INTO devices(mac,last_ipv4,last_ipv6_global) "
        "VALUES('dd:dd','192.168.100.50','2001:0db8:0000:0000:0000:0000:0000:0b0b')")
    old6 = "2001:0db8:0000:0000:0000:0000:0000:0a0a"
    new6 = "2001:0db8:0000:0000:0000:0000:0000:0b0b"
    add_addr_table(conn, [
        ("dd:dd", "192.168.100.50", "ipv4", "arp", "2026-11-01T00:00:00", "2026-11-05T12:00:00"),
        ("dd:dd", old6, "ipv6", "ndp", "2026-11-01T00:00:00", "2026-11-03T00:00:00"),
        ("dd:dd", new6, "ipv6", "ndp", "2026-11-04T00:00:00", "2026-11-05T12:00:00"),
    ])
    # rotated-out address still links for an event inside ITS window
    assert alerts.link_device(conn, old6, "198.51.100.8", "2026-11-02T10:00:00") == "dd:dd"
    # current address links
    assert alerts.link_device(conn, "2001:db8:f00d::1", new6, "2026-11-05T10:00:00") == "dd:dd"
    # IPv4 links via the table too
    assert alerts.link_device(conn, "192.168.100.50", "198.51.100.8", "2026-11-05T10:00:00") == "dd:dd"
    # an event long after the old address's evidence window stays unlinked
    assert alerts.link_device(conn, old6, "198.51.100.8", "2026-11-05T10:00:00") is None


def test_link_device_evidence_window_boundaries(tmp_path):
    # Window = [first_seen - 2h, last_seen + 24h]; both bounds tested both sides.
    conn = make_conn(tmp_path)
    addr = "2001:0db8:0000:0000:0000:0000:0000:0c0c"
    add_addr_table(conn, [
        ("ee:ee", addr, "ipv6", "ndp", "2026-11-04T10:00:00", "2026-11-04T12:00:00"),
    ])
    link = lambda t: alerts.link_device(conn, "2001:db8:f00d::1", addr, t)
    assert link("2026-11-04T08:01:00") == "ee:ee"   # first - 1h59m: inside pre-slack
    assert link("2026-11-04T07:59:00") is None      # first - 2h01m: replayed old event
    assert link("2026-11-05T11:59:00") == "ee:ee"   # last + 23h59m: inside grace
    assert link("2026-11-05T12:01:00") is None      # last + 24h01m: expired


def test_columns_cannot_bypass_an_expired_evidence_window(tmp_path):
    # A rotated-out address can linger in devices.last_ipv6_global. When the
    # evidence table KNOWS the address but its ownership window has expired for
    # the event time, the stale column entry must not link the alert anyway.
    conn = make_conn(tmp_path)
    stale = "2001:0db8:0000:0000:0000:0000:0000:0f0f"
    conn.execute(
        "INSERT INTO devices(mac,last_ipv6_global) VALUES('dd:dd', ?)", (stale,))
    conn.commit()
    add_addr_table(conn, [
        ("dd:dd", stale, "ipv6", "ndp", "2026-11-01T00:00:00", "2026-11-02T00:00:00"),
    ])
    # inside the evidence window: links
    assert alerts.link_device(conn, "2001:db8:f00d::1", stale, "2026-11-01T12:00:00") == "dd:dd"
    # days after last evidence: the column alone must NOT bypass the window
    assert alerts.link_device(conn, "2001:db8:f00d::1", stale, "2026-11-05T12:00:00") is None


def test_columns_still_link_addresses_without_any_evidence(tmp_path):
    # The evidence table exists but has no rows for this address (pre-evidence
    # data): the legacy column match remains the fallback.
    conn = make_conn(tmp_path)
    conn.execute(
        "INSERT INTO devices(mac,last_ipv4) VALUES('ee:ff','192.168.100.80')")
    conn.commit()
    add_addr_table(conn, [
        ("other", "2001:0db8:0000:0000:0000:0000:0000:1111", "ipv6", "ndp",
         "2026-11-01T00:00:00", "2026-11-05T00:00:00"),
    ])
    assert alerts.link_device(conn, "192.168.100.80", "198.51.100.8", "2026-11-05T10:00:00") == "ee:ff"


def test_link_device_ownership_conflict_stays_unlinked(tmp_path):
    # Two MACs with overlapping evidence for one address -> never guess.
    conn = make_conn(tmp_path)
    addr = "2001:0db8:0000:0000:0000:0000:0000:0d0d"
    add_addr_table(conn, [
        ("aa:aa", addr, "ipv6", "ndp", "2026-11-04T00:00:00", "2026-11-05T00:00:00"),
        ("bb:bb", addr, "ipv6", "span", "2026-11-04T00:00:00", "2026-11-05T00:00:00"),
    ])
    assert alerts.link_device(conn, "2001:db8:f00d::1", addr, "2026-11-04T12:00:00") is None


def test_link_device_normalizes_column_address_forms(tmp_path):
    # eve.json writes IPv6 zero-padded exploded; the inventory column holds the
    # kernel's compressed form. The same address must match regardless of form.
    # (A ULA address: the column fallback only serves LAN-scoped addresses.)
    conn = make_conn(tmp_path)
    conn.execute(
        "INSERT INTO devices(mac,last_ipv6_global) VALUES('cc:cc','fd00:dea6:2200::6bc7:cf3:1d4c')")
    conn.execute(
        "INSERT INTO devices(mac,last_ipv6_global) VALUES('dd:dd','2001:db8:1::6bc7:cf3:1d4c')")
    conn.commit()
    exploded = "fd00:dea6:2200:0000:0000:6bc7:0cf3:1d4c"
    assert alerts.link_device(conn, "2001:db8:ffff::1", exploded, "2026-11-05T10:00:00") == "cc:cc"
    # A global IPv6 is never linked from the columns alone (needs evidence).
    assert alerts.link_device(conn, "2001:db8:ffff::1", "2001:db8:1:0:0:6bc7:cf3:1d4c",
                              "2026-11-05T10:00:00") is None


def test_relink_recent_repairs_discovery_lag_without_touching_counts(tmp_path):
    conn = make_conn(tmp_path)
    addr = "2001:0db8:0000:0000:0000:0000:0000:0e0e"
    # Two unlinked alerts on that address: one recent, one old (outside window).
    with conn:
        conn.execute(
            "INSERT INTO alerts (device_mac, alert_type, title, rule_id, event_time, "
            "src_ip, dst_ip, severity, state, occurrence_count, last_event_time) "
            "VALUES (NULL,'Threat','ET X',1,?, '2001:db8:f00d::1', ?, 'Medium','New',7,?)",
            ("2026-11-05T10:00:00", addr, "2026-11-05T10:00:00"))
        conn.execute(
            "INSERT INTO alerts (device_mac, alert_type, title, rule_id, event_time, "
            "src_ip, dst_ip, severity, state, occurrence_count, last_event_time) "
            "VALUES (NULL,'Threat','ET X',1,?, '2001:db8:f00d::1', ?, 'Medium','Resolved',3,?)",
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
    assert rows[1][0] is None and rows[1][1] == 3 and rows[1][2] == "Resolved"
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
    assert alerts.link_device(conn, "10.0.0.9", "198.51.100.8") is None
    # a uniquely-owned address still links
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('solo','10.0.0.5')")
    conn.commit()
    assert alerts.link_device(conn, "10.0.0.5", "198.51.100.8") == "solo"


def _set_excluded_ips(monkeypatch, *ips):
    monkeypatch.setitem(
        alerts._excluded_ip_cache, "ips", {alerts.ipaddress.ip_address(i) for i in ips})


def test_link_device_appliance_self_ip_is_never_a_link_target(tmp_path, monkeypatch):
    # 2026-11-10 incident: DHCP gave the appliance 192.168.8.102, which an
    # offline iPhone still holds in its stale last_ipv4. An alert .102 -> .104
    # linked to the iPhone (source wins); it must link the .104 device.
    conn = make_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,ip,last_ipv4) "
                 "VALUES('02:5a:02:00:00:02','fe80::5a:2ff:fe00:2','192.168.8.102')")
    conn.execute("INSERT INTO devices(mac,ip,last_ipv4) "
                 "VALUES('dc:97:ba:00:00:0c','192.168.8.104','192.168.8.104')")
    conn.execute("INSERT INTO devices(mac,ip,last_ipv4) "
                 "VALUES('02:5a:04:00:00:04','192.168.8.104','192.168.8.104')")
    conn.commit()
    add_addr_table(conn, [
        ("02:5a:04:00:00:04", "192.168.8.104", "ipv4", "arp",
         "2026-11-09T08:00:00", "2026-11-10T21:00:00"),
    ])
    t = "2026-11-10T20:30:00"
    # without the exclusion this is the mislink observed on the device
    assert alerts.link_device(conn, "192.168.8.102", "192.168.8.104", t) == "02:5a:02:00:00:02"
    _set_excluded_ips(monkeypatch, "192.168.8.102", "192.168.8.255", "192.168.8.1")
    assert alerts.link_device(conn, "192.168.8.102", "192.168.8.104", t) == "02:5a:04:00:00:04"
    # and in the reverse direction
    assert alerts.link_device(conn, "192.168.8.104", "192.168.8.102", t) == "02:5a:04:00:00:04"


def test_link_device_gateway_multicast_broadcast_sides_stay_unlinked(tmp_path, monkeypatch):
    # Even when an inventory row claims the address, a gateway, multicast,
    # broadcast or unspecified side never links; the other side still does.
    conn = make_conn(tmp_path)
    for mac, ip in [("gw:gw", "192.168.8.1"), ("mc:4", "224.0.0.251"),
                    ("bc:lim", "255.255.255.255"), ("bc:net", "192.168.8.255"),
                    ("mc:6", "ff02::1"), ("un:sp", "0.0.0.0")]:
        conn.execute("INSERT INTO devices(mac,ip) VALUES(?,?)", (mac, ip))
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('aa:aa','192.168.8.50')")
    conn.commit()
    _set_excluded_ips(monkeypatch, "192.168.8.102", "192.168.8.255", "192.168.8.1")
    t = "2026-11-10T20:30:00"
    assert alerts.link_device(conn, "192.168.8.1", "198.51.100.8", t) is None        # gateway
    assert alerts.link_device(conn, "198.51.100.8", "224.0.0.251", t) is None        # v4 multicast
    assert alerts.link_device(conn, "198.51.100.8", "255.255.255.255", t) is None    # limited bcast
    assert alerts.link_device(conn, "198.51.100.8", "192.168.8.255", t) is None      # subnet bcast
    assert alerts.link_device(conn, "2001:db8:f00d::1", "ff02::1", t) is None       # v6 multicast
    assert alerts.link_device(conn, "0.0.0.0", "198.51.100.8", t) is None            # unspecified
    # the excluded side is skipped, the other side resolved as usual
    assert alerts.link_device(conn, "192.168.8.1", "192.168.8.50", t) == "aa:aa"


IP_ADDR = (
    "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"
    "2: eth0    inet 192.168.8.102/24 brd 192.168.8.255 scope global dynamic eth0\\       "
    "valid_lft 85000sec preferred_lft 85000sec\n"
    "2: eth0    inet6 fe80::dea6:32ff:fe01:0203/64 scope link \\       "
    "valid_lft forever preferred_lft forever\n"
)


def test_parse_interface_addrs():
    ip = alerts.ipaddress.ip_address
    assert alerts.parse_interface_addrs(IP_ADDR) == {
        ip("127.0.0.1"), ip("192.168.8.102"), ip("192.168.8.255"),
        ip("fe80::dea6:32ff:fe01:203"),
    }
    assert alerts.parse_interface_addrs("") == set()


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


def test_resolved_alert_is_terminal_new_event_makes_independent_alert(tmp_path):
    """PBI-22 criterion 7: a matching event AFTER an alert is Resolved must NOT
    reopen or inflate it — it starts a fresh alert with a new id and state New."""
    conn = make_conn(tmp_path)
    a = alerts.parse_alert_event(json.loads(eve_alert(sid=7, ts="2026-11-02T10:00:00+0300")))
    # a recurrence one minute later — well within the 300s dedup window
    b = alerts.parse_alert_event(json.loads(eve_alert(sid=7, ts="2026-11-02T10:01:00+0300")))
    with conn:
        alerts.upsert_alert(conn, a, "dev1", 300)
    first_id = conn.execute("SELECT alert_id FROM alerts").fetchone()[0]
    # user resolves it (terminal)
    with conn:
        conn.execute("UPDATE alerts SET state='Resolved' WHERE alert_id=?", (first_id,))
    with conn:
        result = alerts.upsert_alert(conn, b, "dev1", 300)
    assert result == "inserted"                       # NOT merged into the resolved one
    assert count(conn) == 2
    # the resolved alert is untouched: still Resolved, occurrence stays 1
    old = conn.execute(
        "SELECT state, occurrence_count FROM alerts WHERE alert_id=?", (first_id,)).fetchone()
    assert old == ("Resolved", 1)
    # the new alert is independent: new id, state New, occurrence 1
    new = conn.execute(
        "SELECT alert_id, state, occurrence_count FROM alerts WHERE alert_id != ?",
        (first_id,)).fetchone()
    assert new[0] != first_id and new[1] == "New" and new[2] == 1
    # a further recurrence now merges into the NEW open alert (dedup still works)
    c = alerts.parse_alert_event(json.loads(eve_alert(sid=7, ts="2026-11-02T10:02:00+0300")))
    with conn:
        assert alerts.upsert_alert(conn, c, "dev1", 300) == "merged"
    assert count(conn) == 2
    assert conn.execute(
        "SELECT occurrence_count FROM alerts WHERE alert_id=?", (new[0],)).fetchone()[0] == 2


def test_resolved_newest_match_wins_over_older_open_in_window(tmp_path):
    """PBI-22 criterion 7, edge case: when the MOST RECENT matching alert is
    Resolved and an OLDER matching alert is still open AND inside the dedup
    window, a new event must start a fresh independent alert (new id, state
    New) — it must NOT re-attach to the older open one. The newest matching
    alert's state decides; Resolved closes the stream."""
    conn = make_conn(tmp_path)
    older_open = alerts.parse_alert_event(
        json.loads(eve_alert(sid=7, ts="2026-11-02T10:00:00+0300")))
    with conn:
        alerts.upsert_alert(conn, older_open, "dev1", 300)
    older_id = conn.execute("SELECT alert_id FROM alerts").fetchone()[0]
    rule_id = conn.execute("SELECT rule_id FROM alerts WHERE alert_id=?", (older_id,)).fetchone()[0]
    # A NEWER, already-Resolved alert for the same rule+device (last event 10:02,
    # after the older-open's 10:00). This is the state the live DB can hold.
    with conn:
        conn.execute(
            "INSERT INTO alerts (device_mac, alert_type, title, rule_id, event_time, "
            "severity, state, occurrence_count, last_event_time) "
            "VALUES ('dev1','Threat','t',?, '2026-11-02T10:02:00','Medium','Resolved',5,"
            "'2026-11-02T10:02:00')",
            (rule_id,))
    resolved_id = conn.execute(
        "SELECT alert_id FROM alerts WHERE state='Resolved'").fetchone()[0]

    # New event at 10:03 — within 300s of the OLDER-OPEN alert (10:00), and later
    # than the resolved one (10:02). Newest match is the Resolved alert.
    new_evt = alerts.parse_alert_event(
        json.loads(eve_alert(sid=7, ts="2026-11-02T10:03:00+0300")))
    with conn:
        result = alerts.upsert_alert(conn, new_evt, "dev1", 300)

    assert result == "inserted"            # NOT merged into the older open alert
    assert count(conn) == 3                # older-open, resolved, and the fresh one
    # older-open is untouched (occurrence still 1, still New)
    assert conn.execute(
        "SELECT state, occurrence_count FROM alerts WHERE alert_id=?",
        (older_id,)).fetchone() == ("New", 1)
    # the fresh alert is independent and open
    fresh = conn.execute(
        "SELECT alert_id, state, occurrence_count FROM alerts "
        "WHERE alert_id NOT IN (?,?)", (older_id, resolved_id)).fetchone()
    assert fresh[0] not in (older_id, resolved_id) and fresh[1] == "New" and fresh[2] == 1


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


def _evt(ts, sid=5):
    return alerts.parse_alert_event(json.loads(eve_alert(sid=sid, ts=ts + "+0300")))


def _spans(conn):
    return conn.execute(
        "SELECT event_time, last_event_time, occurrence_count, state FROM alerts "
        "ORDER BY event_time").fetchall()


def test_out_of_order_event_merges_into_older_alert_window(tmp_path):
    # A-27 (IoT-23 3-1): an event more than a window older than the NEWEST alert
    # still merges into the older alert whose window covers it.
    conn = make_conn(tmp_path)
    with conn:
        alerts.upsert_alert(conn, _evt("2026-11-02T10:00:00"), "dev1", 300)
        alerts.upsert_alert(conn, _evt("2026-11-02T10:20:00"), "dev1", 300)  # new alert
        # 18 min older than the newest; 2 min after the older alert
        assert alerts.upsert_alert(conn, _evt("2026-11-02T10:02:00"), "dev1", 300) == "merged"
    assert _spans(conn) == [
        ("2026-11-02T10:00:00", "2026-11-02T10:02:00", 2, "New"),
        ("2026-11-02T10:20:00", "2026-11-02T10:20:00", 1, "New"),
    ]


def test_out_of_order_event_picks_the_closest_alert(tmp_path):
    conn = make_conn(tmp_path)
    with conn:
        alerts.upsert_alert(conn, _evt("2026-11-02T10:00:00"), "dev1", 300)
        alerts.upsert_alert(conn, _evt("2026-11-02T10:08:00"), "dev1", 300)
        # covered by both windows (10:00+5m and 10:08-5m); closer to 10:08
        alerts.upsert_alert(conn, _evt("2026-11-02T10:05:00"), "dev1", 300)
    assert _spans(conn) == [
        ("2026-11-02T10:00:00", "2026-11-02T10:00:00", 1, "New"),
        ("2026-11-02T10:05:00", "2026-11-02T10:08:00", 2, "New"),
    ]


def test_out_of_order_event_outside_every_window_creates_new_alert(tmp_path):
    conn = make_conn(tmp_path)
    with conn:
        alerts.upsert_alert(conn, _evt("2026-11-02T10:00:00"), "dev1", 300)
        alerts.upsert_alert(conn, _evt("2026-11-02T10:30:00"), "dev1", 300)
        # 10 min after the first alert and 20 min before the second
        assert alerts.upsert_alert(conn, _evt("2026-11-02T10:10:00"), "dev1", 300) == "inserted"
        # and one more than a window BEFORE the earliest alert
        assert alerts.upsert_alert(conn, _evt("2026-11-02T09:50:00"), "dev1", 300) == "inserted"
    assert [r[2] for r in _spans(conn)] == [1, 1, 1, 1]


def test_out_of_order_event_matching_only_a_resolved_alert_creates_new_alert(tmp_path):
    conn = make_conn(tmp_path)
    with conn:
        alerts.upsert_alert(conn, _evt("2026-11-02T10:00:00"), "dev1", 300)
        alerts.upsert_alert(conn, _evt("2026-11-02T10:04:00"), "dev1", 300)
        alerts.upsert_alert(conn, _evt("2026-11-02T10:30:00"), "dev1", 300)  # newest, open
        conn.execute("UPDATE alerts SET state='Resolved' WHERE event_time='2026-11-02T10:00:00'")
        # late event inside the Resolved alert's span only
        assert alerts.upsert_alert(conn, _evt("2026-11-02T10:02:00"), "dev1", 300) == "inserted"
    assert _spans(conn) == [
        ("2026-11-02T10:00:00", "2026-11-02T10:04:00", 2, "Resolved"),   # untouched
        ("2026-11-02T10:02:00", "2026-11-02T10:02:00", 1, "New"),
        ("2026-11-02T10:30:00", "2026-11-02T10:30:00", 1, "New"),
    ]


def test_older_event_moves_first_event_time_earlier(tmp_path):
    conn = make_conn(tmp_path)
    with conn:
        alerts.upsert_alert(conn, _evt("2026-11-02T10:10:00"), "dev1", 300)
        alerts.upsert_alert(conn, _evt("2026-11-02T10:12:00"), "dev1", 300)
        alerts.upsert_alert(conn, _evt("2026-11-02T10:30:00"), "dev1", 300)  # newest alert
        # 4 min before the first alert's start, 26 min before the newest
        assert alerts.upsert_alert(conn, _evt("2026-11-02T10:06:00"), "dev1", 300) == "merged"
    assert _spans(conn)[0] == ("2026-11-02T10:06:00", "2026-11-02T10:12:00", 3, "New")


def test_out_of_order_merge_for_unlinked_alerts_uses_rule_and_ips(tmp_path):
    conn = make_conn(tmp_path)

    def evt(ts, src):
        return alerts.parse_alert_event(json.loads(
            eve_alert(sid=9, src=src, dst="198.51.100.1", ts=ts + "+0300")))
    with conn:
        alerts.upsert_alert(conn, evt("2026-11-02T10:00:00", "203.0.113.1"), None, 300)
        alerts.upsert_alert(conn, evt("2026-11-02T10:20:00", "203.0.113.1"), None, 300)
        assert alerts.upsert_alert(
            conn, evt("2026-11-02T10:01:00", "203.0.113.1"), None, 300) == "merged"
        assert alerts.upsert_alert(
            conn, evt("2026-11-02T10:01:00", "203.0.113.2"), None, 300) == "inserted"
    assert count(conn) == 3


def test_merge_lookup_uses_an_index(tmp_path):
    conn = make_conn(tmp_path)
    for sql, args in (
        ("device_mac=? AND rule_id IS ?", ("dev1", 5)),
        ("device_mac IS NULL AND rule_id IS ? AND src_ip IS ? AND dst_ip IS ?", (5, "a", "b")),
    ):
        plan = " ".join(r[-1] for r in conn.execute(
            "EXPLAIN QUERY PLAN SELECT alert_id, event_time, last_event_time, state "
            f"FROM alerts WHERE alert_type='Threat' AND {sql} "
            "AND last_event_time >= ? AND event_time <= ?", args + ("x", "y")))
        assert "SEARCH alerts USING INDEX" in plan, plan


# --------------------------------------------------------------------------- #
# MAC attribution for ADDRESS-LESS events (eve-log ethernet: yes)
# --------------------------------------------------------------------------- #
GW_IP = "192.168.100.1"


def _mac_conn(tmp_path):
    conn = make_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('02:5a:01:00:00:01','192.168.100.238')")
    conn.execute(f"INSERT INTO devices(mac,last_ipv4) VALUES('fc:1b:d1:00:00:0b','{GW_IP}')")  # gateway
    conn.commit()
    return conn


def test_parse_alert_event_extracts_ether():
    o = json.loads(eve_alert(sig="SURICATA IPv6 truncated packet", sid=2200013, sev=3))
    o.pop("src_ip", None); o.pop("dest_ip", None)
    o["ether"] = {"src_mac": "02:5A:01:00:00:01", "dest_mac": "FC:1B:D1:00:00:0B"}
    a = alerts.parse_alert_event(o)
    assert a["ether_src"] == "02:5a:01:00:00:01"   # lowercased
    assert a["ether_dst"] == "fc:1b:d1:00:00:0b"
    assert a["src_ip"] is None and a["dst_ip"] is None


def test_mac_link_both_directions(tmp_path):
    conn = _mac_conn(tmp_path)
    # outbound: device -> gateway
    assert alerts.link_device_by_mac(
        conn, "02:5a:01:00:00:01", "fc:1b:d1:00:00:0b", gateway_macs={"fc:1b:d1:00:00:0b"}) == "02:5a:01:00:00:01"
    # inbound: gateway -> device
    assert alerts.link_device_by_mac(
        conn, "fc:1b:d1:00:00:0b", "02:5a:01:00:00:01", gateway_macs={"fc:1b:d1:00:00:0b"}) == "02:5a:01:00:00:01"


def test_mac_link_gateway_and_multicast_excluded(tmp_path):
    conn = _mac_conn(tmp_path)
    # gateway -> multicast: no candidate at all
    assert alerts.link_device_by_mac(
        conn, "fc:1b:d1:00:00:0b", "33:33:00:00:00:01", gateway_macs={"fc:1b:d1:00:00:0b"}) is None
    # broadcast source is never a candidate
    assert alerts.link_device_by_mac(
        conn, "ff:ff:ff:ff:ff:ff", "02:5a:01:00:00:01", gateway_macs={"fc:1b:d1:00:00:0b"}) == "02:5a:01:00:00:01"


def test_mac_link_unknown_device_stays_null(tmp_path):
    conn = _mac_conn(tmp_path)
    assert alerts.link_device_by_mac(
        conn, "aa:aa:aa:aa:aa:01", "fc:1b:d1:00:00:0b", gateway_macs={"fc:1b:d1:00:00:0b"}) is None


def test_mac_link_two_devices_is_ambiguous(tmp_path):
    conn = _mac_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('02:5a:03:00:00:03','192.168.100.239')")
    conn.commit()
    assert alerts.link_device_by_mac(
        conn, "02:5a:01:00:00:01", "02:5a:03:00:00:03", gateway_macs={"fc:1b:d1:00:00:0b"}) is None


def test_mac_link_appliance_interfaces_excluded(tmp_path, monkeypatch):
    conn = _mac_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('9c:69:d3:00:00:0d','192.168.100.236')")
    conn.commit()
    monkeypatch.setattr(alerts, "_LOCAL_MACS", {"9c:69:d3:00:00:0d"})
    assert alerts.link_device_by_mac(
        conn, "9c:69:d3:00:00:0d", "02:5a:01:00:00:01", gateway_macs={"fc:1b:d1:00:00:0b"}) == "02:5a:01:00:00:01"
    assert alerts.link_device_by_mac(
        conn, "9c:69:d3:00:00:0d", "fc:1b:d1:00:00:0b", gateway_macs={"fc:1b:d1:00:00:0b"}) is None


def test_mac_never_overrides_ip_linking(tmp_path, monkeypatch):
    # An event WITH IP addresses whose IP ownership is conflicted must stay
    # NULL even when the frame MAC names a known device.
    conn = _mac_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('old:dev','10.0.0.9')")
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('new:dev','10.0.0.9')")
    conn.commit()
    monkeypatch.setitem(alerts._gateway_cache, "macs", {"fc:1b:d1:00:00:0b"})
    monkeypatch.setitem(alerts._gateway_cache, "known", True)
    monkeypatch.setitem(alerts._gateway_cache, "ts", 9e18)
    eve = tmp_path / "eve.json"
    o = json.loads(eve_alert(sid=7777, src="10.0.0.9", dst="198.51.100.8"))
    o["ether"] = {"src_mac": "02:5a:01:00:00:01", "dest_mac": "fc:1b:d1:00:00:0b"}
    write(eve, json.dumps(o) + "\n")
    alerts.process_file(conn, str(eve), 300)
    row = conn.execute("SELECT device_mac FROM alerts WHERE rule_id=7777").fetchone()
    assert row == (None,)  # IP conflict not bypassed by the MAC


def test_mac_linked_ingest_creates_new_row_and_preserves_old_null_row(tmp_path, monkeypatch):
    # End-to-end: an address-less event with ether links to the device at
    # insert time, merges with its own kind, and never touches the historical
    # NULL-keyed row of the same rule.
    conn = _mac_conn(tmp_path)
    monkeypatch.setitem(alerts._gateway_cache, "macs", {"fc:1b:d1:00:00:0b"})
    monkeypatch.setitem(alerts._gateway_cache, "known", True)
    monkeypatch.setitem(alerts._gateway_cache, "ts", 9e18)
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
        o["ether"] = {"src_mac": "02:5a:01:00:00:01", "dest_mac": "fc:1b:d1:00:00:0b"}
        return json.dumps(o) + "\n"
    write(eve, no_addr_event("2026-11-05T04:00:00+0300"),
               no_addr_event("2026-11-05T04:01:00+0300"))
    alerts.process_file(conn, str(eve), 300)
    rows = conn.execute(
        "SELECT device_mac, occurrence_count FROM alerts WHERE rule_id=2200013 "
        "ORDER BY alert_id").fetchall()
    assert rows[0] == (None, 64)                       # old NULL row untouched
    assert rows[1] == ("02:5a:01:00:00:01", 2)         # new linked row, merged


# --------------------------------------------------------------------------- #
# Gateway-MAC resolution hardening
# --------------------------------------------------------------------------- #
ROUTE4 = "default via 192.168.100.1 dev eth0 proto dhcp src 192.168.100.236 metric 100\n"
ROUTE6 = "default via fe80::aabb:ccff:fedd:1 dev eth0 proto ra metric 100 pref medium\n"
NEIGH4 = ("192.168.100.1 dev eth0 lladdr fc:1b:d1:00:00:0b REACHABLE\n"
          "192.168.100.50 dev eth0 lladdr aa:aa:aa:aa:aa:50 STALE\n")
NEIGH6 = ("fe80::aabb:ccff:fedd:1 dev eth0 lladdr de:ad:be:ef:00:01 router REACHABLE\n"
          "2001:db8::9 dev eth0 lladdr aa:aa:aa:aa:aa:60 STALE\n")


def test_parse_default_routes_and_neighbor_mac():
    assert alerts.parse_default_routes(ROUTE4) == [("192.168.100.1", "eth0")]
    assert alerts.parse_default_routes(ROUTE6) == [("fe80::aabb:ccff:fedd:1", "eth0")]
    assert alerts.parse_neighbor_mac(NEIGH4, "192.168.100.1", "eth0") == "fc:1b:d1:00:00:0b"
    assert alerts.parse_neighbor_mac(NEIGH6, "fe80::aabb:ccff:fedd:1", "eth0") == "de:ad:be:ef:00:01"
    # unproven neighbor states are not gateway evidence
    assert alerts.parse_neighbor_mac(
        "192.168.100.1 dev eth0  FAILED\n", "192.168.100.1") is None


def _fake_ip_cmd(monkeypatch):
    def fake(args, text=True, timeout=5):
        a = " ".join(args)
        if a == "ip route show default":
            return ROUTE4
        if a == "ip -6 route show default":
            return ROUTE6
        if a == "ip neigh show":
            return NEIGH4
        if a == "ip -6 neigh show":
            return NEIGH6
        raise OSError(a)
    monkeypatch.setattr(alerts.subprocess, "check_output", fake)


def test_gateway_macs_resolved_without_inventory(tmp_path, monkeypatch):
    # The IPv4 gateway row is ABSENT from the inventory and the IPv6 gateway is
    # a different MAC entirely: both must come from the neighbor tables.
    conn = make_conn(tmp_path)  # no gateway rows at all
    _fake_ip_cmd(monkeypatch)
    macs = alerts._resolve_gateway_macs(conn)
    assert macs == {"fc:1b:d1:00:00:0b", "de:ad:be:ef:00:01"}


def test_ipv6_gateway_mac_excluded_from_linking(tmp_path, monkeypatch):
    # A frame from the IPv6 gateway's distinct MAC must not link to it even
    # though that MAC exists in the inventory as a device row.
    conn = make_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('de:ad:be:ef:00:01','192.168.100.254')")
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('02:5a:01:00:00:01','192.168.100.238')")
    conn.commit()
    _fake_ip_cmd(monkeypatch)
    monkeypatch.setitem(alerts._gateway_cache, "ts", 0.0)
    monkeypatch.setitem(alerts._gateway_cache, "known", False)
    # v6-gateway -> device: still links the device, never the v6 gateway
    assert alerts.link_device_by_mac(
        conn, "de:ad:be:ef:00:01", "02:5a:01:00:00:01") == "02:5a:01:00:00:01"
    # v6-gateway -> multicast: no candidate
    assert alerts.link_device_by_mac(conn, "de:ad:be:ef:00:01", "33:33:00:00:00:01") is None


def test_gateway_undetermined_suspends_mac_linking(tmp_path, monkeypatch):
    # Resolution fails entirely -> fail-safe: no MAC link at all, even for a
    # clear device frame (a lone candidate could BE the unknown router).
    conn = _mac_conn(tmp_path)
    monkeypatch.setattr(alerts, "_resolve_gateway_macs", lambda c: set())
    monkeypatch.setitem(alerts._gateway_cache, "macs", set())
    monkeypatch.setitem(alerts._gateway_cache, "known", False)
    monkeypatch.setitem(alerts._gateway_cache, "ts", 0.0)
    assert alerts.link_device_by_mac(conn, "02:5a:01:00:00:01", "33:33:00:00:00:01") is None


def test_gateway_cache_retries_failures_and_refreshes(tmp_path, monkeypatch):
    conn = make_conn(tmp_path)
    calls = {"n": 0}
    results = [set(), {"fc:1b:d1:00:00:0b"}]
    def fake_resolve(c):
        calls["n"] += 1
        return results[min(calls["n"] - 1, 1)]
    monkeypatch.setattr(alerts, "_resolve_gateway_macs", fake_resolve)
    monkeypatch.setitem(alerts._gateway_cache, "macs", set())
    monkeypatch.setitem(alerts._gateway_cache, "known", False)
    monkeypatch.setitem(alerts._gateway_cache, "ts", 0.0)
    t0 = 1_000_000.0
    macs, known = alerts.gateway_macs_now(conn, now=t0)
    assert (macs, known) == (set(), False)            # first attempt fails
    # failure is NOT cached for the long TTL: retried after the short interval
    macs, known = alerts.gateway_macs_now(conn, now=t0 + alerts.GATEWAY_RETRY_SECONDS + 1)
    assert (macs, known) == ({"fc:1b:d1:00:00:0b"}, True)
    # a success is reused within the refresh TTL (no third resolution call)
    alerts.gateway_macs_now(conn, now=t0 + alerts.GATEWAY_RETRY_SECONDS + 10)
    assert calls["n"] == 2


# --------------------------------------------------------------------------- #
# Classtype + device role (Threat Alert titles, Sprint 2)
# --------------------------------------------------------------------------- #
CLASSIFICATION_SAMPLE = """\
# comment line
config classification: not-suspicious,Not Suspicious Traffic,3
config classification: trojan-activity,A Network Trojan was detected, 1
config classification: network-scan,Detection of a Network Scan,3
  config classification:web-application-attack , Web Application Attack , 1
config classification: twin-a,Same Text,2
config classification: twin-b,Same Text,2
config classification: comma-desc,Desc, with a comma,2
config classification: broken-line-without-priority
"""


@pytest.fixture
def classification(tmp_path, monkeypatch):
    path = tmp_path / "classification.config"
    path.write_text(CLASSIFICATION_SAMPLE)
    monkeypatch.setattr(alerts, "CLASSIFICATION_PATH", str(path))
    monkeypatch.setitem(alerts._classification_cache, "path", None)
    monkeypatch.setattr(alerts, "_classification_warned", set())
    return path


def test_parse_classification_config():
    m = alerts.parse_classification_config(CLASSIFICATION_SAMPLE)
    assert m["A Network Trojan was detected"] == "trojan-activity"   # space before priority
    assert m["Web Application Attack"] == "web-application-attack"   # odd spacing
    assert m["Desc, with a comma"] == "comma-desc"
    assert m["Same Text"] is None                                    # ambiguous
    assert "broken-line-without-priority" not in m.values()
    assert len(m) == 6


def test_classtype_for_known_unknown_ambiguous_missing(classification, caplog):
    assert alerts.classtype_for("Detection of a Network Scan") == "network-scan"
    assert alerts.classtype_for(None) is None                # rule with no classtype
    assert alerts.classtype_for("Not In The File") is None
    assert alerts.classtype_for("Same Text") is None
    classification.unlink()
    with caplog.at_level("WARNING", logger="assas.alerts"):
        assert alerts.classtype_for("Detection of a Network Scan") is None
        assert alerts.classtype_for("Detection of a Network Scan") is None
    assert sum("unavailable" in r.getMessage() for r in caplog.records) == 1  # warned once


def test_classification_file_reloaded_when_changed(classification):
    assert alerts.classtype_for("Brand New Text") is None
    classification.write_text("config classification: fresh,Brand New Text,2\n")
    st = classification.stat()
    os.utime(classification, (st.st_atime, st.st_mtime + 10))
    assert alerts.classtype_for("Brand New Text") == "fresh"


def test_parse_alert_event_keeps_category():
    o = json.loads(eve_alert(sid=5))
    o["alert"]["category"] = " A Network Trojan was detected "
    assert alerts.parse_alert_event(o)["category"] == "A Network Trojan was detected"
    o["alert"]["category"] = ""
    assert alerts.parse_alert_event(o)["category"] is None


def test_link_device_with_role(tmp_path):
    conn = make_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('aa:aa','10.0.0.5')")
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('bb:bb','10.0.0.6')")
    conn.commit()
    role = alerts.link_device_with_role
    assert role(conn, "10.0.0.5", "198.51.100.8") == ("aa:aa", "source")
    assert role(conn, "198.51.100.8", "10.0.0.5") == ("aa:aa", "target")
    assert role(conn, "10.0.0.6", "10.0.0.5") == ("bb:bb", "source")   # both -> source
    assert role(conn, "198.51.100.9", "198.51.100.11") == (None, None)


def test_ingest_stores_classtype_category_and_role(tmp_path, classification):
    conn = make_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('aa:aa','10.0.0.5')")
    conn.commit()

    def evt(sid, src, dst, category=None, ts="2026-11-02T10:00:00+0300"):
        o = json.loads(eve_alert(sid=sid, src=src, dst=dst, ts=ts))
        if category:
            o["alert"]["category"] = category
        return alerts.parse_alert_event(o)

    with conn:
        alerts.ingest_alert(conn, evt(1, "10.0.0.5", "198.51.100.8", "A Network Trojan was detected"), 300)
        alerts.ingest_alert(conn, evt(2, "198.51.100.8", "10.0.0.5", "Detection of a Network Scan"), 300)
        alerts.ingest_alert(conn, evt(1000001, "10.0.0.5", "10.0.0.1"), 300)  # test rule: no classtype
        alerts.ingest_alert(conn, evt(4, "198.51.100.9", "198.51.100.11", "Not In The File"), 300)
        # Same rule + device within the window, now with the device as target:
        # merges; classtype/role stay as first stored.
        alerts.ingest_alert(conn, evt(1, "198.51.100.8", "10.0.0.5", "A Network Trojan was detected",
                                      ts="2026-11-02T10:01:00+0300"), 300)
    rows = conn.execute(
        "SELECT rule_id, device_mac, category, classtype, device_role, occurrence_count "
        "FROM alerts ORDER BY alert_id").fetchall()
    assert rows == [
        (1, "aa:aa", "A Network Trojan was detected", "trojan-activity", "source", 2),
        (2, "aa:aa", "Detection of a Network Scan", "network-scan", "target", 1),
        (1000001, "aa:aa", None, None, "source", 1),
        (4, None, "Not In The File", None, None, 1),
    ]


def test_mac_linked_alert_has_no_role(tmp_path, monkeypatch, classification):
    conn = _mac_conn(tmp_path)
    monkeypatch.setitem(alerts._gateway_cache, "macs", {"fc:1b:d1:00:00:0b"})
    monkeypatch.setitem(alerts._gateway_cache, "known", True)
    monkeypatch.setitem(alerts._gateway_cache, "ts", 9e18)
    o = json.loads(eve_alert(sig="SURICATA IPv6 truncated packet", sid=2200013, sev=3))
    o["ether"] = {"src_mac": "02:5a:01:00:00:01", "dest_mac": "fc:1b:d1:00:00:0b"}
    with conn:
        alerts.ingest_alert(conn, alerts.parse_alert_event(o), 300)
    row = conn.execute("SELECT device_mac, device_role FROM alerts").fetchone()
    assert row == ("02:5a:01:00:00:01", None)


def test_relink_sets_device_role(tmp_path):
    conn = make_conn(tmp_path)
    with conn:
        conn.execute(
            "INSERT INTO alerts (device_mac, alert_type, title, rule_id, event_time, "
            "src_ip, dst_ip, severity, state, occurrence_count, last_event_time) "
            "VALUES (NULL,'Threat','ET X',1,?,'198.51.100.8','10.0.0.5','Medium','New',1,?)",
            ("2026-11-05T10:00:00", "2026-11-05T10:00:00"))
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES('aa:aa','10.0.0.5')")
    conn.commit()
    assert alerts.relink_recent(conn, window_hours=24, now_iso="2026-11-05T12:00:00") == 1
    assert conn.execute("SELECT device_mac, device_role FROM alerts").fetchone() == ("aa:aa", "target")


def test_ensure_schema_migrates_old_table_and_keeps_rows(tmp_path):
    conn = sqlite3.connect(tmp_path / "old.db")
    old_ddl = alerts.ALERTS_DDL.replace(
        "last_event_time  TEXT NOT NULL,\n    category         TEXT,\n"
        "    classtype        TEXT,\n    device_role      TEXT,\n"
        "    priority         INTEGER\n",
        "last_event_time  TEXT NOT NULL\n")
    assert "classtype" not in old_ddl and "priority" not in old_ddl
    with conn:
        conn.execute(old_ddl)
        conn.execute(
            "INSERT INTO alerts (title, event_time, severity, last_event_time) "
            "VALUES ('ET OLD', '2026-11-01T10:00:00', 'Low', '2026-11-01T10:00:00')")
    alerts.ensure_schema(conn)
    alerts.ensure_schema(conn)  # idempotent
    cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
    assert {"category", "classtype", "device_role", "priority"} <= cols
    assert conn.execute(
        "SELECT title, category, classtype, device_role, priority FROM alerts").fetchall() == [
        ("ET OLD", None, None, None, None)]


def _pre_release1_db(path, rows):
    """An alerts table from before Release 1 (no priority column) with rows of
    (title, severity, state)."""
    conn = sqlite3.connect(path)
    old_ddl = alerts.ALERTS_DDL.replace(",\n    priority         INTEGER\n", "\n")
    assert "priority" not in old_ddl
    with conn:
        conn.execute(old_ddl)
        conn.executemany(
            "INSERT INTO alerts (title, event_time, severity, state, last_event_time) "
            "VALUES (?, '2026-11-01T10:00:00', ?, ?, '2026-11-01T10:00:00')", rows)
    return conn


def test_release1_conversion_maps_old_labels_and_reviewed_once(tmp_path):
    conn = _pre_release1_db(tmp_path / "old.db", [
        ("A", "Critical", "New"), ("B", "High", "Reviewed"),
        ("C", "Medium", "Resolved"), ("D", "Low", "New"), ("E", "Bogus", "New"),
    ])
    alerts.ensure_schema(conn)
    expected = [
        ("A", 1, "High", "New"), ("B", 2, "Medium", "New"),
        ("C", 3, "Low", "Resolved"), ("D", None, "Low", "New"), ("E", None, "Low", "New"),
    ]
    q = "SELECT title, priority, severity, state FROM alerts ORDER BY title"
    assert conn.execute(q).fetchall() == expected
    # Runs once: a second start must not shift High -> Medium again.
    assert alerts.migrate_release1(conn) is False
    alerts.ensure_schema(conn)
    assert conn.execute(q).fetchall() == expected


def test_fresh_table_is_never_converted(tmp_path):
    conn = sqlite3.connect(tmp_path / "new.db")
    alerts.ensure_schema(conn)
    with conn:
        conn.execute(
            "INSERT INTO alerts (title, event_time, severity, last_event_time, priority) "
            "VALUES ('ET NEW', '2026-11-20T10:00:00', 'High', '2026-11-20T10:00:00', 1)")
    alerts.ensure_schema(conn)
    assert conn.execute("SELECT severity, priority FROM alerts").fetchall() == [("High", 1)]


def test_release1_conversion_rolls_back_as_a_whole(tmp_path, monkeypatch):
    conn = _pre_release1_db(tmp_path / "old.db", [("A", "Critical", "Reviewed")])
    real_execute = conn.execute

    class FailingConn:
        def __getattr__(self, name):
            return getattr(conn, name)

        def execute(self, sql, *args):
            if sql.startswith("UPDATE alerts SET state"):
                raise sqlite3.OperationalError("disk I/O error")
            return real_execute(sql, *args)

    with pytest.raises(sqlite3.OperationalError):
        alerts.migrate_release1(FailingConn())
    # Nothing half-done: no column, old label and state intact, so it can rerun.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
    assert "priority" not in cols
    assert conn.execute("SELECT severity, state FROM alerts").fetchall() == [("Critical", "Reviewed")]
    assert alerts.migrate_release1(conn) is True
    assert conn.execute("SELECT severity, state FROM alerts").fetchall() == [("High", "New")]


def test_ingest_stores_priority_and_new_severity(tmp_path):
    conn = make_conn(tmp_path)
    with conn:
        for sid, sev in ((1000001, 1), (1000002, 2), (1000003, 3)):
            a = alerts.parse_alert_event(json.loads(eve_alert(sid=sid, sev=sev, src="198.51.100.9", dst="198.51.100.11")))
            alerts.ingest_alert(conn, a, 300)
    assert conn.execute(
        "SELECT rule_id, priority, severity FROM alerts ORDER BY rule_id").fetchall() == [
        (1000001, 1, "High"), (1000002, 2, "Medium"), (1000003, 3, "Low")]


# --------------------------------------------------------------------------- #
# Internet addresses never link an alert through the devices columns (bug: an
# alert from an internet server to a laptop was linked to the router, whose
# columns held internet servers' addresses). Documentation placeholders only:
# 203.0.113.0/24, 198.51.100.0/24 and 2001:db8:ffff::/48 are internet servers;
# 192.168.1.0/24 and 2001:db8:1::/64 are the LAN.
# --------------------------------------------------------------------------- #
ROUTER, LAPTOP = "02:00:00:00:00:01", "02:00:00:00:00:20"
SERVER_V4, SERVER_V6 = "203.0.113.10", "2001:db8:ffff::1"
LAPTOP_V4, LAPTOP_V6 = "192.168.1.20", "2001:db8:1::20"
EVENT = "2026-11-10T10:00:00"


def _router_and_laptop(tmp_path):
    """The live state: the router's columns hold internet servers' addresses;
    the laptop has ARP / NDP evidence for its own addresses."""
    conn = make_conn(tmp_path)
    conn.execute("INSERT INTO devices(mac, ip, last_ipv4, last_ipv6_global) VALUES (?,?,?,?)",
                 (ROUTER, SERVER_V4, SERVER_V4, SERVER_V6))
    conn.execute("INSERT INTO devices(mac, ip, last_ipv4, last_ipv6_global) VALUES (?,?,?,?)",
                 (LAPTOP, LAPTOP_V4, LAPTOP_V4, LAPTOP_V6))
    add_addr_table(conn, [
        (LAPTOP, LAPTOP_V4, "ipv4", "arp", "2026-11-01T10:00:00", "2026-11-20T10:00:00"),
        (LAPTOP, ipaddress.ip_address(LAPTOP_V6).exploded, "ipv6", "ndp",
         "2026-11-01T10:00:00", "2026-11-20T10:00:00"),
    ])
    return conn


def test_internet_source_links_the_lan_target_not_the_router(tmp_path):
    conn = _router_and_laptop(tmp_path)
    assert alerts.link_device_with_role(conn, SERVER_V4, LAPTOP_V4, EVENT) == (LAPTOP, "target")
    assert alerts.link_device_with_role(conn, SERVER_V6, LAPTOP_V6, EVENT) == (LAPTOP, "target")
    # Both sides internet: unlinked, never the router.
    assert alerts.link_device_with_role(conn, SERVER_V4, "198.51.100.7", EVENT) == (None, None)


def test_column_fallback_still_serves_lan_addresses_without_evidence(tmp_path):
    conn = make_conn(tmp_path)  # older discovery: no evidence table at all
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES (?,?)", (LAPTOP, LAPTOP_V4))
    conn.execute("INSERT INTO devices(mac,last_ipv4) VALUES (?,?)", (ROUTER, SERVER_V4))
    conn.commit()
    assert alerts.link_device_with_role(conn, LAPTOP_V4, SERVER_V4, EVENT) == (LAPTOP, "source")
    assert alerts.link_device_with_role(conn, SERVER_V4, None, EVENT) == (None, None)


def _insert(conn, mac, role, src, dst, count=5, state="New"):
    cur = conn.execute(
        "INSERT INTO alerts (device_mac, alert_type, title, rule_id, event_time, src_ip, "
        "dst_ip, severity, state, occurrence_count, last_event_time, device_role) "
        "VALUES (?, 'Threat', 'ET X', 1, ?, ?, ?, 'Medium', ?, ?, ?, ?)",
        (mac, EVENT, src, dst, state, count, EVENT, role))
    return cur.lastrowid


def _alert(conn, alert_id):
    return conn.execute(
        "SELECT device_mac, device_role, state, occurrence_count, event_time, "
        "last_event_time FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()


def test_relink_repairs_internet_links_once_and_touches_nothing_else(tmp_path):
    conn = _router_and_laptop(tmp_path)
    with conn:
        wrong = _insert(conn, ROUTER, "source", SERVER_V4, LAPTOP_V4)          # the bug
        wrong_v6 = _insert(conn, ROUTER, "source", SERVER_V6, LAPTOP_V6)
        no_owner = _insert(conn, ROUTER, "source", SERVER_V4, "198.51.100.7")  # -> unlinked
        legacy = _insert(conn, ROUTER, None, SERVER_V4, LAPTOP_V4)             # before roles
        lan_ok = _insert(conn, LAPTOP, "source", LAPTOP_V4, SERVER_V4)         # justified
        evidence_ok = _insert(conn, LAPTOP, "target", SERVER_V6, LAPTOP_V6)    # global + evidence
        by_mac = _insert(conn, LAPTOP, None, None, None)                       # MAC-linked
        resolved = _insert(conn, ROUTER, "source", SERVER_V4, LAPTOP_V4, state="Resolved")
        # A phone's read marker (API-owned table) must not be touched.
        conn.execute("CREATE TABLE alert_reads (session_id INTEGER, alert_id INTEGER, "
                     "read_count INTEGER, read_at TEXT)")
        conn.execute("INSERT INTO alert_reads VALUES (1, ?, 5, ?)", (wrong, EVENT))
    before = {i: _alert(conn, i) for i in (lan_ok, evidence_ok, by_mac)}

    assert alerts.relink_offlink_links(conn) == 5
    assert _alert(conn, wrong)[:2] == (LAPTOP, "target")
    assert _alert(conn, wrong_v6)[:2] == (LAPTOP, "target")
    assert _alert(conn, no_owner)[:2] == (None, None)
    assert _alert(conn, legacy)[:2] == (LAPTOP, "target")
    assert _alert(conn, resolved)[:2] == (LAPTOP, "target")
    # Only device_mac / device_role changed.
    assert _alert(conn, wrong)[2:] == ("New", 5, EVENT, EVENT)
    assert _alert(conn, resolved)[2] == "Resolved"
    assert conn.execute("SELECT session_id, alert_id, read_count FROM alert_reads").fetchall() == [
        (1, wrong, 5)]
    # Justified links and MAC-linked alerts are left alone.
    assert {i: _alert(conn, i) for i in before} == before

    # Runs once: a later run changes nothing, even if a bad link reappears.
    with conn:
        conn.execute("UPDATE alerts SET device_mac=?, device_role='source' WHERE alert_id=?",
                     (ROUTER, wrong))
    assert alerts.relink_offlink_links(conn) is None
    assert _alert(conn, wrong)[:2] == (ROUTER, "source")
    assert conn.execute("SELECT COUNT(*) FROM migrations WHERE name=?",
                        (alerts.RELINK_OFFLINK_LINKS,)).fetchone()[0] == 1


def test_relink_rolls_back_as_a_whole(tmp_path):
    conn = _router_and_laptop(tmp_path)
    with conn:
        wrong = _insert(conn, ROUTER, "source", SERVER_V4, LAPTOP_V4)
    real_execute = conn.execute

    class FailingConn:
        def __getattr__(self, name):
            return getattr(conn, name)

        def execute(self, sql, *args):
            if sql.startswith("INSERT INTO migrations"):
                raise sqlite3.OperationalError("disk I/O error")
            return real_execute(sql, *args)

    with pytest.raises(sqlite3.OperationalError):
        alerts.relink_offlink_links(FailingConn())
    assert _alert(conn, wrong)[:2] == (ROUTER, "source")  # nothing half-done
    assert alerts.relink_offlink_links(conn) == 1          # and it can run again
    assert _alert(conn, wrong)[:2] == (LAPTOP, "target")


def test_relink_on_a_fresh_database_just_records_its_marker(tmp_path):
    conn = make_conn(tmp_path)
    assert alerts.relink_offlink_links(conn) == 0
    assert alerts.relink_offlink_links(conn) is None
