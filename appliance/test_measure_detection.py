"""Tests for the detection-evaluation matcher (EVALUATION.md §2–3)."""
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "tools"))
import measure_detection as md


def ev(ts, sid=100, src="192.168.1.195", dst="8.8.8.8", etype="alert"):
    return {"event_type": etype, "timestamp": ts,
            "src_ip": src, "dest_ip": dst,
            "alert": {"signature_id": sid, "signature": f"SIG {sid}"}}


def test_event_matches_window_and_addresses():
    addrs = {"192.168.1.195"}
    start, stop = "2026-11-06T12:00:00", "2026-11-06T12:20:00"
    assert md.event_matches(ev("2026-11-06T12:10:00+0300"), start, stop, addrs)
    # address on either side counts
    assert md.event_matches(ev("2026-11-06T12:10:00", src="1.1.1.1", dst="192.168.1.195"),
                            start, stop, addrs)
    # outside the window -> no
    assert not md.event_matches(ev("2026-11-06T12:21:00"), start, stop, addrs)
    assert not md.event_matches(ev("2026-11-06T11:59:59"), start, stop, addrs)
    # co-occurring but unrelated addresses -> does NOT count
    assert not md.event_matches(ev("2026-11-06T12:10:00", src="10.9.9.9", dst="1.1.1.1"),
                                start, stop, addrs)
    # non-alert events never count
    assert not md.event_matches(ev("2026-11-06T12:10:00", etype="stats"), start, stop, addrs)


def test_measure_counts_per_sid(tmp_path):
    p = tmp_path / "eve.json"
    lines = [ev("2026-11-06T12:01:00", sid=2024001),
             ev("2026-11-06T12:02:00", sid=2024001),
             ev("2026-11-06T12:03:00", sid=2010935),
             ev("2026-11-06T12:30:00", sid=2024001),            # outside window
             ev("2026-11-06T12:04:00", sid=999, src="5.5.5.5", dst="6.6.6.6")]  # unrelated
    p.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    counts, names, matched = md.measure([str(p)], "2026-11-06T12:00:00",
                                        "2026-11-06T12:20:00", {"192.168.1.195"})
    assert counts == {2024001: 2, 2010935: 1}
    assert names[2024001] == "SIG 2024001"
    assert len(matched) == 3


def test_suricata_comm_matcher():
    """Regression for the clean-run pid=null: the kernel reports Suricata's
    comm as 'Suricata-Main', which the old matcher ('suricata' only) missed."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "tools"))
    import resource_sampler as rs
    assert rs._is_suricata_comm("Suricata-Main")
    assert rs._is_suricata_comm("suricata")
    assert not rs._is_suricata_comm("suricata-update")
    assert not rs._is_suricata_comm("python3")
