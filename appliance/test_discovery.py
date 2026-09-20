import os
import socket
import sqlite3
import tempfile
import unittest

from scapy.layers.netbios import (
    NBNSHeader, NBNSRegistrationRequest, NBNSQueryRequest,
    NBNSNodeStatusRequest, NBNSNodeStatusResponse, NBNSNodeStatusResponseService,
)
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.all import Ether, IP, TCP, UDP

import discovery
from discovery import (
    type_from_vendor,
    type_from_dns_query,
    type_from_vendor_class,
    type_from_mdns_query,
    fingerprint_tcp_syn,
    extract_nbns_name,
    extract_nbns_nodestatus_name,
    extract_llmnr_name,
    is_locally_administered_mac,
    is_unclassified,
    display_vendor,
    display_device_type,
    vendor_from_model_in_hostname,
    vendor_from_domain_needle,
    merge_candidate,
    extract_mdns_metadata,
    DHCP_SIGNATURES,
    SCORES,
)


class NbnsLlmnrExtractionTests(unittest.TestCase):
    def test_unique_registration_workstation_suffix_extracted(self):
        pkt = NBNSHeader(OPCODE=5, RESPONSE=0) / NBNSRegistrationRequest(
            QUESTION_NAME="MYHOST", SUFFIX=0x4141, G=0
        )
        self.assertEqual(extract_nbns_name(pkt), "MYHOST")

    def test_unique_registration_file_server_suffix_extracted(self):
        pkt = NBNSHeader(OPCODE=5, RESPONSE=0) / NBNSRegistrationRequest(
            QUESTION_NAME="FILESRV", SUFFIX=0x4341, G=0
        )
        self.assertEqual(extract_nbns_name(pkt), "FILESRV")

    def test_group_registration_rejected(self):
        # WORKGROUP/domain-name registrations are group names, not a host's
        # own hostname.
        pkt = NBNSHeader(OPCODE=5, RESPONSE=0) / NBNSRegistrationRequest(
            QUESTION_NAME="WORKGROUP", SUFFIX=0x4141, G=1
        )
        self.assertIsNone(extract_nbns_name(pkt))

    def test_browser_election_suffix_rejected(self):
        pkt = NBNSHeader(OPCODE=5, RESPONSE=0) / NBNSRegistrationRequest(
            QUESTION_NAME="MYHOST", SUFFIX=0x424F, G=0
        )
        self.assertIsNone(extract_nbns_name(pkt))

    def test_plain_query_rejected(self):
        # A plain query's name may belong to a different host on the segment.
        pkt = NBNSHeader(OPCODE=0, RESPONSE=0) / NBNSQueryRequest(
            QUESTION_NAME="SOMEPEER", SUFFIX=0x4141
        )
        self.assertIsNone(extract_nbns_name(pkt))

    def test_llmnr_response_extracted(self):
        pkt = LLMNRResponse(qd=DNSQR(qname="myhost.local"))
        self.assertEqual(extract_llmnr_name(pkt), "myhost.local")

    def test_llmnr_query_rejected(self):
        # A query's qname may be about a different host on the segment.
        pkt = LLMNRQuery(qr=0, qd=DNSQR(qname="somepeer.local"))
        self.assertIsNone(extract_llmnr_name(pkt))


class RandomizedMacTests(unittest.TestCase):
    def test_locally_administered_bit_set(self):
        self.assertTrue(is_locally_administered_mac("02:11:22:33:44:55"))

    def test_real_oui_prefix_not_randomized(self):
        # Real Raspberry Pi Foundation OUI prefix.
        self.assertFalse(is_locally_administered_mac("dc:a6:32:11:22:33"))

    def test_python_bit_test_matches_sql_nibble_set(self):
        sql_nibbles = {"2", "3", "6", "7", "a", "A", "b", "B", "e", "E", "f", "F"}
        for high_nibble in "0123456789abcdef":
            for low_nibble in "0123456789abcdef":
                mac = f"{high_nibble}{low_nibble}:00:00:00:00:00"
                expected = low_nibble in sql_nibbles or low_nibble.upper() in sql_nibbles
                self.assertEqual(
                    is_locally_administered_mac(mac), expected,
                    f"mismatch for {mac}",
                )

    def test_display_vendor_randomized_no_inference(self):
        self.assertEqual(
            display_vendor("02:11:22:33:44:55", None),
            "Private MAC (randomized)",
        )

    def test_display_vendor_real_oui(self):
        self.assertEqual(display_vendor("dc:a6:32:11:22:33", "Raspberry Pi Foundation"), "Raspberry Pi Foundation")

    def test_display_vendor_no_vendor(self):
        self.assertEqual(display_vendor("dc:a6:32:11:22:33", None), "-")

    def test_display_vendor_inferred_takes_priority_over_randomized(self):
        # Regression: an inferred vendor is only ever stored for a
        # locally-administered MAC, so the inferred-check must run before
        # the randomized-MAC check, or "(inferred)" would be unreachable.
        self.assertEqual(
            display_vendor("02:11:22:33:44:55", "Samsung Electronics", "inferred: model"),
            "Samsung Electronics (inferred)",
        )

    def test_display_vendor_on_randomized_mac_is_inferred_even_without_source(self):
        # Item 3: any vendor on a locally-administered MAC is never OUI
        # ground-truth (get_vendor() returns None for randomized MACs), so
        # even a NULL-vendor_source value -- a legacy row stored before the
        # column existed, or a device self-report -- must read "(inferred)",
        # not as if it came from the OUI table.
        self.assertEqual(
            display_vendor("72:a3:36:be:90:06", "Apple Inc.", None),
            "Apple Inc. (inferred)",
        )

    def test_display_vendor_real_mac_null_source_shown_plainly(self):
        # A real (non-randomized) MAC with a NULL source is a genuine OUI
        # vendor and must NOT be relabelled inferred.
        self.assertEqual(
            display_vendor("28:39:5e:d7:44:0c", "Samsung Electronics", None),
            "Samsung Electronics",
        )


class BackfillMigrationTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)  # let init_db() create it fresh
        self._orig_db_path = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        discovery.init_db()

    def tearDown(self):
        discovery.DB_PATH = self._orig_db_path
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _insert(self, mac, vendor, vendor_source):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO devices (mac, vendor, vendor_source, first_seen, last_seen, status) "
            "VALUES (?, ?, ?, 'x', 'x', 'candidate')",
            (mac, vendor, vendor_source),
        )
        conn.commit()
        conn.close()

    def _vendor(self, mac):
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT vendor FROM devices WHERE mac=?", (mac,)).fetchone()
        conn.close()
        return row[0]

    def test_stale_fake_vendor_is_nulled(self):
        self._insert("02:11:22:33:44:55", "(Unknown: locally administered)", None)
        discovery.init_db()
        self.assertIsNone(self._vendor("02:11:22:33:44:55"))

    def test_randomised_wording_variant_is_nulled(self):
        self._insert("02:11:22:33:44:77", "(randomised address)", None)
        discovery.init_db()
        self.assertIsNone(self._vendor("02:11:22:33:44:77"))

    def test_dup_suffixed_variant_is_nulled(self):
        self._insert("02:11:22:33:44:88", "(Unknown: locally administered) (DUP: 41)", None)
        discovery.init_db()
        self.assertIsNone(self._vendor("02:11:22:33:44:88"))

    def test_genuine_self_reported_vendor_on_randomized_mac_survives(self):
        # Critical: a device can self-report a real manufacturer (e.g. a
        # UPnP "manufacturer=" field) while using a randomized MAC. The
        # locally-administered bit alone must not be treated as proof the
        # stored vendor is fake placeholder text.
        self._insert("62:84:4b:77:f4:e5", "Skyworth BJ", None)
        discovery.init_db()
        self.assertEqual(self._vendor("62:84:4b:77:f4:e5"), "Skyworth BJ")

    def test_inferred_vendor_survives_backfill(self):
        # Critical: item 6 stores real inferred vendors in this same column
        # for locally-administered MACs. The backfill must never wipe them.
        self._insert("02:11:22:33:44:66", "Apple Inc.", "inferred: model")
        discovery.init_db()
        self.assertEqual(self._vendor("02:11:22:33:44:66"), "Apple Inc.")

    def test_real_oui_vendor_untouched(self):
        self._insert("dc:a6:32:11:22:33", "Raspberry Pi Foundation", None)
        discovery.init_db()
        self.assertEqual(self._vendor("dc:a6:32:11:22:33"), "Raspberry Pi Foundation")


class MdnsProbeTests(unittest.TestCase):
    def test_disabled_probe_is_noop(self):
        orig = discovery.ENABLE_MDNS_PROBE
        discovery.ENABLE_MDNS_PROBE = False
        try:
            discovery.mdns_probed.discard("aa:bb:cc:dd:ee:ff")
            discovery.schedule_mdns_probe("aa:bb:cc:dd:ee:ff", "192.168.100.50")
            self.assertNotIn("aa:bb:cc:dd:ee:ff", discovery.mdns_probed)
        finally:
            discovery.ENABLE_MDNS_PROBE = orig

    def test_query_builder_question_names(self):
        pkt = discovery._mdns_query_packet(
            ["_services._dns-sd._udp.local", "_device-info._tcp.local"], "PTR"
        )
        qd = pkt.qd if isinstance(pkt.qd, list) else [pkt.qd]
        names = [q.qname.decode().rstrip(".") for q in qd]
        self.assertEqual(
            names, ["_services._dns-sd._udp.local", "_device-info._tcp.local"]
        )

    def test_reply_with_txt_needs_no_followup(self):
        pkt = DNS(qr=1, an=[
            DNSRR(rrname="_device-info._tcp.local", type="PTR",
                  rdata="Kitchen._device-info._tcp.local"),
            DNSRR(rrname="Kitchen._device-info._tcp.local", type="TXT",
                  rdata=[b"model=MacBookPro18,3"]),
        ])
        self.assertFalse(discovery._mdns_needs_followup_txt(pkt))
        self.assertEqual(extract_mdns_metadata(pkt)[0], "MacBookPro18,3")

    def test_reply_without_txt_needs_followup_and_yields_instance(self):
        pkt = DNS(qr=1, an=DNSRR(
            rrname="_device-info._tcp.local", type="PTR",
            rdata="Kitchen._device-info._tcp.local",
        ))
        self.assertTrue(discovery._mdns_needs_followup_txt(pkt))
        self.assertEqual(
            discovery._mdns_device_info_instance(pkt),
            "Kitchen._device-info._tcp.local",
        )

    def test_followup_txt_reply_parses_model(self):
        pkt = DNS(qr=1, an=DNSRR(
            rrname="Kitchen._device-info._tcp.local", type="TXT",
            rdata=[b"model=iPad13,1"],
        ))
        self.assertEqual(extract_mdns_metadata(pkt)[0], "iPad13,1")


class ProbeTriggerTests(unittest.TestCase):
    """update_device() must schedule probes for EXISTING unclassified devices,
    not only brand-new ones (the target unknowns are already in the DB)."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)
        self._orig_db_path = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        discovery.init_db()
        # Enable both probe gates but replace the workers with no-ops so no
        # real thread/sleep/network runs.
        self._orig_mdns_enable = discovery.ENABLE_MDNS_PROBE
        self._orig_active_enable = discovery.ENABLE_ACTIVE_PROBE
        self._orig_mdns_worker = discovery.mdns_probe_device
        self._orig_active_worker = discovery.probe_device_ports
        discovery.ENABLE_MDNS_PROBE = True
        discovery.ENABLE_ACTIVE_PROBE = True
        discovery.mdns_probe_device = lambda mac, ip: None
        discovery.probe_device_ports = lambda mac, ip: None
        discovery.mdns_probed.clear()
        discovery.active_probed.clear()

    def tearDown(self):
        discovery.ENABLE_MDNS_PROBE = self._orig_mdns_enable
        discovery.ENABLE_ACTIVE_PROBE = self._orig_active_enable
        discovery.mdns_probe_device = self._orig_mdns_worker
        discovery.probe_device_ports = self._orig_active_worker
        discovery.mdns_probed.clear()
        discovery.active_probed.clear()
        discovery.write_cache.clear()
        discovery.DB_PATH = self._orig_db_path
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _insert(self, mac, device_type):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO devices (mac, ip, device_type, first_seen, last_seen, status) "
            "VALUES (?, '192.168.100.50', ?, 'x', 'x', 'online')",
            (mac, device_type),
        )
        conn.commit()
        conn.close()

    def test_existing_unclassified_null_type_schedules_once(self):
        mac = "72:e4:6b:44:a6:f5"
        self._insert(mac, None)
        discovery.update_device(mac, ip="192.168.100.50", seen_on_span=True)
        self.assertIn(mac, discovery.mdns_probed)
        self.assertIn(mac, discovery.active_probed)
        # Seen again -> not re-scheduled (still just once in the set).
        discovery.update_device(mac, ip="192.168.100.50", seen_on_span=True)
        self.assertEqual(sum(1 for m in discovery.mdns_probed if m == mac), 1)

    def test_existing_generic_unknown_type_schedules(self):
        mac = "72:e4:6b:44:a6:00"
        self._insert(mac, "Generic / Unknown")
        discovery.update_device(mac, ip="192.168.100.50", seen_on_span=True)
        self.assertIn(mac, discovery.mdns_probed)

    def test_existing_classified_device_not_scheduled(self):
        mac = "72:e4:6b:44:a6:11"
        self._insert(mac, "Computer")
        discovery.update_device(mac, ip="192.168.100.50", seen_on_span=True)
        self.assertNotIn(mac, discovery.mdns_probed)
        self.assertNotIn(mac, discovery.active_probed)


class DisplayDeviceTypeTests(unittest.TestCase):
    def test_private_mac_no_evidence(self):
        self.assertEqual(
            display_device_type(None, "de:45:d6:62:b3:29", None, None, None),
            "Unknown (private MAC)",
        )

    def test_private_mac_generic_type_no_evidence(self):
        self.assertEqual(
            display_device_type("Generic / Unknown", "de:45:d6:62:b3:29", None, None, None),
            "Unknown (private MAC)",
        )

    def test_private_mac_with_hostname_stays_generic(self):
        # .234 in the live inventory: private MAC but hostname "LUJAIN".
        self.assertEqual(
            display_device_type(None, "26:3b:93:16:69:76", "LUJAIN", None, None),
            "Generic / Unknown",
        )

    def test_real_mac_unknown_stays_generic(self):
        self.assertEqual(
            display_device_type(None, "28:39:5e:d7:44:0c", None, None, None),
            "Generic / Unknown",
        )

    def test_classified_device_unchanged(self):
        self.assertEqual(
            display_device_type("Computer", "de:45:d6:62:b3:29", None, None, None),
            "Computer",
        )

    def test_label_fits_column(self):
        self.assertLessEqual(len("Unknown (private MAC)"), 22)


class RescoreStoredEvidenceTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)
        self._orig = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        discovery.init_db()

    def tearDown(self):
        discovery.DB_PATH = self._orig
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _insert(self, mac, **cols):
        keys = ["mac", "first_seen", "last_seen", "status"] + list(cols)
        vals = [mac, "x", "x", "online"] + list(cols.values())
        ph = ",".join("?" * len(keys))
        conn = sqlite3.connect(self.db_path)
        conn.execute(f"INSERT INTO devices ({','.join(keys)}) VALUES ({ph})", vals)
        conn.commit()
        conn.close()

    def _get(self, mac):
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT device_type, COALESCE(class_score,0), class_source "
            "FROM devices WHERE mac=?", (mac,)
        ).fetchone()
        conn.close()
        return row

    def test_windows_dhcp_signature_upgrades_unknown(self):
        self._insert("aa:00:00:00:00:01",
                     dhcp_signature="1,3,6,15,31,33,43,44,46,47,119,121,249,252,114")
        n = discovery.rescore_stored_evidence(verbose=False)
        self.assertEqual(self._get("aa:00:00:00:00:01")[0], "Computer")
        self.assertGreaterEqual(n, 1)

    def test_vendor_class_upgrades_unknown(self):
        self._insert("aa:00:00:00:00:02", vendor_class="android-dhcp-15")
        discovery.rescore_stored_evidence(verbose=False)
        dtype, score, source = self._get("aa:00:00:00:00:02")
        self.assertEqual(dtype, "Mobile (Android)")
        self.assertEqual(score, discovery.SCORES["dhcp_vendor"])
        self.assertIn("android-dhcp-", source)

    def test_no_downgrade_of_stronger_classification(self):
        # Strong existing type (gateway, 100) with only weak stored vendor
        # evidence must be left untouched.
        self._insert("aa:00:00:00:00:03", device_type="Router", class_score=100,
                     class_source="default gateway", vendor="Dell Inc.")
        discovery.rescore_stored_evidence(verbose=False)
        self.assertEqual(self._get("aa:00:00:00:00:03"), ("Router", 100, "default gateway"))

    def test_no_evidence_row_unchanged(self):
        # Mirrors the live randomized-MAC unknowns: nothing to match.
        self._insert("aa:00:00:00:00:04")
        n = discovery.rescore_stored_evidence(verbose=False)
        self.assertIsNone(self._get("aa:00:00:00:00:04")[0])

    def test_unmatched_hostname_stays_unknown(self):
        # .234-like: hostname present but matches no hint, no other evidence.
        self._insert("aa:00:00:00:00:05", hostname="LUJAIN")
        discovery.rescore_stored_evidence(verbose=False)
        self.assertIsNone(self._get("aa:00:00:00:00:05")[0])

    def test_equal_score_is_not_a_change(self):
        # Stored Computer at exactly the DHCP-fingerprint score must not be
        # rewritten (strictly-greater required).
        self._insert("aa:00:00:00:00:06", device_type="Computer",
                     class_score=discovery.SCORES["dhcp"], class_source="DHCP fingerprint",
                     dhcp_signature="1,3,6,15,31,33,43,44,46,47,119,121,249,252,114")
        n = discovery.rescore_stored_evidence(verbose=False)
        self.assertEqual(n, 0)


def _nbns_nodestatus_reply(entries, rr_name="HOST"):
    """Build a parsed NBSTAT node-status response from (name, suffix, flags)."""
    svcs = [
        NBNSNodeStatusResponseService(
            NETBIOS_NAME=name.ljust(15)[:15], SUFFIX=suffix, NAME_FLAGS=flags
        )
        for name, suffix, flags in entries
    ]
    pkt = NBNSHeader(RESPONSE=1, ANCOUNT=1) / NBNSNodeStatusResponse(
        RR_NAME=rr_name, NUM_NAMES=len(svcs), NODE_NAME=svcs
    )
    return NBNSHeader(bytes(pkt))  # round-trip so fields dissect like the wire


class NbnsProbeTests(unittest.TestCase):
    def test_disabled_probe_is_noop(self):
        orig = discovery.ENABLE_NBNS_PROBE
        discovery.ENABLE_NBNS_PROBE = False
        try:
            discovery.nbns_probed.discard("aa:bb:cc:dd:ee:ff")
            discovery.schedule_nbns_probe("aa:bb:cc:dd:ee:ff", "192.168.100.50")
            self.assertNotIn("aa:bb:cc:dd:ee:ff", discovery.nbns_probed)
        finally:
            discovery.ENABLE_NBNS_PROBE = orig

    def test_request_is_nbstat_named_star(self):
        req = NBNSHeader(bytes(discovery._nbns_nodestatus_request_packet()))
        nsr = req[NBNSNodeStatusRequest]
        self.assertEqual(int(nsr.QUESTION_TYPE), 0x21)  # NBSTAT
        self.assertEqual(bytes(nsr.QUESTION_NAME)[:1], b"*")

    def test_unique_name_picked_over_group(self):
        # 0x84 = group flag (0x80) set; 0x04 = active/unique.
        reply = _nbns_nodestatus_reply([
            ("WORKGROUP", 0x00, 0x84),   # group -> ignored
            ("MYPC", 0x00, 0x04),        # unique workstation -> chosen
        ])
        self.assertEqual(extract_nbns_nodestatus_name(reply), "MYPC")

    def test_file_server_suffix_accepted(self):
        reply = _nbns_nodestatus_reply([("FILESRV", 0x20, 0x04)])
        self.assertEqual(extract_nbns_nodestatus_name(reply), "FILESRV")

    def test_special_suffixes_rejected(self):
        for suffix in (0x1D, 0x1E, 0x1B, 0x03):
            reply = _nbns_nodestatus_reply([("MYPC", suffix, 0x04)])
            self.assertIsNone(
                extract_nbns_nodestatus_name(reply),
                f"suffix {hex(suffix)} should be rejected",
            )

    def test_group_only_reply_yields_no_name(self):
        reply = _nbns_nodestatus_reply([
            ("WORKGROUP", 0x00, 0x84),
            ("MYDOMAIN", 0x1C, 0x84),
        ])
        self.assertIsNone(extract_nbns_nodestatus_name(reply))

    def test_reply_from_wrong_source_ip_ignored(self):
        # Monkeypatch the socket so recvfrom returns a valid NBSTAT reply but
        # from a DIFFERENT source IP than the one probed -> must be ignored.
        reply_bytes = bytes(_nbns_nodestatus_reply([("MYPC", 0x00, 0x04)]))

        class FakeSock:
            def __init__(self, *a, **k):
                self._sent = False

            def settimeout(self, t):
                pass

            def sendto(self, data, addr):
                pass

            def recvfrom(self, n):
                if not self._sent:
                    self._sent = True
                    return reply_bytes, ("10.0.0.99", 137)  # wrong source
                raise socket.timeout()

            def close(self):
                pass

        orig = socket.socket
        socket.socket = lambda *a, **k: FakeSock()
        try:
            self.assertIsNone(discovery._nbns_nodestatus_query("192.168.100.50", timeout=0.2))
        finally:
            socket.socket = orig


class NbnsProbeTriggerTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)
        self._orig_db = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        discovery.init_db()
        self._orig_enable = discovery.ENABLE_NBNS_PROBE
        self._orig_worker = discovery.nbns_probe_device
        discovery.ENABLE_NBNS_PROBE = True
        discovery.nbns_probe_device = lambda mac, ip: None
        discovery.nbns_probed.clear()

    def tearDown(self):
        discovery.ENABLE_NBNS_PROBE = self._orig_enable
        discovery.nbns_probe_device = self._orig_worker
        discovery.nbns_probed.clear()
        discovery.write_cache.clear()
        discovery.DB_PATH = self._orig_db
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _insert(self, mac, device_type):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO devices (mac, ip, device_type, first_seen, last_seen, status) "
            "VALUES (?, '192.168.100.50', ?, 'x', 'x', 'online')",
            (mac, device_type),
        )
        conn.commit()
        conn.close()

    def test_existing_unclassified_schedules_once(self):
        mac = "72:e4:6b:44:a6:f5"
        self._insert(mac, None)
        discovery.update_device(mac, ip="192.168.100.50", seen_on_span=True)
        self.assertIn(mac, discovery.nbns_probed)
        discovery.update_device(mac, ip="192.168.100.50", seen_on_span=True)
        self.assertEqual(sum(1 for m in discovery.nbns_probed if m == mac), 1)

    def test_existing_classified_not_scheduled(self):
        mac = "72:e4:6b:44:a6:11"
        self._insert(mac, "Computer")
        discovery.update_device(mac, ip="192.168.100.50", seen_on_span=True)
        self.assertNotIn(mac, discovery.nbns_probed)


class SynFingerprintLocalOnlyTests(unittest.TestCase):
    """handle() must fingerprint only pure SYNs from the local subnet."""

    APPLE_OPTS = [("MSS", 1460), ("NOP", None), ("WScale", 6), ("NOP", None),
                  ("NOP", None), ("Timestamp", (1, 0)), ("SAckOK", b""), ("EOL", None)]

    def setUp(self):
        import ipaddress
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)
        self._orig_db = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        discovery.init_db()
        self._orig_nets = list(discovery.monitored_networks)
        discovery.monitored_networks[:] = [ipaddress.ip_network("192.168.100.0/24")]
        discovery.syn_fp_last.clear()
        discovery.write_cache.clear()

    def tearDown(self):
        discovery.monitored_networks[:] = self._orig_nets
        discovery.syn_fp_last.clear()
        discovery.write_cache.clear()
        discovery.DB_PATH = self._orig_db
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _row(self, mac):
        conn = sqlite3.connect(self.db_path)
        r = conn.execute(
            "SELECT device_type FROM devices WHERE mac=?", (mac.lower(),)
        ).fetchone()
        conn.close()
        return r

    def _pkt(self, mac, src_ip):
        return Ether(bytes(
            Ether(src=mac) / IP(src=src_ip, ttl=64) /
            TCP(flags="S", window=65535, options=self.APPLE_OPTS)
        ))

    def test_foreign_source_ip_ignored(self):
        mac = "02:aa:aa:aa:aa:01"
        discovery.handle(self._pkt(mac, "8.8.8.8"))
        self.assertIsNone(self._row(mac))

    def test_local_source_ip_fingerprinted(self):
        mac = "02:aa:aa:aa:aa:02"
        discovery.handle(self._pkt(mac, "192.168.100.77"))
        row = self._row(mac)
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "Apple Device")


class MdnsQueryVendorInferenceTests(unittest.TestCase):
    """Full handle() -> update_device() path: a _companion-link query infers the
    Apple vendor only when the source MAC has no real OUI vendor."""

    def setUp(self):
        import ipaddress
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)
        self._orig_db = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        discovery.init_db()
        self._orig_nets = list(discovery.monitored_networks)
        discovery.monitored_networks[:] = [ipaddress.ip_network("192.168.100.0/24")]
        # Real OUI so get_vendor() resolves the Dell, exactly as the running
        # daemon would after load_oui() (seed just the prefix under test).
        self._orig_oui = dict(discovery.oui_dict)
        discovery.oui_dict["b44506"] = "Dell Inc."
        discovery.write_cache.clear()

    def tearDown(self):
        discovery.monitored_networks[:] = self._orig_nets
        discovery.oui_dict.clear()
        discovery.oui_dict.update(self._orig_oui)
        discovery.write_cache.clear()
        discovery.DB_PATH = self._orig_db
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _query(self, mac, src_ip):
        return Ether(bytes(
            Ether(src=mac) / IP(src=src_ip, dst="224.0.0.251") /
            UDP(sport=5353, dport=5353) /
            DNS(qr=0, qd=DNSQR(qname="x._companion-link._tcp.local"))
        ))

    def _insert(self, mac, **cols):
        keys = ["mac", "first_seen", "last_seen", "status"] + list(cols)
        vals = [mac, "x", "x", "online"] + list(cols.values())
        ph = ",".join("?" * len(keys))
        conn = sqlite3.connect(self.db_path)
        conn.execute(f"INSERT INTO devices ({','.join(keys)}) VALUES ({ph})", vals)
        conn.commit()
        conn.close()

    def _get(self, mac):
        conn = sqlite3.connect(self.db_path)
        r = conn.execute(
            "SELECT device_type, vendor, vendor_source FROM devices WHERE mac=?",
            (mac.lower(),),
        ).fetchone()
        conn.close()
        return r

    def test_randomized_mac_infers_apple(self):
        mac = "02:ab:cd:ef:00:11"  # locally administered -> no OUI vendor
        discovery.handle(self._query(mac, "192.168.100.90"))
        dtype, vendor, vsrc = self._get(mac)
        self.assertEqual(dtype, "Apple Device")
        self.assertEqual(vendor, "Apple Inc.")
        self.assertEqual(vsrc, "inferred: mDNS query (_companion-link._tcp)")

    def test_real_oui_dell_survives(self):
        # The misattribution trap: a real-OUI Dell that queries _companion-link
        # (e.g. AirDrop target discovery) must KEEP "Dell Inc." / NULL source,
        # not be relabelled Apple. Gating on the MAC (not observed_vendor) is
        # what protects it.
        mac = "b4:45:06:90:7f:2e"
        self._insert(mac, ip="192.168.100.112", device_type="Computer",
                     class_score=discovery.SCORES["dhcp_vendor"],
                     class_source="DHCP vendor class (msft 5.0)",
                     vendor="Dell Inc.", vendor_source=None)
        discovery.handle(self._query(mac, "192.168.100.112"))
        dtype, vendor, vsrc = self._get(mac)
        self.assertEqual(vendor, "Dell Inc.")
        self.assertIsNone(vsrc)
        # weak mdns_query (40) cannot beat the stored dhcp_vendor (65) type.
        self.assertEqual(dtype, "Computer")


class CleanupStaleMdnsQueryTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)
        self._orig = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        discovery.init_db()

    def tearDown(self):
        discovery.DB_PATH = self._orig
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _insert(self, mac, **cols):
        keys = ["mac", "first_seen", "last_seen", "status"] + list(cols)
        vals = [mac, "x", "x", "online"] + list(cols.values())
        ph = ",".join("?" * len(keys))
        conn = sqlite3.connect(self.db_path)
        conn.execute(f"INSERT INTO devices ({','.join(keys)}) VALUES ({ph})", vals)
        conn.commit()
        conn.close()

    def _get(self, mac):
        conn = sqlite3.connect(self.db_path)
        r = conn.execute(
            "SELECT device_type, COALESCE(class_score,0), class_source "
            "FROM devices WHERE mac=?", (mac,)
        ).fetchone()
        conn.close()
        return r

    def test_removed_hint_rows_reset_kept_rows_survive(self):
        self._insert("aa:00:00:00:00:01", device_type="Apple Device",
                     class_score=discovery.SCORES["mdns_query"],
                     class_source="mDNS query (_airplay._tcp)")
        self._insert("aa:00:00:00:00:02", device_type="Apple Device",
                     class_score=discovery.SCORES["mdns_query"],
                     class_source="mDNS query (_apple-mobdev2._tcp)")
        self._insert("aa:00:00:00:00:03", device_type="Apple Device",
                     class_score=discovery.SCORES["mdns_query"],
                     class_source="mDNS query (_companion-link._tcp)")  # kept
        n = discovery.cleanup_stale_mdns_query_classifications(verbose=False)
        self.assertEqual(n, 2)
        self.assertEqual(self._get("aa:00:00:00:00:01"), (None, 0, None))
        self.assertEqual(self._get("aa:00:00:00:00:02"), (None, 0, None))
        self.assertEqual(
            self._get("aa:00:00:00:00:03"),
            ("Apple Device", discovery.SCORES["mdns_query"],
             "mDNS query (_companion-link._tcp)"),
        )

    def test_idempotent_second_run_changes_nothing(self):
        self._insert("aa:00:00:00:00:01", device_type="Apple Device",
                     class_score=discovery.SCORES["mdns_query"],
                     class_source="mDNS query (_raop._tcp)")
        self.assertEqual(discovery.cleanup_stale_mdns_query_classifications(verbose=False), 1)
        self.assertEqual(discovery.cleanup_stale_mdns_query_classifications(verbose=False), 0)


if __name__ == "__main__":
    unittest.main()
