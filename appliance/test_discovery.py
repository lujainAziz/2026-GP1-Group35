import os
import socket
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta

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
    normalize_arpscan_vendor,
    presence_status,
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


class ArpScanVendorNormalizationTests(unittest.TestCase):
    def test_unknown_parenthesized_to_none(self):
        self.assertIsNone(normalize_arpscan_vendor("(Unknown)"))

    def test_unknown_bare_to_none(self):
        self.assertIsNone(normalize_arpscan_vendor("Unknown"))

    def test_unknown_with_dup_suffix_to_none(self):
        # The confirmed RE-laptop bug: an unknown placeholder carrying a
        # duplicate-response annotation must still normalize to None.
        self.assertIsNone(normalize_arpscan_vendor("(Unknown) (DUP: 2)"))

    def test_real_vendor_with_dup_suffix_preserved(self):
        self.assertEqual(
            normalize_arpscan_vendor("Some Vendor (DUP: 2)"), "Some Vendor"
        )

    def test_normal_vendor_unchanged(self):
        self.assertEqual(
            normalize_arpscan_vendor("Raspberry Pi Foundation"),
            "Raspberry Pi Foundation",
        )

    def test_empty_and_none_to_none(self):
        self.assertIsNone(normalize_arpscan_vendor(""))
        self.assertIsNone(normalize_arpscan_vendor("   "))
        self.assertIsNone(normalize_arpscan_vendor(None))


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

    def test_global_mac_unknown_dup_placeholder_is_nulled(self):
        # The confirmed bug: a globally administered MAC (the RE laptop) with a
        # missing-OUI placeholder carrying a DUP annotation must be reset. The
        # locally-administered-only cleanup never reaches a global MAC.
        self._insert("dc:97:ba:fc:34:ce", "(Unknown) (DUP: 2)", None)
        discovery.init_db()
        self.assertIsNone(self._vendor("dc:97:ba:fc:34:ce"))

    def test_global_mac_plain_unknown_is_nulled(self):
        self._insert("dc:97:ba:11:22:33", "(Unknown)", None)
        discovery.init_db()
        self.assertIsNone(self._vendor("dc:97:ba:11:22:33"))

    def test_global_mac_real_vendor_preserved(self):
        # A legitimate OUI vendor on a globally administered MAC must never be
        # cleared by the new placeholder cleanup.
        self._insert("28:39:5e:d7:44:0c", "Samsung Electronics", None)
        discovery.init_db()
        self.assertEqual(self._vendor("28:39:5e:d7:44:0c"), "Samsung Electronics")


class ObservedStatusAgingTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)
        self._orig_db_path = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        discovery.init_db()
        discovery.write_cache.clear()
        now = datetime.now()
        self.fresh = (now - timedelta(seconds=10)).isoformat(timespec="seconds")
        self.stale = (
            now - timedelta(seconds=discovery.DISCOVERY_STALE_SECONDS + 60)
        ).isoformat(timespec="seconds")

    def tearDown(self):
        discovery.DB_PATH = self._orig_db_path
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _insert(self, mac, **cols):
        keys = ["mac", "first_seen", "last_seen"] + list(cols)
        vals = [mac, "x", "x"] + list(cols.values())
        ph = ",".join("?" * len(keys))
        conn = sqlite3.connect(self.db_path)
        conn.execute(f"INSERT INTO devices ({','.join(keys)}) VALUES ({ph})", vals)
        conn.commit()
        conn.close()

    def _row(self, mac, *fields):
        conn = sqlite3.connect(self.db_path)
        r = conn.execute(
            f"SELECT {','.join(fields)} FROM devices WHERE mac=?", (mac,)
        ).fetchone()
        conn.close()
        return r

    def test_passive_observed_fresh_span_stays_observed(self):
        self._insert("aa:00:00:00:00:01", status="observed", discovered_current=0,
                     ap_associated=0, session_seen=1, last_span_seen=self.fresh)
        discovery.mark_stale_discovery_records()
        self.assertEqual(self._row("aa:00:00:00:00:01", "status")[0], "observed")

    def test_passive_observed_stale_span_becomes_offline(self):
        self._insert("aa:00:00:00:00:02", status="observed", discovered_current=0,
                     ap_associated=0, session_seen=1, last_span_seen=self.stale)
        discovery.mark_stale_discovery_records()
        self.assertEqual(self._row("aa:00:00:00:00:02", "status")[0], "offline")

    def test_discovered_aged_out_fresh_span_becomes_observed(self):
        self._insert("aa:00:00:00:00:03", status="online", discovered_current=1,
                     ap_associated=0, session_seen=1,
                     last_discovery_seen=self.stale, last_span_seen=self.fresh)
        discovery.mark_stale_discovery_records()
        st, dc = self._row("aa:00:00:00:00:03", "status", "discovered_current")
        self.assertEqual(st, "observed")
        self.assertEqual(dc, 0)

    def test_discovered_aged_out_stale_span_becomes_offline(self):
        self._insert("aa:00:00:00:00:04", status="online", discovered_current=1,
                     ap_associated=0, session_seen=1,
                     last_discovery_seen=self.stale, last_span_seen=self.stale)
        discovery.mark_stale_discovery_records()
        st, dc = self._row("aa:00:00:00:00:04", "status", "discovered_current")
        self.assertEqual(st, "offline")
        self.assertEqual(dc, 0)

    def test_ap_associated_remains_online(self):
        self._insert("aa:00:00:00:00:05", status="online", discovered_current=0,
                     ap_associated=1, session_seen=0,
                     last_discovery_seen=self.stale, last_span_seen=self.stale)
        discovery.mark_stale_discovery_records()
        self.assertEqual(self._row("aa:00:00:00:00:05", "status")[0], "online")

    def test_session_seen_preserved_when_observed_becomes_offline(self):
        self._insert("aa:00:00:00:00:06", status="observed", discovered_current=0,
                     ap_associated=0, session_seen=1, last_span_seen=self.stale)
        discovery.mark_stale_discovery_records()
        st, ss = self._row("aa:00:00:00:00:06", "status", "session_seen")
        self.assertEqual(st, "offline")
        self.assertEqual(ss, 1)  # runtime metric untouched

    def test_fresh_span_after_offline_restores_observed(self):
        self._insert("aa:00:00:00:00:07", ip="192.168.1.80", status="offline",
                     discovered_current=0, ap_associated=0, session_seen=0,
                     last_span_seen=self.stale)
        discovery.update_device("aa:00:00:00:00:07", ip="192.168.1.80", seen_on_span=True)
        st, ss = self._row("aa:00:00:00:00:07", "status", "session_seen")
        self.assertEqual(st, "observed")
        self.assertEqual(ss, 1)

    def test_currently_discovered_stays_online(self):
        # Normal online behaviour is unchanged by the ager.
        self._insert("aa:00:00:00:00:08", status="online", discovered_current=1,
                     ap_associated=0, session_seen=1,
                     last_discovery_seen=self.fresh, last_span_seen=self.fresh)
        discovery.mark_stale_discovery_records()
        st, dc = self._row("aa:00:00:00:00:08", "status", "discovered_current")
        self.assertEqual(st, "online")
        self.assertEqual(dc, 1)

    def test_presence_status_helper_rules(self):
        self.assertEqual(presence_status(1, 0, None), "online")
        self.assertEqual(presence_status(0, 1, None), "online")
        self.assertEqual(presence_status(0, 0, self.fresh), "observed")
        self.assertEqual(presence_status(0, 0, self.stale), "offline")
        self.assertEqual(presence_status(0, 0, None), "offline")


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

    def _insert(self, mac, device_type, hostname=None):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO devices (mac, ip, device_type, hostname, first_seen, last_seen, status) "
            "VALUES (?, '192.168.100.50', ?, ?, 'x', 'x', 'online')",
            (mac, device_type, hostname),
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

    def test_existing_classified_and_named_device_not_scheduled(self):
        # Classified AND already has a usable hostname -> no enrichment at all.
        mac = "72:e4:6b:44:a6:11"
        self._insert(mac, "Computer", hostname="OFFICE-PC")
        discovery.update_device(mac, ip="192.168.100.50", seen_on_span=True)
        self.assertNotIn(mac, discovery.mdns_probed)
        self.assertNotIn(mac, discovery.active_probed)

    def test_existing_classified_without_name_gets_mdns(self):
        # Classified but NO hostname -> eligible for mDNS name enrichment,
        # but NOT the active/Nmap probe (which stays unclassified-only).
        mac = "72:e4:6b:44:a6:22"
        self._insert(mac, "Apple Device")
        discovery.update_device(mac, ip="192.168.100.50", seen_on_span=True)
        self.assertIn(mac, discovery.mdns_probed)
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

    def test_vendor_class_android_rescores_to_os_hint(self):
        # "android-dhcp-..." is an OS token, not a phone: it now rescores to the
        # neutral "Android Device" at the weak os_hint tier (was Mobile (Android)
        # at dhcp_vendor -- that mapping was the bug).
        self._insert("aa:00:00:00:00:02", vendor_class="android-dhcp-15")
        discovery.rescore_stored_evidence(verbose=False)
        dtype, score, source = self._get("aa:00:00:00:00:02")
        self.assertEqual(dtype, "Android Device")
        self.assertEqual(score, discovery.SCORES["os_hint"])

    def test_xbox_vendor_class_still_upgrades_unknown(self):
        # A specific (non-OS) vendor class is unaffected by the android change.
        self._insert("aa:00:00:00:00:12", vendor_class="XBOX 1.0")
        discovery.rescore_stored_evidence(verbose=False)
        dtype, score, _ = self._get("aa:00:00:00:00:12")
        self.assertEqual(dtype, "Game Console")
        self.assertEqual(score, discovery.SCORES["dhcp_vendor"])

    def test_mitv_model_beats_android_hostname(self):
        # Real case 60:35:73:f2:4d:7b: an Android-TV A-record hostname (OS token)
        # plus a TV model. The model (95) must win over the android OS hint (40),
        # so the device is a Smart TV, not "Mobile (Android)".
        self._insert("aa:00:00:00:00:13",
                     hostname="android-aesp0", model="MiTV-AESP0", model_score=95)
        discovery.rescore_stored_evidence(verbose=False)
        self.assertEqual(self._get("aa:00:00:00:00:13")[0],
                         "Smart TV / Media Device")

    def test_android_only_hostname_rescores_to_os_hint(self):
        # Real case Android-5: a bare "android" hostname with no form-factor
        # evidence is the neutral OS label, not a phone.
        self._insert("aa:00:00:00:00:14", hostname="Android-5")
        discovery.rescore_stored_evidence(verbose=False)
        dtype, score, _ = self._get("aa:00:00:00:00:14")
        self.assertEqual(dtype, "Android Device")
        self.assertEqual(score, discovery.SCORES["os_hint"])

    def test_zflip3_hostname_rescores_to_mobile(self):
        # Real case d2:5a:1b:a1:48:de: the phone family in the hostname is
        # form-factor evidence, so it stays Mobile (Android).
        self._insert("aa:00:00:00:00:15", hostname="Z-Flip3-alkhas-b-noura")
        discovery.rescore_stored_evidence(verbose=False)
        dtype, score, _ = self._get("aa:00:00:00:00:15")
        self.assertEqual(dtype, "Mobile (Android)")
        self.assertEqual(score, discovery.SCORES["hostname"])

    def test_android_signature_with_extra_options_rescores_to_os_hint(self):
        # Fix 2 real case: Z-Flip3 PRL = base Android + 114 + 108 (RFC 8925).
        # Exact-tuple lookup missed it; tolerant matching classifies it, and it
        # is OS-only -> "Android Device" at os_hint (no hostname evidence here).
        self._insert("aa:00:00:00:00:16",
                     dhcp_signature="1,3,6,15,26,28,51,58,59,43,114,108")
        discovery.rescore_stored_evidence(verbose=False)
        dtype, score, _ = self._get("aa:00:00:00:00:16")
        self.assertEqual(dtype, "Android Device")
        self.assertEqual(score, discovery.SCORES["os_hint"])

    def test_zflip3_hostname_plus_signature_stays_mobile(self):
        # With the phone-family hostname AND the Android signature, the
        # form-factor hostname (90) wins over the OS signature (os_hint).
        self._insert("aa:00:00:00:00:17", hostname="Z-Flip3-alkhas-b-noura",
                     dhcp_signature="1,3,6,15,26,28,51,58,59,43,114,108")
        discovery.rescore_stored_evidence(verbose=False)
        dtype, score, _ = self._get("aa:00:00:00:00:17")
        self.assertEqual(dtype, "Mobile (Android)")
        self.assertEqual(score, discovery.SCORES["hostname"])

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

    def _insert(self, mac, device_type, hostname=None):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO devices (mac, ip, device_type, hostname, first_seen, last_seen, status) "
            "VALUES (?, '192.168.100.50', ?, ?, 'x', 'x', 'online')",
            (mac, device_type, hostname),
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

    def test_existing_classified_and_named_not_scheduled(self):
        # Classified AND already named -> no NBNS enrichment.
        mac = "72:e4:6b:44:a6:11"
        self._insert(mac, "Computer", hostname="OFFICE-PC")
        discovery.update_device(mac, ip="192.168.100.50", seen_on_span=True)
        self.assertNotIn(mac, discovery.nbns_probed)

    def test_existing_classified_without_name_gets_nbns(self):
        # Classified but NO hostname -> eligible for NBNS name enrichment.
        mac = "72:e4:6b:44:a6:33"
        self._insert(mac, "Computer")
        discovery.update_device(mac, ip="192.168.100.50", seen_on_span=True)
        self.assertIn(mac, discovery.nbns_probed)


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


class AndroidTvClassificationTests(unittest.TestCase):
    """Full handle() path for the real Xiaomi Android-TV case: an mDNS response
    whose A-record hostname carries the "android" OS token plus a TV model. The
    model must win so the device is a Smart TV, not Mobile (Android)."""

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
        discovery.write_cache.clear()

    def tearDown(self):
        discovery.monitored_networks[:] = self._orig_nets
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

    def _mdns(self, mac, src_ip, answers):
        return Ether(bytes(
            Ether(src=mac) / IP(src=src_ip, dst="224.0.0.251") /
            UDP(sport=5353, dport=5353) / DNS(qr=1, an=answers)
        ))

    def test_android_tv_model_beats_android_hostname(self):
        mac = "60:35:73:f2:4d:7b"
        pkt = self._mdns(mac, "192.168.100.50", [
            DNSRR(rrname="android-aesp0.local", type="A", rdata="192.168.100.50"),
            DNSRR(rrname="x._device-info._tcp.local", type="TXT",
                  rdata=[b"model=MiTV-AESP0"]),
        ])
        discovery.handle(pkt)
        self.assertEqual(self._row(mac)[0], "Smart TV / Media Device")

    def test_android_only_hostname_is_android_device(self):
        mac = "d2:9b:4b:ce:f7:84"
        pkt = self._mdns(mac, "192.168.100.51", [
            DNSRR(rrname="Android-5.local", type="A", rdata="192.168.100.51"),
        ])
        discovery.handle(pkt)
        self.assertEqual(self._row(mac)[0], "Android Device")


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


class ActiveProbeSurveillanceTests(unittest.TestCase):
    """Drive the REAL probe_device_ports() with faked nmap output and assert
    it stores the broad Video Surveillance Device verdict (never a bare
    Security Camera) for RTSP-bearing devices."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)
        self._orig_db_path = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        discovery.init_db()
        # Neutralize the pre-probe wait and the real nmap invocation.
        self._orig_delay = discovery.ACTIVE_PROBE_DELAY_SECONDS
        self._orig_check_output = discovery.subprocess.check_output
        discovery.ACTIVE_PROBE_DELAY_SECONDS = 0

    def tearDown(self):
        discovery.ACTIVE_PROBE_DELAY_SECONDS = self._orig_delay
        discovery.subprocess.check_output = self._orig_check_output
        discovery.write_cache.clear()
        discovery.DB_PATH = self._orig_db_path
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _insert_unclassified(self, mac, ip):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO devices (mac, ip, device_type, first_seen, last_seen, status) "
            "VALUES (?, ?, NULL, 'x', 'x', 'online')",
            (mac, ip),
        )
        conn.commit()
        conn.close()

    def _fake_nmap(self, table_text):
        def _check_output(cmd, **kwargs):
            return table_text
        discovery.subprocess.check_output = _check_output

    def _row(self, mac):
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT device_type, class_score, class_source FROM devices WHERE mac=?",
            (mac,),
        ).fetchone()
        conn.close()
        return row

    def test_probe_80_443_554_8000_is_video_surveillance(self):
        mac, ip = "52:d4:f6:d3:28:55", "192.168.1.236"
        self._insert_unclassified(mac, ip)
        self._fake_nmap(
            "PORT     STATE  SERVICE\n"
            "80/tcp   open   http\n"
            "443/tcp  open   https\n"
            "554/tcp  open   rtsp\n"
            "8000/tcp open   http-alt\n"
        )
        discovery.probe_device_ports(mac, ip)
        dtype, score, source = self._row(mac)
        self.assertEqual(dtype, "Video Surveillance Device")
        self.assertEqual(score, discovery.SCORES["port"])
        self.assertIn("554+8000", source)

    def test_probe_rtsp_only_is_video_surveillance_not_camera(self):
        mac, ip = "52:d4:f6:aa:bb:cc", "192.168.1.237"
        self._insert_unclassified(mac, ip)
        self._fake_nmap(
            "PORT     STATE  SERVICE\n"
            "80/tcp   open   http\n"
            "443/tcp  open   https\n"
            "554/tcp  open   rtsp\n"
        )
        discovery.probe_device_ports(mac, ip)
        dtype, score, source = self._row(mac)
        self.assertEqual(dtype, "Video Surveillance Device")
        self.assertNotEqual(dtype, "Security Camera")
        self.assertEqual(score, discovery.SCORES["port"])
        self.assertIn("554", source)


class OnvifRefinementTests(unittest.TestCase):
    """Generic ONVIF is stored broad (weak_service) and MUST be refinable by
    later explicit NVT/NVS evidence (service), via update_device's real merge."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)
        self._orig = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        discovery.init_db()

    def tearDown(self):
        discovery.write_cache.clear()
        discovery.DB_PATH = self._orig
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _row(self, mac):
        conn = sqlite3.connect(self.db_path)
        r = conn.execute(
            "SELECT device_type, class_score FROM devices WHERE mac=?", (mac,)
        ).fetchone()
        conn.close()
        return r

    def test_generic_onvif_stored_broad_then_nvt_refines_to_camera(self):
        mac = "aa:bb:cc:dd:ee:01"
        discovery.update_device(
            mac, ip="192.168.1.50", seen_on_span=True,
            candidate=("Video Surveillance Device", discovery.SCORES["weak_service"],
                       "WS-Discovery / ONVIF (generic)"),
        )
        self.assertEqual(
            self._row(mac),
            ("Video Surveillance Device", discovery.SCORES["weak_service"]),
        )
        discovery.update_device(
            mac, ip="192.168.1.50", seen_on_span=True,
            candidate=("Security Camera", discovery.SCORES["service"],
                       "WS-Discovery / ONVIF advertisement"),
        )
        self.assertEqual(
            self._row(mac), ("Security Camera", discovery.SCORES["service"])
        )

    def test_generic_onvif_stored_broad_then_nvs_refines_to_nvr(self):
        mac = "aa:bb:cc:dd:ee:02"
        discovery.update_device(
            mac, ip="192.168.1.51", seen_on_span=True,
            candidate=("Video Surveillance Device", discovery.SCORES["weak_service"],
                       "WS-Discovery / ONVIF (generic)"),
        )
        self.assertEqual(self._row(mac)[0], "Video Surveillance Device")
        discovery.update_device(
            mac, ip="192.168.1.51", seen_on_span=True,
            candidate=("Network Video Recorder", discovery.SCORES["service"],
                       "WS-Discovery / ONVIF advertisement"),
        )
        self.assertEqual(
            self._row(mac), ("Network Video Recorder", discovery.SCORES["service"])
        )


class MdnsNameExtractionTests(unittest.TestCase):
    """mDNS A/AAAA owner + DNS-SD instance name extraction (response packets)."""

    def test_a_record_owner_hostname(self):
        pkt = DNS(qr=1, an=DNSRR(rrname="Living-Room-TV.local", type="A",
                                 rdata="192.168.1.5"))
        self.assertEqual(discovery.extract_mdns_hostname(pkt), "Living-Room-TV")

    def test_aaaa_record_owner_hostname(self):
        pkt = DNS(qr=1, an=DNSRR(rrname="MacBook-Pro.local", type="AAAA",
                                 rdata="fe80::1"))
        self.assertEqual(discovery.extract_mdns_hostname(pkt), "MacBook-Pro")

    def test_ptr_instance_name(self):
        pkt = DNS(qr=1, an=DNSRR(rrname="_rdlink._tcp.local", type="PTR",
                                 rdata="Lujain-iPhone._rdlink._tcp.local"))
        self.assertEqual(discovery.extract_mdns_instance_name(pkt), "Lujain-iPhone")

    def test_escaped_dot_in_instance_label(self):
        # \. is an escaped dot inside one label, not a separator.
        labels = discovery._split_dns_labels("Lujains\\.iPhone._rdlink._tcp.local")
        self.assertEqual(labels, ["Lujains.iPhone", "_rdlink", "_tcp", "local"])

    def test_service_only_owner_rejected(self):
        pkt = DNS(qr=1, an=DNSRR(rrname="_rdlink._tcp.local", type="A",
                                 rdata="192.168.1.9"))
        self.assertIsNone(discovery.extract_mdns_hostname(pkt))

    def test_bare_service_ptr_has_no_instance(self):
        pkt = DNS(qr=1, an=DNSRR(rrname="_rdlink._tcp.local", type="PTR",
                                 rdata="_rdlink._tcp.local"))
        self.assertIsNone(discovery.extract_mdns_instance_name(pkt))

    def test_numeric_ip_like_owner_rejected(self):
        pkt = DNS(qr=1, an=DNSRR(rrname="192-168-1-5.local", type="A",
                                 rdata="192.168.1.5"))
        self.assertIsNone(discovery.extract_mdns_hostname(pkt))

    def test_generic_instance_rejected(self):
        pkt = DNS(qr=1, an=DNSRR(rrname="_http._tcp.local", type="PTR",
                                 rdata="Media Renderer._http._tcp.local"))
        self.assertIsNone(discovery.extract_mdns_instance_name(pkt))

    def test_txt_fn_still_supported_and_preferred(self):
        pkt = DNS(qr=1, an=[
            DNSRR(rrname="x._airplay._tcp.local", type="TXT",
                  rdata=[b"fn=Living Room TV"]),
            DNSRR(rrname="Living-Room-TV.local", type="A", rdata="192.168.1.5"),
        ])
        friendly = extract_mdns_metadata(pkt)[5]
        self.assertEqual(friendly, "Living Room TV")
        name, src = discovery.mdns_name_candidate(pkt, friendly)
        self.assertEqual((name, src), ("Living Room TV", "mDNS friendly name"))

    def test_candidate_falls_back_to_a_record_then_instance(self):
        a_pkt = DNS(qr=1, an=DNSRR(rrname="Office-PC.local", type="A",
                                   rdata="192.168.1.7"))
        self.assertEqual(discovery.mdns_name_candidate(a_pkt, None),
                         ("Office-PC", "mDNS A-record hostname"))
        ptr_pkt = DNS(qr=1, an=DNSRR(rrname="_rdlink._tcp.local", type="PTR",
                                     rdata="Pixel-7._rdlink._tcp.local"))
        self.assertEqual(discovery.mdns_name_candidate(ptr_pkt, None),
                         ("Pixel-7", "mDNS service-instance name"))

    def test_query_packet_yields_no_name(self):
        # Passive DNS/mDNS QUERIES must not become a hostname (privacy).
        q = DNS(qr=0, qd=DNSQR(qname="private-host.example.com"))
        self.assertIsNone(discovery.extract_mdns_hostname(q))
        self.assertIsNone(discovery.extract_mdns_instance_name(q))

    def test_query_with_known_answer_records_yields_no_name(self):
        # An mDNS QUERY (qr=0) may legitimately carry known-answer A/PTR records
        # in its answer section; those name OTHER hosts, never the sender, so
        # neither helper may extract from a query packet.
        q = DNS(qr=0, qd=DNSQR(qname="_rdlink._tcp.local", qtype="PTR"), an=[
            DNSRR(rrname="Someone-Else-TV.local", type="A", rdata="192.168.1.80"),
            DNSRR(rrname="_rdlink._tcp.local", type="PTR",
                  rdata="Someone-Else-iPhone._rdlink._tcp.local"),
        ])
        self.assertEqual(int(q[DNS].qr), 0)
        self.assertIsNone(discovery.extract_mdns_hostname(q))
        self.assertIsNone(discovery.extract_mdns_instance_name(q))


class _SyncThread:
    """Run a scheduled worker synchronously so scheduling can be asserted."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None, **_):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        if self._target:
            self._target(*self._args, **self._kwargs)


class NameEnrichmentEligibilityTests(unittest.TestCase):
    """mDNS/NBNS NAME enrichment eligibility: unclassified OR hostname missing.
    The Nmap/active probe must stay unclassified-only (not broadened)."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)
        self._orig_db = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        discovery.init_db()

        self._orig_thread = discovery.threading.Thread
        discovery.threading.Thread = _SyncThread
        self._orig_mdns = discovery.mdns_probe_device
        self._orig_nbns = discovery.nbns_probe_device
        self._orig_active = discovery.probe_device_ports
        self.calls = {"mdns": [], "nbns": [], "active": []}
        discovery.mdns_probe_device = lambda mac, ip: self.calls["mdns"].append(mac)
        discovery.nbns_probe_device = lambda mac, ip: self.calls["nbns"].append(mac)
        discovery.probe_device_ports = lambda mac, ip: self.calls["active"].append(mac)

        self._orig_flags = (discovery.ENABLE_MDNS_PROBE,
                            discovery.ENABLE_NBNS_PROBE,
                            discovery.ENABLE_ACTIVE_PROBE)
        discovery.ENABLE_MDNS_PROBE = True
        discovery.ENABLE_NBNS_PROBE = True
        discovery.ENABLE_ACTIVE_PROBE = True
        discovery.mdns_probed.clear()
        discovery.nbns_probed.clear()
        discovery.active_probed.clear()

    def tearDown(self):
        discovery.threading.Thread = self._orig_thread
        discovery.mdns_probe_device = self._orig_mdns
        discovery.nbns_probe_device = self._orig_nbns
        discovery.probe_device_ports = self._orig_active
        (discovery.ENABLE_MDNS_PROBE,
         discovery.ENABLE_NBNS_PROBE,
         discovery.ENABLE_ACTIVE_PROBE) = self._orig_flags
        discovery.mdns_probed.clear()
        discovery.nbns_probed.clear()
        discovery.active_probed.clear()
        discovery.write_cache.clear()
        discovery.DB_PATH = self._orig_db
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    # 1. classified + hostname present -> no name-enrichment probe
    def test_classified_with_hostname_not_probed(self):
        discovery.update_device(
            "aa:00:00:00:22:01", ip="192.168.1.70", seen_on_span=True,
            hostname="OfficePC",
            candidate=("Computer", discovery.SCORES["service"], "test"),
        )
        self.assertEqual(self.calls["mdns"], [])
        self.assertEqual(self.calls["nbns"], [])
        self.assertEqual(self.calls["active"], [])

    # 2. classified + hostname missing -> eligible for mDNS/NBNS (not Nmap)
    def test_classified_without_hostname_gets_name_enrichment(self):
        mac = "aa:00:00:00:22:02"
        discovery.update_device(
            mac, ip="192.168.1.71", seen_on_span=True, hostname=None,
            candidate=("Apple Device", discovery.SCORES["service"], "test"),
        )
        self.assertEqual(self.calls["mdns"], [mac])
        self.assertEqual(self.calls["nbns"], [mac])
        self.assertEqual(self.calls["active"], [])  # active probe NOT broadened

    # 3. unclassified -> still eligible as before (incl. active probe)
    def test_unclassified_still_eligible(self):
        mac = "aa:00:00:00:22:03"
        discovery.update_device(mac, ip="192.168.1.72", seen_on_span=True)
        self.assertEqual(self.calls["mdns"], [mac])
        self.assertEqual(self.calls["nbns"], [mac])
        self.assertEqual(self.calls["active"], [mac])

    # 4. cooldown / dedup still prevents repeated probing
    def test_dedup_prevents_repeat_probe(self):
        mac = "aa:00:00:00:22:04"
        for _ in range(3):
            discovery.update_device(
                mac, ip="192.168.1.73", seen_on_span=True, hostname=None,
                candidate=("Apple Device", discovery.SCORES["service"], "test"),
            )
        self.assertEqual(self.calls["mdns"], [mac])   # scheduled exactly once
        self.assertEqual(self.calls["nbns"], [mac])

    def test_eligibility_helper(self):
        self.assertFalse(discovery._name_enrichment_eligible("Computer", "OfficePC"))
        self.assertTrue(discovery._name_enrichment_eligible("Computer", None))
        self.assertTrue(discovery._name_enrichment_eligible("Apple Device", "   "))
        self.assertTrue(discovery._name_enrichment_eligible(None, None))
        self.assertTrue(discovery._name_enrichment_eligible("Generic / Unknown", "x"))


class MdnsNamePersistenceTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)
        self._orig = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        discovery.init_db()

    def tearDown(self):
        discovery.write_cache.clear()
        discovery.DB_PATH = self._orig
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _hostname(self, mac):
        conn = sqlite3.connect(self.db_path)
        r = conn.execute("SELECT hostname FROM devices WHERE mac=?", (mac,)).fetchone()
        conn.close()
        return r[0] if r else None

    def test_stronger_existing_hostname_not_overwritten_by_weaker_mdns(self):
        mac = "aa:00:00:00:11:01"
        discovery.update_device(mac, ip="192.168.1.60", hostname="OfficePC",
                                seen_on_span=True)
        self.assertEqual(self._hostname(mac), "OfficePC")
        # A weaker/equal-quality mDNS-derived name must not replace it.
        discovery.update_device(mac, ip="192.168.1.60", hostname="laptop",
                                seen_on_span=True)
        self.assertEqual(self._hostname(mac), "OfficePC")

    def test_probe_reply_persists_a_record_hostname(self):
        mac = "aa:00:00:00:11:02"
        pkt = DNS(qr=1, an=DNSRR(rrname="Pixel-7.local", type="A",
                                 rdata="192.168.1.61"))
        discovery._apply_mdns_reply(mac, "192.168.1.61", pkt)
        self.assertEqual(self._hostname(mac), "Pixel-7")


class TrustedColumnTests(unittest.TestCase):
    """devices.trusted is a user-only recognition state. discovery.py must
    create it (default 0) but never write or reset it."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)  # let init_db() create it fresh
        self._orig_db_path = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        discovery.write_cache.clear()

    def tearDown(self):
        discovery.DB_PATH = self._orig_db_path
        discovery.write_cache.clear()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _columns(self):
        conn = sqlite3.connect(self.db_path)
        try:
            return {r[1]: r for r in conn.execute("PRAGMA table_info(devices)")}
        finally:
            conn.close()

    def _trusted(self, mac):
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(
                "SELECT trusted FROM devices WHERE mac=?", (mac,)
            ).fetchone()[0]
        finally:
            conn.close()

    def _set_trusted(self, mac, value):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("UPDATE devices SET trusted=? WHERE mac=?", (value, mac))
            conn.commit()
        finally:
            conn.close()

    def test_fresh_db_has_trusted_not_null_default_zero(self):
        discovery.init_db()
        col = self._columns()["trusted"]
        # PRAGMA row: (cid, name, type, notnull, dflt_value, pk)
        self.assertEqual(col[2], "INTEGER")
        self.assertEqual(col[3], 1)       # NOT NULL
        self.assertEqual(str(col[4]), "0")  # DEFAULT 0

    def test_newly_discovered_device_defaults_untrusted(self):
        discovery.init_db()
        discovery.update_device("aa:00:00:00:aa:01", ip="192.168.1.70",
                                seen_in_discovery=True, mark_current=True)
        self.assertEqual(self._trusted("aa:00:00:00:aa:01"), 0)

    def test_old_db_without_column_is_migrated_and_backfilled_false(self):
        # Simulate a pre-trusted DB: base table + a row, no trusted column.
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "CREATE TABLE devices (mac TEXT PRIMARY KEY, ip TEXT, vendor TEXT, "
            "first_seen TEXT, last_seen TEXT, status TEXT)"
        )
        conn.execute("INSERT INTO devices (mac, status) VALUES ('aa:00:00:00:aa:02','online')")
        conn.commit()
        conn.close()
        self.assertNotIn("trusted", self._columns())
        discovery.init_db()  # additive migration adds the column
        self.assertIn("trusted", self._columns())
        self.assertEqual(self._trusted("aa:00:00:00:aa:02"), 0)  # backfilled

    def test_update_device_never_changes_trusted(self):
        discovery.init_db()
        mac = "aa:00:00:00:aa:03"
        discovery.update_device(mac, ip="192.168.1.71", seen_in_discovery=True,
                                mark_current=True)
        self._set_trusted(mac, 1)
        discovery.write_cache.clear()
        # A later discovery event hits the UPDATE path and enriches identity...
        discovery.update_device(mac, ip="192.168.1.71", hostname="OfficePC",
                                seen_in_discovery=True, mark_current=True)
        self.assertEqual(self._trusted(mac), 1)  # ...but trusted is untouched.

    def test_reset_session_state_never_clears_trusted(self):
        discovery.init_db()
        mac = "aa:00:00:00:aa:04"
        discovery.update_device(mac, ip="192.168.1.72", seen_in_discovery=True,
                                mark_current=True)
        self._set_trusted(mac, 1)
        discovery.reset_session_state()  # startup reset of runtime flags
        self.assertEqual(self._trusted(mac), 1)

    def test_trusted_persists_across_reopen_and_reinit(self):
        discovery.init_db()
        mac = "aa:00:00:00:aa:05"
        discovery.update_device(mac, ip="192.168.1.73", seen_in_discovery=True,
                                mark_current=True)
        self._set_trusted(mac, 1)
        # Simulate API + discovery service restart against the same DB file.
        discovery.init_db()
        discovery.reset_session_state()
        self.assertEqual(self._trusted(mac), 1)


class ActiveProbesSettingTests(unittest.TestCase):
    """active_probes is the single persisted switch for the three active
    identification probes (mDNS / NBNS / limited nmap). The DB row is
    authoritative; the ASSAS_*_PROBE env flags only seed the initial value."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)  # let init_db() create it fresh
        self._orig_db_path = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        self._orig_flags = (
            discovery.ENABLE_MDNS_PROBE,
            discovery.ENABLE_NBNS_PROBE,
            discovery.ENABLE_ACTIVE_PROBE,
        )
        self._orig_upnp = discovery.ENABLE_UPNP_ENRICHMENT
        # Deterministic baseline: all active probes off (independent of the
        # env the test process happens to run under).
        discovery.ENABLE_MDNS_PROBE = False
        discovery.ENABLE_NBNS_PROBE = False
        discovery.ENABLE_ACTIVE_PROBE = False
        discovery.write_cache.clear()

    def tearDown(self):
        discovery.DB_PATH = self._orig_db_path
        (discovery.ENABLE_MDNS_PROBE,
         discovery.ENABLE_NBNS_PROBE,
         discovery.ENABLE_ACTIVE_PROBE) = self._orig_flags
        discovery.ENABLE_UPNP_ENRICHMENT = self._orig_upnp
        discovery.write_cache.clear()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _row(self):
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(
                "SELECT active_probes FROM app_settings WHERE id = 1"
            ).fetchone()
        finally:
            conn.close()

    def _set_active_probes(self, value):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "UPDATE app_settings SET active_probes = ? WHERE id = 1",
                (1 if value else 0,),
            )
            conn.commit()
        finally:
            conn.close()

    def test_fresh_db_seeds_default_false(self):
        discovery.init_db()
        self.assertEqual(self._row()[0], 0)
        self.assertIs(discovery.reload_runtime_settings(), False)
        self.assertFalse(discovery.ENABLE_MDNS_PROBE)
        self.assertFalse(discovery.ENABLE_NBNS_PROBE)
        self.assertFalse(discovery.ENABLE_ACTIVE_PROBE)

    def test_env_flag_seeds_true_once(self):
        # An operator who enabled nmap via env before this setting existed keeps
        # it on as the seeded initial value.
        discovery.ENABLE_ACTIVE_PROBE = True
        discovery.init_db()
        self.assertEqual(self._row()[0], 1)

    def test_db_value_is_authoritative_over_env(self):
        discovery.init_db()  # seeds 0 (all off)
        # Env now claims "on", but the persisted row says off -> DB wins.
        discovery.ENABLE_MDNS_PROBE = True
        discovery.ENABLE_NBNS_PROBE = True
        discovery.ENABLE_ACTIVE_PROBE = True
        self.assertIs(discovery.reload_runtime_settings(), False)
        self.assertFalse(discovery.ENABLE_MDNS_PROBE)
        self.assertFalse(discovery.ENABLE_NBNS_PROBE)
        self.assertFalse(discovery.ENABLE_ACTIVE_PROBE)

    def test_periodic_reload_updates_three_flags_only(self):
        discovery.init_db()
        self._set_active_probes(True)
        before_upnp = discovery.ENABLE_UPNP_ENRICHMENT
        self.assertIs(discovery.reload_runtime_settings(), True)
        self.assertTrue(discovery.ENABLE_MDNS_PROBE)
        self.assertTrue(discovery.ENABLE_NBNS_PROBE)
        self.assertTrue(discovery.ENABLE_ACTIVE_PROBE)
        # SSDP/UPnP M-SEARCH is out of scope and must not be touched.
        self.assertEqual(discovery.ENABLE_UPNP_ENRICHMENT, before_upnp)

    def test_setting_persists_across_reopen_and_reinit(self):
        discovery.init_db()
        self._set_active_probes(True)
        discovery.init_db()  # restart: INSERT OR IGNORE keeps the stored row
        self.assertEqual(self._row()[0], 1)
        self.assertIs(discovery.reload_runtime_settings(), True)

    def test_active_probes_off_does_not_block_inventory(self):
        discovery.init_db()
        self._set_active_probes(False)
        discovery.reload_runtime_settings()
        mac = "aa:00:00:00:bb:01"
        # Passive/discovery inventory still records the device with probes off.
        discovery.update_device(mac, ip="192.168.1.90", seen_in_discovery=True,
                                mark_current=True)
        conn = sqlite3.connect(self.db_path)
        try:
            n = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE mac = ?", (mac,)
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(n, 1)


if __name__ == "__main__":
    unittest.main()
