import unittest

from scapy.all import Ether, IP, TCP

from classification import (
    DHCP_SIGNATURES,
    SCORES,
    fingerprint_tcp_syn,
    is_unclassified,
    merge_candidate,
    type_from_dns_query,
    type_from_mdns_query,
    type_from_vendor,
    type_from_vendor_class,
    vendor_from_domain_needle,
    vendor_from_mdns_query_needle,
    vendor_from_model_in_hostname,
)


class DhcpFingerprintTests(unittest.TestCase):
    def test_added_apple_option55_signature(self):
        self.assertEqual(
            DHCP_SIGNATURES.get((1, 121, 3, 6, 15, 108, 114, 119, 162, 252)),
            "Apple Device",
        )

    def test_added_windows_option55_signature(self):
        self.assertEqual(
            DHCP_SIGNATURES.get(
                (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252, 114)
            ),
            "Computer",
        )

    def test_vendor_class_android(self):
        self.assertEqual(type_from_vendor_class("android-dhcp-14"), ("Mobile (Android)", "android-dhcp-"))
        self.assertEqual(type_from_vendor_class("android-dhcp-15"), ("Mobile (Android)", "android-dhcp-"))

    def test_vendor_class_windows(self):
        self.assertEqual(type_from_vendor_class("MSFT 5.0"), ("Computer", "msft 5.0"))

    def test_vendor_class_xbox_precedes_msft(self):
        # An Xbox vendor class must resolve to Game Console, not Computer,
        # even though Xbox is Windows-based -- first-match ordering.
        self.assertEqual(type_from_vendor_class("XBOX 1.0"), ("Game Console", "xbox"))

    def test_vendor_class_ambiguous_returns_none(self):
        for vc in ("udhcp 1.0", "MSFT", "dhcpcd-9.4.1", "", None):
            self.assertEqual(type_from_vendor_class(vc), (None, None))

    def test_vendor_class_needle_not_full_string(self):
        _, needle = type_from_vendor_class("android-dhcp-15")
        self.assertEqual(needle, "android-dhcp-")
        self.assertNotIn("15", needle)

    def test_android_vendor_class_does_not_override_tv_evidence(self):
        # android-dhcp is also sent by Android TV boxes; a real TV service
        # advertisement (SCORES["service"]=85) must win over it (dhcp_vendor=65).
        tv = ("Smart TV / Media Device", SCORES["service"], "mDNS advertisement")
        vc_dtype, _ = type_from_vendor_class("android-dhcp-14")
        result = merge_candidate(tv, vc_dtype, SCORES["dhcp_vendor"], "DHCP vendor class")
        self.assertEqual(result, tv)


class VendorHintsTests(unittest.TestCase):
    def test_intel_nic_is_computer(self):
        self.assertEqual(type_from_vendor("Intel Corporate"), "Computer")

    def test_asustek_is_computer(self):
        self.assertEqual(type_from_vendor("ASUSTek Computer Inc."), "Computer")

    def test_msi_is_computer(self):
        self.assertEqual(type_from_vendor("Micro-Star INTERNATIONAL CO., LTD."), "Computer")

    def test_existing_entry_not_regressed(self):
        self.assertEqual(type_from_vendor("Sonos, Inc."), "Smart Speaker / Media Device")

    def test_unrelated_vendor_returns_none(self):
        self.assertIsNone(type_from_vendor("Some Random Vendor LLC"))


class DomainHintsTests(unittest.TestCase):
    def test_android_domain(self):
        self.assertEqual(
            type_from_dns_query("android.clients.google.com"),
            ("Mobile (Android)", "android.clients.google.com"),
        )

    def test_apple_domain_broad_match(self):
        self.assertEqual(
            type_from_dns_query("gsp10-ssl.ls.apple.com"),
            ("Apple Device", "apple.com"),
        )

    def test_windows_ncsi_domain(self):
        self.assertEqual(
            type_from_dns_query("www.msftconnecttest.com"),
            ("Computer", "msftconnecttest.com"),
        )

    def test_captive_apple_needle_not_shadowed_by_apple_com(self):
        # Regression: captive.apple.com/mesu.apple.com must be listed before
        # the general "apple.com" entry, or the returned needle would be the
        # shorter "apple.com" and item 6's domain-vendor inference would never
        # see the exact needle it depends on.
        self.assertEqual(type_from_dns_query("captive.apple.com")[1], "captive.apple.com")

    def test_mesu_apple_needle_not_shadowed_by_apple_com(self):
        self.assertEqual(type_from_dns_query("mesu.apple.com")[1], "mesu.apple.com")

    def test_needle_is_never_the_full_qname(self):
        qname = "gsp10-ssl.ls.apple.com"
        _, needle = type_from_dns_query(qname)
        self.assertNotEqual(needle, qname)
        self.assertLess(len(needle), len(qname))


class VendorInferenceTests(unittest.TestCase):
    def test_hostname_long_needle_matches_as_substring(self):
        self.assertEqual(vendor_from_model_in_hostname("Johns-iPhone"), "Apple Inc.")

    def test_hostname_short_needle_rejected_as_arbitrary_substring(self):
        # "ps4" and other <=4-char needles must not match inside unrelated
        # free-form hostnames.
        self.assertIsNone(vendor_from_model_in_hostname("corpsforce4-desktop"))
        self.assertIsNone(vendor_from_model_in_hostname("animaciones-pc"))

    def test_hostname_short_needle_matches_as_whole_token(self):
        self.assertEqual(vendor_from_model_in_hostname("living-room-ps4"), "Sony")

    def test_hostname_no_match_returns_none(self):
        self.assertIsNone(vendor_from_model_in_hostname("random-device-name"))

    def test_domain_vendor_apple_os_endpoint(self):
        self.assertEqual(vendor_from_domain_needle("captive.apple.com"), "Apple Inc.")
        self.assertEqual(vendor_from_domain_needle("mesu.apple.com"), "Apple Inc.")

    def test_domain_vendor_excludes_broad_apple_domain(self):
        # apple.com/icloud.com are also hit by non-Apple devices (Windows
        # iTunes/iCloud, browsers) so they must stay device-type-only.
        self.assertIsNone(vendor_from_domain_needle("apple.com"))
        self.assertIsNone(vendor_from_domain_needle("icloud.com"))

    def test_domain_vendor_excludes_android(self):
        self.assertIsNone(vendor_from_domain_needle("android.clients.google.com"))

    def test_domain_vendor_exact_match_only(self):
        # Never substring-match a full qname -- only the exact needle
        # returned by type_from_dns_query().
        self.assertIsNone(vendor_from_domain_needle("notcaptive.apple.com.evil.com"))


class IsUnclassifiedTests(unittest.TestCase):
    def test_true_cases(self):
        for v in (None, "", "Generic / Unknown"):
            self.assertTrue(is_unclassified(v))

    def test_false_cases(self):
        for v in ("Computer", "Apple Device", "Smart TV / Media Device"):
            self.assertFalse(is_unclassified(v))


class MdnsQueryHintTests(unittest.TestCase):
    def test_apple_continuity_queries(self):
        # Only the Apple peer-to-peer Continuity services (querier is Apple).
        for svc in ("_companion-link._tcp.local", "_rdlink._tcp.local"):
            self.assertEqual(type_from_mdns_query(svc)[0], "Apple Device", svc)

    def test_target_identifying_queries_removed(self):
        # Querying these means "I want to reach an Apple device", NOT "I am one":
        # iTunes for Windows sends _apple-mobdev2; casting apps send _airplay/_raop.
        for svc in ("_apple-mobdev2._tcp.local", "_airplay._tcp.local",
                    "_raop._tcp.local"):
            self.assertEqual(type_from_mdns_query(svc), (None, None), svc)

    def test_googlecast_not_mapped(self):
        # _googlecast is not OS-discriminating (iPhones w/ YouTube/Google Home
        # and desktop Chrome all query it) -> must produce no hint.
        self.assertEqual(type_from_mdns_query("_googlecast._tcp.local"), (None, None))

    def test_unmapped_query_returns_none(self):
        self.assertEqual(type_from_mdns_query("_http._tcp.local"), (None, None))

    def test_needle_is_service_type_not_full_name(self):
        _, needle = type_from_mdns_query("Kitchen._companion-link._tcp.local")
        self.assertEqual(needle, "_companion-link._tcp")

    def test_weight_below_weak_service(self):
        self.assertLess(SCORES["mdns_query"], SCORES["weak_service"])


class MdnsQueryVendorHintTests(unittest.TestCase):
    def test_continuity_needles_infer_apple(self):
        self.assertEqual(vendor_from_mdns_query_needle("_companion-link._tcp"), "Apple Inc.")
        self.assertEqual(vendor_from_mdns_query_needle("_rdlink._tcp"), "Apple Inc.")

    def test_removed_services_infer_nothing(self):
        # These identify the query target, not the querier -> no vendor.
        for n in ("_airplay._tcp", "_raop._tcp", "_apple-mobdev2._tcp"):
            self.assertIsNone(vendor_from_mdns_query_needle(n), n)

    def test_none_and_unknown(self):
        self.assertIsNone(vendor_from_mdns_query_needle(None))
        self.assertIsNone(vendor_from_mdns_query_needle("_http._tcp"))


def _syn(ttl, window, opts):
    """Round-trip a pure-SYN packet through bytes so options dissect like wire."""
    p = Ether() / IP(ttl=ttl) / TCP(flags="S", window=window, options=opts)
    return Ether(bytes(p))


class TcpSynFingerprintTests(unittest.TestCase):
    APPLE_OPTS = [("MSS", 1460), ("NOP", None), ("WScale", 6), ("NOP", None),
                  ("NOP", None), ("Timestamp", (1, 0)), ("SAckOK", b""), ("EOL", None)]

    def test_apple_ttl64(self):
        self.assertEqual(
            fingerprint_tcp_syn(_syn(64, 65535, self.APPLE_OPTS)),
            ("Apple", "Apple Device"),
        )

    def test_windows_stack_no_hint(self):
        # Windows bucket was removed as unvalidated on this network -> no hint.
        pkt = _syn(128, 64240, [("MSS", 1460), ("NOP", None), ("WScale", 8),
                                ("NOP", None), ("NOP", None), ("SAckOK", b"")])
        self.assertEqual(fingerprint_tcp_syn(pkt), (None, None))

    def test_linux_stack_no_hint(self):
        # Linux/Android bucket was removed as unvalidated -> no hint.
        pkt = _syn(64, 64240, [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)),
                               ("NOP", None), ("WScale", 7)])
        self.assertEqual(fingerprint_tcp_syn(pkt), (None, None))

    def test_ambiguous_no_hint(self):
        self.assertEqual(fingerprint_tcp_syn(_syn(200, 1024, [("MSS", 1460)])), (None, None))

    def test_weight_is_weak(self):
        self.assertLess(SCORES["syn_fp"], SCORES["weak_service"])


if __name__ == "__main__":
    unittest.main()
