import unittest

from scapy.all import Ether, IP, TCP

from classification import (
    DHCP_SIGNATURES,
    PORT_HINTS,
    SCORES,
    fingerprint_tcp_syn,
    is_unclassified,
    merge_candidate,
    surveillance_type_from_ports,
    type_from_dns_query,
    type_from_hostname,
    type_from_mdns_query,
    type_from_model,
    type_from_os_hint,
    type_from_payload,
    type_from_vendor,
    type_from_vendor_class,
    weak_type_from_payload,
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

    def test_vendor_class_android_is_os_hint_not_phone(self):
        # "android-dhcp-..." is sent by Android phones, tablets, TVs and boxes
        # alike, so it must NOT resolve to the phone form factor. It is no
        # longer a VENDOR_CLASS_HINTS entry; it is an OS token (os_hint tier).
        self.assertEqual(type_from_vendor_class("android-dhcp-14"), (None, None))
        self.assertEqual(type_from_vendor_class("android-dhcp-15"), (None, None))
        self.assertEqual(type_from_os_hint("android-dhcp-14"), "Android Device")

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
        # Only the matched needle is ever returned/logged, never the full
        # vendor-class string (which can carry a version). (Repointed from the
        # removed android-dhcp entry to xbox, which still demonstrates this.)
        _, needle = type_from_vendor_class("XBOX 1.0")
        self.assertEqual(needle, "xbox")
        self.assertNotIn("1.0", needle)

    def test_android_vendor_class_does_not_override_tv_evidence(self):
        # android-dhcp is also sent by Android TV boxes; a real TV service
        # advertisement (SCORES["service"]=85) must win over the OS token, now
        # scored at the weak os_hint tier (40).
        tv = ("Smart TV / Media Device", SCORES["service"], "mDNS advertisement")
        os_dtype = type_from_os_hint("android-dhcp-14")
        self.assertEqual(os_dtype, "Android Device")
        result = merge_candidate(tv, os_dtype, SCORES["os_hint"], "android OS")
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
        # Android OS connectivity domains are also queried by Android TVs, so
        # they map to the neutral OS label, not the phone form factor.
        self.assertEqual(
            type_from_dns_query("android.clients.google.com"),
            ("Android Device", "android.clients.google.com"),
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


class AndroidOsTokenTests(unittest.TestCase):
    """Fix 1: "android" identifies the OS, not the form factor."""

    def test_android_hostname_is_not_a_form_factor(self):
        # Bare "android" no longer resolves to a phone via the hostname table.
        self.assertIsNone(type_from_hostname("android-12ab"))
        self.assertEqual(type_from_os_hint("android-12ab"), "Android Device")

    def test_mitv_model_is_smart_tv(self):
        # Real case: Xiaomi Android TV 60:35:73:f2:4d:7b, model MiTV-AESP0.
        self.assertEqual(type_from_model("MiTV-AESP0"), "Smart TV / Media Device")

    def test_other_android_tv_box_models_are_smart_tv(self):
        for m in ("Mi Box S", "NVIDIA SHIELD Android TV", "Fire TV Stick",
                  "Chromecast", "AndroidTV-1234"):
            self.assertEqual(type_from_model(m), "Smart TV / Media Device", m)

    def test_samsung_phone_families_are_mobile(self):
        for m in ("SM-S901B", "SM-A546E", "SM-G991B", "SM-F711B", "SM-N970F",
                  "Galaxy Z Flip3", "Redmi Note 12"):
            self.assertEqual(type_from_model(m), "Mobile (Android)", m)

    def test_samsung_tablet_families_are_not_mobile(self):
        # SM-T/X/P and "tab" must never be classified as phones.
        for m in ("SM-T870", "SM-X200", "SM-P610", "Galaxy Tab S8"):
            self.assertNotEqual(type_from_model(m), "Mobile (Android)", m)

    def test_phone_family_with_pad_tab_tv_token_is_not_mobile(self):
        # "galaxy"/"redmi" also ship tablets (Galaxy Tab, Redmi Pad) and TVs
        # (Redmi TV). A pad/tab/tv token must override the phone family, even
        # with hyphen separators that the "galaxy tab" needle alone misses.
        cases = {
            "Redmi-Pad-SE": "Tablet (Android)",
            "Galaxy-Tab-S8": "Tablet (Android)",
            "Redmi-TV-X50": "Smart TV / Media Device",
        }
        for name, expected in cases.items():
            self.assertEqual(type_from_model(name), expected, name)
            self.assertEqual(type_from_hostname(name), expected, name)
            self.assertNotEqual(type_from_model(name), "Mobile (Android)", name)
            self.assertNotEqual(type_from_hostname(name), "Mobile (Android)", name)

    def test_phone_family_without_form_factor_token_stays_mobile(self):
        # The guard must not steal legitimate phones: no pad/tab/tv token here.
        for name in ("Redmi-Note-12", "Galaxy-S23", "Johns-Pixel-7"):
            self.assertEqual(type_from_model(name), "Mobile (Android)", name)
            self.assertEqual(type_from_hostname(name), "Mobile (Android)", name)

    def test_form_factor_guard_uses_whole_tokens_not_substrings(self):
        # "database" contains "tab" as a substring but not as a token, so a
        # phone family here must still read as a phone.
        self.assertEqual(type_from_hostname("Galaxy-database-node"),
                         "Mobile (Android)")

    def test_zflip3_hostname_stays_mobile(self):
        # Real case: d2:5a:1b:a1:48:de hostname "Z-Flip3-alkhas-b-noura".
        self.assertEqual(type_from_hostname("Z-Flip3-alkhas-b-noura"),
                         "Mobile (Android)")

    def test_os_hint_is_overridden_by_form_factor_evidence(self):
        os_hint = ("Android Device", SCORES["os_hint"], "android OS")
        tv_model = merge_candidate(os_hint, "Smart TV / Media Device",
                                   SCORES["model"], "model")
        self.assertEqual(tv_model[0], "Smart TV / Media Device")
        tv_service = merge_candidate(os_hint, "Smart TV / Media Device",
                                     SCORES["service"], "mDNS advertisement")
        self.assertEqual(tv_service[0], "Smart TV / Media Device")

    def test_os_hint_tier_below_dhcp_so_phone_fingerprint_wins(self):
        # The option-55 Android phone fingerprint (dhcp=60) must beat the bare
        # "android" OS token (os_hint=40) so phones stay phones.
        self.assertLess(SCORES["os_hint"], SCORES["dhcp"])
        self.assertLess(SCORES["os_hint"], SCORES["weak_service"])


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


class SurveillanceClassificationTests(unittest.TestCase):
    def test_rtsp_only_is_broad_not_camera(self):
        # 554 alone must NOT read as a standalone Security Camera.
        self.assertEqual(surveillance_type_from_ports({554}), "Video Surveillance Device")
        self.assertEqual(surveillance_type_from_ports({8554}), "Video Surveillance Device")
        self.assertNotEqual(surveillance_type_from_ports({554}), "Security Camera")
        self.assertEqual(PORT_HINTS[554], "Video Surveillance Device")
        self.assertEqual(PORT_HINTS[8554], "Video Surveillance Device")

    def test_rtsp_plus_mgmt_is_broad(self):
        self.assertEqual(
            surveillance_type_from_ports({80, 443, 554, 8000}),
            "Video Surveillance Device",
        )

    def test_mgmt_or_web_only_is_none(self):
        self.assertIsNone(surveillance_type_from_ports({8000}))
        self.assertIsNone(surveillance_type_from_ports({80, 443, 8000}))
        self.assertIsNone(surveillance_type_from_ports({80, 443}))

    def test_non_integer_ports_ignored(self):
        self.assertEqual(
            surveillance_type_from_ports(["554", "80", None]),
            "Video Surveillance Device",
        )

    def test_onvif_storage_is_nvr_and_outranks_port(self):
        # ONVIF NVS (NetworkVideoStorage) -> explicit recorder evidence.
        self.assertEqual(
            type_from_payload(b"<d:Types>dn:NetworkVideoStorage tds:Device</d:Types>"),
            "Network Video Recorder",
        )
        self.assertGreater(SCORES["service"], SCORES["port"])  # 85 > 75

    def test_onvif_transmitter_still_camera(self):
        self.assertEqual(
            type_from_payload(b"onvif://www.onvif.org/type/NetworkVideoTransmitter"),
            "Security Camera",
        )

    def test_nvr_hostname_beats_generic_camera(self):
        self.assertEqual(type_from_hostname("hikvision-nvr-01"), "Network Video Recorder")
        self.assertEqual(type_from_hostname("lobby-dvr"), "Network Video Recorder")

    def test_nvr_model_ordering_beats_vendor_camera(self):
        self.assertEqual(
            type_from_model("Hikvision NVR DS-7608NI-K2"), "Network Video Recorder"
        )
        self.assertGreater(SCORES["model"], SCORES["port"])  # 95 > 75

    def test_plain_ipcam_still_camera(self):
        self.assertEqual(type_from_hostname("ipcam-door"), "Security Camera")

    # --- v3.1: generic ONVIF is weak/broad and refinable; brand alone is weak ---

    def test_generic_onvif_is_weak_broad_not_service_camera(self):
        # generic onvif is no longer a SERVICE (camera) match...
        self.assertIsNone(type_from_payload(b"http://www.onvif.org/ver10/network/wsdl"))
        # ...it is a WEAK broad surveillance match instead.
        self.assertEqual(
            weak_type_from_payload(b"http://www.onvif.org/ver10/network/wsdl"),
            "Video Surveillance Device",
        )

    def test_generic_onvif_weaker_than_explicit(self):
        self.assertLess(SCORES["weak_service"], SCORES["service"])  # 45 < 85

    def test_plain_vendor_hikvision_is_video_surveillance(self):
        self.assertEqual(
            type_from_vendor("Hangzhou Hikvision Digital Technology Co.,Ltd."),
            "Video Surveillance Device",
        )

    def test_brand_only_model_no_high_score_broad(self):
        # brand-only model text must NOT classify (score 95 would block later
        # explicit ONVIF NVT/NVS at 85).
        self.assertIsNone(type_from_model("Hikvision DS-2CD2042"))
        self.assertIsNone(type_from_model("Dahua IPC series"))

    def test_brand_only_hostname_no_high_score_broad(self):
        self.assertIsNone(type_from_hostname("reolink"))

    def test_hikvision_nvr_model_is_nvr(self):
        self.assertEqual(type_from_model("Hikvision NVR DS-7608NI-K2"),
                         "Network Video Recorder")

    def test_reolink_ip_camera_model_is_camera(self):
        self.assertEqual(type_from_model("Reolink IP Camera"), "Security Camera")


if __name__ == "__main__":
    unittest.main()
