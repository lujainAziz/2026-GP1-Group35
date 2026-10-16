import csv
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import discovery
import model_db
from classification import (
    MODEL_ALIASES,
    SCORES,
    normalize_model,
    type_from_hostname,
    type_from_huawei_vendor_class,
    type_from_model,
    vendor_from_model,
    vendor_from_model_in_hostname,
)

HERE = Path(__file__).parent
ALLOWED_TYPES = {
    "", "Mobile (Android)", "Tablet (Android)", "Mobile (Apple)", "Tablet (Apple)",
    "Smart TV / Media Device", "Computer",
}


def _rows(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


class DataFileTests(unittest.TestCase):
    """device_models.csv / device_models_manual.csv are well-formed."""

    def test_generated_file_shape(self):
        with open(model_db.DATA_PATH, encoding="utf-8", newline="") as f:
            self.assertEqual(next(csv.reader(f)), ["code", "brand", "name", "type"])
        rows = _rows(model_db.DATA_PATH)
        self.assertGreater(len(rows), 40000)
        codes = [r["code"].lower() for r in rows]
        self.assertEqual(len(codes), len(set(codes)), "duplicate codes")
        for r in rows:
            self.assertIn(r["type"], ALLOWED_TYPES, r)
            self.assertGreaterEqual(len(r["code"]), model_db.MIN_CODE_LEN, r)
            self.assertFalse(r["code"].isdigit(), r)
        for simulator in ("i386", "x86_64", "arm64"):
            self.assertNotIn(simulator, codes)

    def test_manual_rows_are_sourced_and_new(self):
        generated = {r["code"].lower() for r in _rows(model_db.DATA_PATH)}
        rows = _rows(model_db.MANUAL_PATH)
        self.assertTrue(rows)
        for r in rows:
            self.assertTrue(r["source"].startswith("https://"), r)
            self.assertTrue(r["code"] and r["brand"] and r["name"], r)
            self.assertIn(r["type"], ALLOWED_TYPES, r)
            self.assertNotIn(r["code"].lower(), generated,
                             "manual file is only for devices missing from the datasets")


class LookupTests(unittest.TestCase):
    def test_known_codes(self):
        cases = {
            "DBY-W09": ("Huawei", "HUAWEI MatePad 11 Wi-Fi", "Tablet (Android)"),
            "MNA-LX9": ("Huawei", "HUAWEI P60 Pro", "Mobile (Android)"),
            "SM-X710": ("Samsung", "Galaxy Tab S9", "Tablet (Android)"),
            "SM-F711B": ("Samsung", "Galaxy Z Flip3 5G", "Mobile (Android)"),
            "CPH2451": ("OnePlus", "OnePlus 11 5G", "Mobile (Android)"),
            "iPhone14,2": ("Apple", "iPhone 13 Pro", "Mobile (Apple)"),
            "SM-S948B": ("Samsung", "Galaxy S26 Ultra", "Mobile (Android)"),
            "iPhone19,2": ("Apple", "iPhone 18 Pro", "Mobile (Apple)"),      # manual file
            "iPad16,8": ("Apple", "iPad Air 11-inch (M4)", "Tablet (Apple)"),  # manual file
        }
        for code, (brand, name, dtype) in cases.items():
            with self.subTest(code=code):
                entry = model_db.lookup(code)
                self.assertIsNotNone(entry)
                self.assertEqual((entry.brand, entry.name, entry.type), (brand, name, dtype))

    def test_case_and_whitespace_insensitive(self):
        self.assertEqual(model_db.lookup(" sm-x710 ").code, "SM-X710")

    def test_newest_devices_present(self):
        for code in ("SM-S931B", "SM-F776B", "SM-X730", "iPhone18,1", "iPhone18,4",
                     "Pixel 10", "Pixel 11", "SGT-AL00", "KEE-AL00", "BKQ-N49",
                     "24117RN76G", "CPH2745"):
            with self.subTest(code=code):
                self.assertIsNotNone(model_db.lookup(code))

    def test_short_numeric_and_unknown_codes_never_match(self):
        for code in ("G2", "A10", "1013", "unknown", "", None, "not-a-real-code-123"):
            with self.subTest(code=code):
                self.assertIsNone(model_db.lookup(code))

    def test_vendor_names_match_existing_hint_table(self):
        self.assertEqual(model_db.vendor_for_model("SM-X710"), "Samsung Electronics")
        self.assertEqual(model_db.vendor_for_model("iPhone14,2"), "Apple Inc.")
        self.assertEqual(model_db.vendor_for_model("24117RN76G"), "Xiaomi")


class AppleBoardAndMacTests(unittest.TestCase):
    """Apple extension: board IDs (api.ipsw.me) and Mac identifiers."""

    def test_board_ids_resolve_to_name_and_type(self):
        cases = {
            "J271AP": ("iPad (10th generation)", "Tablet (Apple)"),
            "N841AP": ("iPhone XR", "Mobile (Apple)"),
            "J720AP": ("iPad Pro 13-inch (M4)", "Tablet (Apple)"),
            "D74AP": ("iPhone 14 Pro Max", "Mobile (Apple)"),
            "D221AP": ("iPhone X", "Mobile (Apple)"),
            "V54AP": ("iPhone 17 Pro Max", "Mobile (Apple)"),
            "J707AP": ("iPad Air 11-inch (M4, WiFi)", "Tablet (Apple)"),
            "J481AP": ("iPad (A16)", "Tablet (Apple)"),
            "J181AP": ("iPad (9th generation)", "Tablet (Apple)"),
        }
        for code, (name, dtype) in cases.items():
            with self.subTest(code=code):
                entry = model_db.lookup(code)
                self.assertIsNotNone(entry)
                self.assertEqual((entry.brand, entry.name, entry.type),
                                 ("Apple", name, dtype))

    def test_mac_identifier_is_a_computer(self):
        entry = model_db.lookup("MacBookPro9,2")
        self.assertEqual((entry.brand, entry.name, entry.type),
                         ("Apple", "MacBook Pro (13-inch, Mid 2012)", "Computer"))
        self.assertEqual(model_db.vendor_for_model("MacBookPro9,2"), "Apple Inc.")

    def test_computer_type_propagates_through_classification(self):
        # classification.py is untouched; it must still carry the new type.
        self.assertEqual(normalize_model("MacBookPro9,2"), ("MacBookPro9,2", "Computer"))
        self.assertEqual(type_from_model("MacBookPro9,2") or
                         model_db.type_for_model("MacBookPro9,2"), "Computer")

    def test_existing_board_id_alias_still_wins(self):
        # D211AP is both a MODEL_ALIASES entry and an ipsw board ID; the alias
        # (an existing rule) must still win in normalize_model.
        self.assertEqual(normalize_model("d211ap"), MODEL_ALIASES["d211ap"])


class TypeRuleTests(unittest.TestCase):
    """The build rule, as stored in the generated file."""

    def test_form_factor_from_name(self):
        self.assertEqual(model_db.type_for_model("SM-X730"), "Tablet (Android)")      # Tab S11
        self.assertEqual(model_db.type_for_model("PCE-W40"), "Tablet (Android)")      # 平板 / MatePad
        self.assertEqual(model_db.type_for_model("MiTV-AESP0"), "Smart TV / Media Device")

    def test_wearables_cars_laptops_have_vendor_and_name_only(self):
        for code in ("SM-R940", "NOR-B39", "VLT-W60"):       # Watch6, band, MagicBook
            with self.subTest(code=code):
                entry = model_db.lookup(code)
                self.assertIsNone(entry.type)
                self.assertTrue(entry.brand)

    def test_other_brands_never_default_to_phone(self):
        rows = [r for r in _rows(model_db.DATA_PATH) if r["brand"] == "Oukitel"]
        self.assertTrue(rows)
        self.assertNotIn("Mobile (Android)", {r["type"] for r in rows})


class DisplayNameTests(unittest.TestCase):
    def test_bare_code_gets_name_and_code(self):
        self.assertEqual(model_db.display_model("SM-S948B"), "Galaxy S26 Ultra (SM-S948B)")
        self.assertEqual(model_db.display_model("iPhone19,7"), "iPhone 18 Pro Max (iPhone19,7)")

    def test_names_and_unknown_codes_are_left_alone(self):
        self.assertIsNone(model_db.display_model("Galaxy S26 Ultra"))
        self.assertIsNone(model_db.display_model("Pixel 10"))     # code is its own name
        self.assertIsNone(model_db.display_model("XYZ-0000"))

    def test_read_back_uses_the_code(self):
        for code in ("SM-S948B", "SM-X710", "DBY-W09", "LM-Q610(FGN)", "21061119BI"):
            with self.subTest(code=code):
                shown = model_db.display_model(code)
                self.assertEqual(model_db.stored_code(shown), model_db.lookup(code).code)
                self.assertEqual(model_db.lookup(shown), model_db.lookup(code))

    def test_read_back_type_matches_observation(self):
        """Every row: typing the stored display value gives the observed type."""
        for r in _rows(model_db.DATA_PATH):
            code = r["code"]
            _, observed = normalize_model(code)
            stored = model_db.display_model(code) or code
            back = model_db.stored_code(stored)
            reread = type_from_model(back) or model_db.type_for_model(back)
            self.assertEqual(observed, reread, (code, stored))

    def test_stored_code_leaves_other_values_unchanged(self):
        for value in ("Galaxy S26 Ultra", "My Phone (2)", "SM-S948B", None):
            self.assertEqual(model_db.stored_code(value), value)


class ExistingRulesFirstTests(unittest.TestCase):
    def test_model_alias_still_wins(self):
        self.assertEqual(normalize_model("d211ap"), MODEL_ALIASES["d211ap"])

    def test_existing_type_hint_wins_over_database(self):
        # "sm-s" in MODEL_TYPE_HINTS already gives Mobile; the database agrees.
        self.assertEqual(normalize_model("SM-S948B"), ("SM-S948B", "Mobile (Android)"))
        # No hint for "sm-x": the database supplies the tablet type.
        self.assertEqual(normalize_model("SM-X710"), ("SM-X710", "Tablet (Android)"))

    def test_normalize_model_keeps_the_observed_code(self):
        self.assertEqual(normalize_model("iPad13,1")[0], "iPad13,1")

    def test_existing_vendor_hint_wins(self):
        self.assertEqual(vendor_from_model("Galaxy S26 Ultra (SM-S948B)"), "Samsung Electronics")
        self.assertEqual(vendor_from_model("V2514"), "vivo")      # database only

    def test_existing_huawei_table_wins(self):
        self.assertEqual(type_from_huawei_vendor_class("HUAWEI:android:DBY"), "Tablet (Android)")
        self.assertEqual(type_from_huawei_vendor_class("HUAWEI:android:MNA"), "Mobile (Android)")


class HuaweiPrefixTests(unittest.TestCase):
    def test_prefix_fallback(self):
        self.assertEqual(type_from_huawei_vendor_class("HUAWEI:android:CLS"), "Mobile (Android)")
        self.assertEqual(type_from_huawei_vendor_class("HUAWEI:android:PCE"), "Tablet (Android)")

    def test_disagreeing_prefix_has_no_type(self):
        # CRS covers a nova phone and HONOR bands.
        self.assertIsNone(type_from_huawei_vendor_class("HUAWEI:android:CRS"))

    def test_unknown_and_non_huawei(self):
        self.assertIsNone(type_from_huawei_vendor_class("HUAWEI:android:XYZ"))
        self.assertIsNone(model_db.model_from_huawei_vendor_class("HUAWEI:android:XYZ"))
        self.assertIsNone(model_db.model_from_huawei_vendor_class("android-dhcp-14"))

    def test_prefix_is_exact(self):
        # "SG" must not match the SGT-* (Mate 80) codes.
        self.assertEqual(model_db.type_for_huawei_code("SGT"), "Mobile (Android)")
        self.assertIsNone(model_db.type_for_huawei_code("SG"))

    def test_model_names(self):
        self.assertEqual(model_db.model_from_huawei_vendor_class("HUAWEI:android:DBY"),
                         "HUAWEI MatePad 11 (DBY)")
        self.assertEqual(model_db.model_from_huawei_vendor_class("HUAWEI:android:ANA"),
                         "HUAWEI P40 (ANA)")
        self.assertEqual(model_db.model_from_huawei_vendor_class("HUAWEI:android:CRS"),
                         "HUAWEI (CRS)")


class NeverOnHostnamesTests(unittest.TestCase):
    """V2514 (vivo X300 Pro) and SM-X710 are known only to the database."""

    def test_hostname_paths_do_not_use_the_database(self):
        for name in ("V2514", "SM-X710", "PCE-W40"):
            with self.subTest(name=name):
                self.assertIsNone(vendor_from_model_in_hostname(name))
        self.assertIsNone(type_from_hostname("V2514"))
        self.assertIsNone(type_from_hostname("SM-X710"))
        self.assertIsNone(discovery.infer_type_from_text("V2514"))
        self.assertIsNone(discovery.infer_type_from_text("SM-X710"))


class LazyLoadTests(unittest.TestCase):
    def test_import_does_not_read_the_data(self):
        out = subprocess.run(
            [sys.executable, "-c",
             "import classification, discovery, model_db; print(model_db.is_loaded())"],
            cwd=HERE, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(out.stdout.strip(), "False", out.stderr)


class StorageTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)
        self._orig_db_path = discovery.DB_PATH
        discovery.DB_PATH = self.db_path
        discovery.init_db()
        discovery.write_cache.clear()

    def tearDown(self):
        discovery.DB_PATH = self._orig_db_path
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _row(self, mac, *fields):
        conn = sqlite3.connect(self.db_path)
        r = conn.execute(f"SELECT {','.join(fields)} FROM devices WHERE mac=?",
                         (mac,)).fetchone()
        conn.close()
        return r

    def test_code_is_stored_as_name_and_code(self):
        discovery.update_device("a4:00:00:00:00:01", ip="192.168.1.50", model="SM-S948B",
                                model_score=95, model_source="mDNS model")
        self.assertEqual(self._row("a4:00:00:00:00:01", "model")[0],
                         "Galaxy S26 Ultra (SM-S948B)")

    def test_observed_name_is_not_overwritten(self):
        discovery.update_device("a4:00:00:00:00:02", ip="192.168.1.51",
                                model="Living room iPad", model_score=95,
                                model_source="mDNS model")
        self.assertEqual(self._row("a4:00:00:00:00:02", "model")[0], "Living room iPad")

    def test_rescore_types_stored_display_name_by_code(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT INTO devices (mac, first_seen, last_seen, model, model_score) "
                     "VALUES (?, 'x', 'x', ?, 95)",
                     ("a4:00:00:00:00:03", "Galaxy Tab S9 (SM-X710)"))
        conn.commit()
        conn.close()
        discovery.rescore_stored_evidence(verbose=False)
        dtype, score = self._row("a4:00:00:00:00:03", "device_type", "class_score")
        self.assertEqual(dtype, "Tablet (Android)")
        self.assertEqual(score, SCORES["model"])


if __name__ == "__main__":
    unittest.main()
