#!/usr/bin/env python3
"""Rebuild appliance/device_models.csv from the public model datasets.

Usage:
    python appliance/build_device_models.py D:\\GP-DATA\\datasets

The datasets directory must contain (see docs/DEVICE_MODELS.md for sources):
    supported_devices.csv                    Google Play supported devices (UTF-16)
    apple_ios-device-identifiers.json        kyle-seongwoo-jun/apple-device-identifiers
    apple_tvos-device-identifiers.json       kyle-seongwoo-jun/apple-device-identifiers
    apple_mac-device-identifiers.json        kyle-seongwoo-jun/apple-device-identifiers
    ipsw_devices.json                        api.ipsw.me/v4/devices (Apple board IDs)
    mobilemodels/huawei_cn.md                KHwang9883/MobileModels
    mobilemodels/huawei_global_en.md         KHwang9883/MobileModels
    mobilemodels/honor_cn.md                 KHwang9883/MobileModels
    mobilemodels/honor_global_en.md          KHwang9883/MobileModels

Output columns: code, brand, name, type. One row per model code (case-
insensitive), sorted. Verified devices missing from these datasets go in
device_models_manual.csv instead, which model_db.py overlays at runtime, so
they survive a rebuild.
"""
import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

OUT_PATH = Path(__file__).with_name("device_models.csv")

# Phone/tablet makers whose unlabelled models are phones by default. Keys are
# the lowercased brand as the datasets write it; values are the display brand.
MAJOR_BRANDS = {
    "samsung": "Samsung", "apple": "Apple", "google": "Google",
    "huawei": "Huawei", "honor": "Honor",
    "xiaomi": "Xiaomi", "redmi": "Redmi", "poco": "POCO",
    "oppo": "OPPO", "oneplus": "OnePlus", "vivo": "vivo", "iqoo": "iQOO",
    "realme": "realme", "motorola": "Motorola", "nokia": "Nokia", "hmd": "HMD",
    "sony": "Sony", "lge": "LGE", "lenovo": "Lenovo", "zte": "ZTE",
    "nubia": "nubia", "asus": "ASUS", "tecno": "TECNO", "tecno mobile": "TECNO",
    "infinix": "Infinix", "itel": "itel", "nothing": "Nothing",
    "cmf by nothing": "CMF by Nothing",
    "fairphone": "Fairphone", "meizu": "Meizu", "tcl": "TCL", "sharp": "Sharp",
    "kyocera": "Kyocera", "fujitsu": "Fujitsu", "blackberry": "BlackBerry",
    "htc": "HTC",
}

# Apple's simulator identifiers are not devices, and a bare "arm64" would
# match far too much.
APPLE_SKIP = {"i386", "x86_64", "arm64"}

# Codes this short, or purely numeric, are shared by unrelated products and
# are unreliable as an exact-match key (e.g. "G2", "A10", "1013").
MIN_CODE_LEN = 4
# Placeholder "codes" that are not identifiers (classification's
# clean_observed_text() discards the same words).
PLACEHOLDER_CODES = {"unknown", "generic", "device", "model", "none", "null"}


def _kw(*words):
    """Whole-word keyword regex. A keyword may be followed by digits ("Tab4",
    "Watch5") but must not sit inside a longer word ("IdeaPad", "database")."""
    return re.compile(r"(?<![a-z])(?:%s)(?![a-z])" % "|".join(map(re.escape, words)))


NO_TYPE_RE = _kw(
    "watch", "band", "buds", "freebuds", "car", "auto", "automotive",
    "chromebook", "matebook", "magicbook", "book", "laptop", "notebook",
    "ideapad", "thinkpad", "glass", "glasses", "eyewear", "ipod", "simulator",
)
# Dedicated cameras that run Android ("Galaxy Camera", "Galaxy NX"). A phone
# sold on its camera ("Prime Camera Edition") is still a phone, and a bare
# "NX" is a phone line at other brands (ARROWS NX, TECNO NX).
CAMERA_RE = re.compile(r"(?<![a-z])camera(?![a-z])(?!\s+edition)|(?<![a-z])galaxy nx(?![a-z])")
NO_TYPE_ZH = ("手表", "手环", "耳机", "笔记本", "擎云", "眼镜", "车机", "路由", "音箱")
# "TV" as its own word, or glued to a known TV family ("MiTV", "LenovoTV").
# Deliberately not "DTV": that marks a phone with a TV tuner.
TV_RE = _kw("tv", "mitv", "lenovotv", "androidtv", "googletv", "smarttv", "beyondtv",
            "hitv", "appletv")
TV_MAJOR_RE = _kw("box", "stick", "bravia", "chromecast")
# Phone families sold with a TV tuner ("Galaxy S2 Duos TV"): neither a TV nor
# provably a plain phone, so no type.
TUNER_PHONE_RE = _kw("galaxy", "duos", "dtv")
TV_ZH = ("智慧屏", "电视")
TABLET_RE = _kw("tab", "tabpro", "pad", "tablet", "ipad", "matepad", "mediapad")
TABLET_ZH = ("平板",)
# Non-phone hardware from major brands with no matching ASSAS type.
OTHER_MAJOR_RE = _kw("projector", "hub", "display", "vr", "terminal", "router",
                     "speaker", "scanner", "monitor")

ANDROID_TYPES = {"phone": "Mobile (Android)", "tablet": "Tablet (Android)"}
APPLE_TYPES = {"phone": "Mobile (Apple)", "tablet": "Tablet (Apple)"}
TV_TYPE = "Smart TV / Media Device"
# classification.py labels Macs (and Mac-class Apple hardware) "Computer".
APPLE_COMPUTER_TYPE = "Computer"
# Identifier prefixes that are Mac-class hardware (MacBookPro, Macmini, iMac,
# the Developer Transition Kit, a Mac VM) and so take the Computer type.
APPLE_COMPUTER_PREFIXES = ("mac", "imac", "virtualmac", "adp")

CJK_RE = re.compile(r"[\u3000-\u9fff\uff00-\uffef]")


def classify(brand_key, name, code):
    """Device type from a marketing name; None when the name does not say.

    Major brands: Tab/Pad = tablet, TV/box = Smart TV, watch/car/laptop = no
    type, otherwise phone. Other brands: a type only when the name itself says
    Tab/Pad/Tablet/TV -- never a default phone.
    """
    if not name:
        return None
    major = brand_key in MAJOR_BRANDS
    kinds = APPLE_TYPES if brand_key == "apple" else ANDROID_TYPES
    low = name.lower()
    # Some major-brand TVs carry the TV only in the code (TCL "Smart TV").
    text = f"{low} {code.lower()}" if major else low
    if NO_TYPE_RE.search(low) or CAMERA_RE.search(low) or any(z in name for z in NO_TYPE_ZH):
        return None
    if TUNER_PHONE_RE.search(low) and TV_RE.search(low):
        return None
    if TV_RE.search(text) or any(z in name for z in TV_ZH) or (major and TV_MAJOR_RE.search(text)):
        return TV_TYPE
    if TABLET_RE.search(low) or any(z in name for z in TABLET_ZH):
        return kinds["tablet"]
    if not major or OTHER_MAJOR_RE.search(low):
        return None
    return kinds["phone"]


def strip_brand_prefix(code):
    # MobileModels' Chinese files write some codes as "HUAWEI MT1-T00".
    for prefix in ("HUAWEI ", "HONOR ", "Huawei ", "Honor "):
        if code.startswith(prefix):
            return code[len(prefix):]
    return code


# Lower rank wins when choosing the display name for a code.
SOURCE_RANK = {"apple": 0, "mobilemodels_global": 1, "google": 2, "mobilemodels_cn": 3}


def load_rows(datasets):
    """Every source row as (source, brand, code, name); brand as written."""
    rows = []
    with open(datasets / "supported_devices.csv", encoding="utf-16", newline="") as f:
        for r in csv.DictReader(f):
            rows.append(("google", r["Retail Branding"].strip(),
                         r["Model"].strip(), r["Marketing Name"].strip()))
    for fn in ("apple_ios-device-identifiers.json", "apple_tvos-device-identifiers.json"):
        with open(datasets / fn, encoding="utf-8") as f:
            for code, name in json.load(f).items():
                if code not in APPLE_SKIP:
                    rows.append(("apple", "Apple", code.strip(), name.strip()))
    line_re = re.compile(r"^((?:`[^`]+`\s*)+):\s*(.+)$")
    for fn, brand, source in (
        ("huawei_global_en.md", "Huawei", "mobilemodels_global"),
        ("honor_global_en.md", "Honor", "mobilemodels_global"),
        ("huawei_cn.md", "Huawei", "mobilemodels_cn"),
        ("honor_cn.md", "Honor", "mobilemodels_cn"),
    ):
        with open(datasets / "mobilemodels" / fn, encoding="utf-8") as f:
            for line in f:
                m = line_re.match(line.strip())
                if not m:
                    continue
                for code in re.findall(r"`([^`]+)`", m.group(1)):
                    rows.append((source, brand, strip_brand_prefix(code.strip()),
                                 m.group(2).strip()))
    return rows


def pick_name(entries):
    """English first, then a real name over a bare code, then source, then shortest."""
    def key(e):
        source, _, code, name = e
        return (bool(CJK_RE.search(name)), name.lower() == code.lower(),
                SOURCE_RANK[source], len(name), name)
    named = [e for e in entries if e[3]]
    return min(named, key=key)[3] if named else ""


def pick_brand(brands):
    """One display brand, or "" when unrelated brands share the code."""
    keys = {b.lower() for b in brands if b}
    if keys == {"huawei", "honor"}:
        return "Huawei"      # pre-2020 Honor models were Huawei-made
    if len(keys) != 1:
        return ""
    key = keys.pop()
    if key in MAJOR_BRANDS:
        return MAJOR_BRANDS[key]
    return Counter(b for b in brands if b.lower() == key).most_common(1)[0][0]


def apple_identifier_type(identifier):
    """ASSAS type for an Apple identifier, by family. Mac-class hardware takes
    the Computer type classification.py already uses; iPhone/iPad/Apple TV take
    their usual Apple form factor; everything else (iPod, Watch, HomePod,
    Vision Pro) has no ASSAS form factor and so no type."""
    low = identifier.lower()
    if low.startswith(APPLE_COMPUTER_PREFIXES):
        return APPLE_COMPUTER_TYPE
    if low.startswith("ipad"):
        return APPLE_TYPES["tablet"]
    if low.startswith("iphone"):
        return APPLE_TYPES["phone"]
    if low.startswith("appletv"):
        return TV_TYPE
    return None


def _apple_identifier_names(datasets):
    """identifier -> marketing name, from the Apple identifier datasets. A few
    identifiers carry a list of names (one code, several products); the first
    is used."""
    names = {}
    for fn in ("apple_ios-device-identifiers.json",
               "apple_tvos-device-identifiers.json",
               "apple_mac-device-identifiers.json"):
        path = datasets / fn
        if not path.exists():
            continue
        with open(path, encoding="utf-8") as f:
            for code, name in json.load(f).items():
                names[code] = name[0] if isinstance(name, list) else name
    return names


def apple_extension(datasets, existing, stats):
    """Additive Apple rows the base datasets do not already produce:

    * every Mac identifier (MacBookPro9,2, iMac13,1, ...) as a Computer row;
    * every Apple board ID (J271AP, D74AP, ...) as its own code row, resolved
      through api.ipsw.me to its identifier, then to that identifier's name
      and form factor.

    Board IDs with no real marketing name (iBridge coprocessors, whose name is
    just the identifier) are skipped. Codes already produced by the base build
    -- in `existing` -- are never touched.
    """
    names = _apple_identifier_names(datasets)
    out = []
    added = set()

    def emit(code, name, dtype):
        key = code.lower()
        if key in existing or key in added:
            return
        if len(code) < MIN_CODE_LEN or code.isdigit():
            return
        added.add(key)
        out.append((code, "Apple", name, dtype or ""))

    mac_path = datasets / "apple_mac-device-identifiers.json"
    if mac_path.exists():
        with open(mac_path, encoding="utf-8") as f:
            for code, name in json.load(f).items():
                if code in APPLE_SKIP:
                    continue
                display = name[0] if isinstance(name, list) else name
                emit(code.strip(), display.strip(), apple_identifier_type(code))
    stats["apple_mac_identifier_rows"] = len(added)

    ipsw_path = datasets / "ipsw_devices.json"
    before = len(added)
    if ipsw_path.exists():
        with open(ipsw_path, encoding="utf-8") as f:
            devices = json.load(f)
        for dev in devices:
            identifier = (dev.get("identifier") or "").strip()
            name = (names.get(identifier) or dev.get("name") or "").strip()
            if not name or name == identifier:
                continue   # no real marketing name (e.g. iBridge coprocessors)
            dtype = apple_identifier_type(identifier)
            for board in dev.get("boards") or []:
                code = (board.get("boardconfig") or "").strip().upper()
                if code:
                    emit(code, name, dtype)
    stats["apple_board_id_rows"] = len(added) - before
    return out


def build(datasets):
    rows = load_rows(datasets)
    stats = Counter(source_rows=len(rows))
    by_code = defaultdict(list)
    for source, brand, code, name in rows:
        if len(code) < MIN_CODE_LEN or code.isdigit() or code.lower() in PLACEHOLDER_CODES:
            stats["dropped_short_numeric_or_placeholder_code"] += 1
            continue
        by_code[code.lower()].append((source, brand, code, name))

    out = []
    for entries in by_code.values():
        types = {classify(b.lower(), n, c) for _, b, c, n in entries}
        if len(types) > 1:
            stats["codes_with_conflicting_types_left_blank"] += 1
        dtype = types.pop() if len(types) == 1 else None
        brand = pick_brand([b for _, b, _, _ in entries])
        if not brand:
            stats["codes_shared_by_brands_left_blank"] += 1
        code = min(e[2] for e in entries)
        out.append((code, brand, pick_name(entries), dtype or ""))
    stats["rows_from_base_datasets"] = len(out)
    existing = {r[0].lower() for r in out}
    out.extend(apple_extension(datasets, existing, stats))
    out.sort(key=lambda r: (r[0].lower(), r[0]))
    stats["output_rows"] = len(out)
    return out, stats


def main():
    ap = argparse.ArgumentParser(description="Rebuild device_models.csv")
    ap.add_argument("datasets", type=Path, help="directory holding the downloaded datasets")
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    args = ap.parse_args()

    out, stats = build(args.datasets)
    with open(args.out, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["code", "brand", "name", "type"])
        w.writerows(out)
    for k in sorted(stats):
        print(f"{k}: {stats[k]}")
    for k, v in Counter(r[3] or "(no type)" for r in out).most_common():
        print(f"type {k}: {v}")
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
