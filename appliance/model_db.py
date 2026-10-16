"""Model-code database: exact device model code -> brand, marketing name, type.

A fallback only. classification.py consults it after its own tables
(MODEL_ALIASES, MODEL_TYPE_HINTS, MODEL_VENDOR_HINTS, HUAWEI_MODEL_CODE_HINTS)
have returned nothing, and only for structured model fields (mDNS/UPnP/
WS-Discovery model, stored model column) or the Huawei DHCP vendor class --
never for free-text hostnames.

Data: device_models.csv (built by build_device_models.py from public
datasets, see docs/DEVICE_MODELS.md) plus device_models_manual.csv (verified
devices missing from those datasets; each row cites a source URL). Both load
lazily on the first lookup, so importing this module costs nothing.
"""
import csv
import re
import threading
from collections import namedtuple
from pathlib import Path

DATA_PATH = Path(__file__).with_name("device_models.csv")
MANUAL_PATH = Path(__file__).with_name("device_models_manual.csv")

Entry = namedtuple("Entry", "code brand name type")

# Same guard as build_device_models.py: short or numeric codes are shared by
# unrelated products and are not trustworthy as an exact-match key.
MIN_CODE_LEN = 4

# Brand -> vendor string, aligned with classification.MODEL_VENDOR_HINTS where
# that table already names the manufacturer (e.g. "Samsung Electronics").
VENDOR_NAMES = {
    "samsung": "Samsung Electronics",
    "apple": "Apple Inc.",
    "redmi": "Xiaomi",
    "poco": "Xiaomi",
    "lge": "LG Electronics",
}

_CJK_RE = re.compile(r"[　-鿿＀-￯]")

_lock = threading.Lock()
_by_code = None      # code.lower() -> Entry
_by_prefix = None    # Huawei/Honor code prefix.lower() -> (type or None, display name)


def _read(path):
    if not path.exists():
        return []
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


# Connectivity/SIM variant words, not part of a family name.
_VARIANT_WORDS = {"wi-fi", "wifi", "lte", "4g", "5g", "dual", "single", "sim"}


def _family_display(prefix, entries):
    """Common English family name for a Huawei/Honor prefix, e.g.
    "HUAWEI MatePad (DBY)"; "HUAWEI (DBY)" when the names share nothing or
    the prefix covers different kinds of device (phone and band)."""
    brands = {e.brand for e in entries if e.brand}
    label = brands.pop().upper() if len(brands) == 1 else "HUAWEI"
    if len({e.type for e in entries}) > 1:
        return f"{label} ({prefix.upper()})"
    words = []
    for e in entries:
        if not e.name or _CJK_RE.search(e.name):
            continue
        tokens = e.name.split()
        if tokens and tokens[0].upper() in ("HUAWEI", "HONOR"):
            tokens = tokens[1:]
        words.append(tokens)
    common = []
    if words:
        for column in zip(*words):
            if len({w.lower() for w in column}) != 1:
                break
            common.append(column[0])
    while common and common[-1].lower() in _VARIANT_WORDS:
        common.pop()
    family = " ".join([label] + common)
    return f"{family} ({prefix.upper()})"


def _load():
    global _by_code, _by_prefix
    with _lock:
        if _by_code is not None:
            return
        intern = {}
        by_code = {}
        for path in (DATA_PATH, MANUAL_PATH):     # manual rows win
            for row in _read(path):
                code = (row.get("code") or "").strip()
                if not code:
                    continue
                brand = intern.setdefault(row.get("brand") or "", row.get("brand") or "")
                dtype = intern.setdefault(row.get("type") or "", row.get("type") or "")
                by_code[code.lower()] = Entry(code, brand, (row.get("name") or "").strip(),
                                              dtype or None)
        groups = {}
        for entry in by_code.values():
            if entry.brand.lower() in ("huawei", "honor") and "-" in entry.code:
                groups.setdefault(entry.code.split("-", 1)[0].lower(), []).append(entry)
        by_prefix = {}
        for prefix, entries in groups.items():
            types = {e.type for e in entries}
            by_prefix[prefix] = (types.pop() if len(types) == 1 else None,
                                 _family_display(prefix, entries))
        _by_code, _by_prefix = by_code, by_prefix


def _usable(code):
    return len(code) >= MIN_CODE_LEN and not code.isdigit()


def _trailing_group(text):
    """Contents of the final balanced "(...)" group, so "LG Q7+ (LM-Q610(FGN))"
    gives "LM-Q610(FGN)"; None when the text does not end with ")"."""
    if not text.endswith(")"):
        return None
    depth = 0
    for i in range(len(text) - 1, -1, -1):
        if text[i] == ")":
            depth += 1
        elif text[i] == "(":
            depth -= 1
            if depth == 0:
                return text[i + 1:-1].strip()
    return None


def lookup(model):
    """Entry for an exact model code (case-insensitive), or None.

    Also accepts the "Name (CODE)" form produced by display_model(), so a
    model stored that way resolves to the same entry.
    """
    if not model:
        return None
    _load()
    text = " ".join(model.split())
    if _usable(text):
        entry = _by_code.get(text.lower())
        if entry:
            return entry
    code = _trailing_group(text)
    if code and _usable(code):
        return _by_code.get(code.lower())
    return None


def stored_code(model):
    """The model code behind a stored model value.

    A stored "Name (CODE)" display value gives back CODE, so re-classifying
    stored evidence sees exactly what was observed; anything else (a raw code,
    an unknown value, a real name) is returned unchanged.
    """
    entry = lookup(model)
    if entry and " ".join(model.split()).lower() != entry.code.lower():
        return entry.code
    return model


def type_for_model(model):
    entry = lookup(model)
    return entry.type if entry else None


def model_from_hostname(hostname):
    """Match a whole model code, never an arbitrary substring or brand name.

    Hostnames are user-editable; callers must use a lower score than a
    structured model field. Generic Android OS IDs do not identify hardware.
    """
    if not hostname:
        return None
    text = hostname.strip().rstrip('.')
    if text.lower().endswith('.local'):
        text = text[:-6]
    entry = lookup(text)
    if not entry or not entry.brand or text.casefold() != entry.code.casefold():
        return None
    return entry.code if any(c.isdigit() for c in text) else None


def vendor_for_model(model):
    entry = lookup(model)
    if not entry or not entry.brand:
        return None
    return VENDOR_NAMES.get(entry.brand.lower(), entry.brand)


def display_model(model):
    """"Marketing Name (CODE)" for a raw model code, or None.

    None when the code is unknown, the dataset has no name, or the observed
    text is already a name rather than a bare code (it is never overwritten).
    """
    if not model:
        return None
    text = " ".join(model.split())
    if not _usable(text):
        return None
    _load()
    entry = _by_code.get(text.lower())
    if not entry or not entry.name:
        return None
    if entry.name.lower() == text.lower():
        return None              # "Pixel 10" is already its own name
    # Always keep "(CODE)" so a stored display name resolves again by lookup().
    return f"{entry.name} ({entry.code})"


def type_for_huawei_code(code):
    """Type for a Huawei vendor-class model code by its prefix ("ANA" covers
    every "ANA-*"); None when unknown or when that prefix's models disagree."""
    if not code:
        return None
    _load()
    found = _by_prefix.get(code.strip().split("-", 1)[0].lower())
    return found[0] if found else None


def model_from_huawei_vendor_class(vendor_class):
    """Model display name from "HUAWEI:android:<CODE>", or None.

    "HUAWEI P60 Pro (MNA)" when the prefix's models share a family name,
    otherwise "HUAWEI (DBY)"-style; None for non-Huawei or unknown prefixes.
    """
    if not vendor_class:
        return None
    lowered = vendor_class.strip().lower()
    if not lowered.startswith("huawei:"):
        return None
    code = lowered.rsplit(":", 1)[-1].strip()
    if not code:
        return None
    _load()
    found = _by_prefix.get(code.split("-", 1)[0])
    return found[1] if found else None


def is_loaded():
    return _by_code is not None
