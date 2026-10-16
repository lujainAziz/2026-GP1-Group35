# Device model database

`appliance/model_db.py` maps an exact device model code (for example
`SM-S948B`, `iPhone19,2`, `DBY-W09`) to a brand, a marketing name and an ASSAS
device type. It is a **fallback only**: the existing tables in
`classification.py` (`MODEL_ALIASES`, `MODEL_TYPE_HINTS`, `MODEL_VENDOR_HINTS`,
`HUAWEI_MODEL_CODE_HINTS`) always run first, and the database is consulted only
when they return nothing. It uses the same scores as the calling path; there
are no new `SCORES` keys.

## Where it is used

| Path | What the database adds | Score |
|---|---|---|
| `classification.normalize_model` (mDNS / UPnP / WS-Discovery / ONVIF model fields) | type, when `type_from_model` has none | caller's model score |
| `classification.vendor_from_model` | vendor, when `MODEL_VENDOR_HINTS` has none | n/a |
| `classification.type_from_huawei_vendor_class` (`HUAWEI:android:<CODE>`) | type by code prefix (`ANA` covers every `ANA-*`), when `HUAWEI_MODEL_CODE_HINTS` has none; no type if that prefix's models disagree | `SCORES["dhcp_vendor"]` |
| `discovery.update_device` | stores a bare code as `Marketing Name (CODE)`; a value that is already a name is never changed | unchanged |
| `discovery` DHCP vendor class | a model name such as `HUAWEI MatePad 11 (DBY)`, or `HUAWEI (DBY)` when the models share no family name, only when the packet carried no model | `SCORES["dhcp_vendor"]` (any real mDNS/UPnP model replaces it) |
| `discovery.rescore_stored_evidence` and the second-pass recompute | a stored `Name (CODE)` is typed by its CODE, so the type matches what was observed | `SCORES["model"]` |

It is **never** used on free-text hostnames: `type_from_hostname`,
`vendor_from_model_in_hostname` and `infer_type_from_text` do not call it.

The mobile app shows the `model` field only as a fallback device name
(`Device.detectedName`: user name, then hostname, then model), so a named
model such as `Galaxy S26 Ultra (SM-S948B)` appears there for devices without
a hostname. The app itself is unchanged.

## Files

| File | Purpose |
|---|---|
| `appliance/device_models.csv` | Generated. Columns `code,brand,name,type`; one row per code. |
| `appliance/build_device_models.py` | Rebuilds the CSV from the downloaded datasets. |
| `appliance/device_models_manual.csv` | Verified devices missing from the datasets. Columns `code,brand,name,type,source`; every row cites a source URL. Overlaid at runtime (wins over the generated file) so it survives a rebuild. |
| `appliance/model_db.py` | Lookup module. Loads both CSVs lazily on the first lookup. |
| `appliance/test_model_db.py` | Tests. |

## Rebuilding

Download the sources below into one directory (outside the repo), then:

```
python appliance/build_device_models.py D:\GP-DATA\datasets
```

Layout expected by the script: `supported_devices.csv`,
`apple_ios-device-identifiers.json`, `apple_tvos-device-identifiers.json`, and
`mobilemodels/{huawei_cn,huawei_global_en,honor_cn,honor_global_en}.md`.

## Build rules

- Codes shorter than 4 characters, purely numeric, or placeholders
  (`unknown`, `generic`, ...) are dropped: they are shared by unrelated
  products. Apple simulator identifiers (`i386`, `x86_64`, `arm64`) are dropped.
- Type from the marketing name. **Major brands** (Samsung, Apple, Google,
  Huawei, Honor, Xiaomi, Redmi, POCO, OPPO, OnePlus, vivo, iQOO, realme,
  Motorola, Nokia, HMD, Sony, LG, Lenovo, ZTE, nubia, ASUS, TECNO, Infinix,
  itel, Nothing, CMF by Nothing, Fairphone, Meizu, TCL, Sharp, Kyocera,
  Fujitsu, BlackBerry, HTC):
  Tab/Pad/Tablet/平板 = tablet; TV/box/stick/BRAVIA/Chromecast/智慧屏 = Smart TV;
  watch/band/buds/car/Chromebook/laptop/MateBook/iPod/手表/手环 = no type;
  projector/hub/display/VR and similar = no type; otherwise phone.
  A phone family with a TV tuner ("Galaxy S2 Duos TV", "DTV") gets no type.
- **Other brands**: vendor and name only; a type only when the name itself says
  Tab/Pad/Tablet/TV. Never a default phone.
- A code listed with different types gets no type; a code shared by unrelated
  brands gets no brand (Huawei + Honor is kept as Huawei).
- Display name: English preferred, then a real name over a bare code, then
  source (Apple, MobileModels global, Google, MobileModels China), then shortest.

## Sources and licenses

| Source | Used for | License |
|---|---|---|
| Google Play supported devices, <https://storage.googleapis.com/play_public/supported_devices.csv> (linked from <https://support.google.com/googleplay/answer/1727131>) | Android devices, all brands | No license stated; published by Google for reference. Subject to the Google Play Terms of Service. |
| kyle-seongwoo-jun/apple-device-identifiers, <https://github.com/kyle-seongwoo-jun/apple-device-identifiers> | iOS / tvOS identifiers | MIT, Copyright (c) 2021 Kyle Seongwoo Jun |
| KHwang9883/MobileModels, <https://github.com/KHwang9883/MobileModels> (`brands/huawei_cn.md`, `huawei_global_en.md`, `honor_cn.md`, `honor_global_en.md`) | Huawei and Honor model codes | CC BY-NC-SA 4.0. Used here for a non-commercial university project, with attribution. Data derived from it (Huawei/Honor rows of `device_models.csv`) is shared under the same license. |
| Manual rows | Newest Apple devices missing from the datasets | Facts (identifier ↔ name), each row cites its source: EveryMac (<https://everymac.com>) and ipsw.me (<https://ipsw.me>) |

**Attribution:** Huawei and Honor model data © KHwang9883 and MobileModels
contributors, licensed under
[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).

## Cost

About 44,000 codes and 1.6 MB on disk. Loaded on the first lookup, not at
startup. Measured on a development PC: about 0.15 s and 13 MB resident (25 MB
peak while loading). A Raspberry Pi is expected to be several times slower on
load (not measured). Lookups are
dictionary hits (about 1 µs).
