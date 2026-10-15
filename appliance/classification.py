#!/usr/bin/env python3
"""Pure classification logic for ASSAS discovery.

Scoring table, evidence-hint tables, and the pure functions that map observed
evidence (hostnames, vendors, DNS/mDNS queries, DHCP signatures, TCP SYN
fingerprints, model strings) to device types. No sockets, DB, or module-global
runtime state; discovery.py imports these names so existing references resolve.
"""
import re

from scapy.all import IP, TCP


SCORES = {
    "gateway": 100,
    "model": 95,
    "hostname": 90,
    "service": 85,
    "lldp": 90,
    "port": 75,
    "dhcp_vendor": 65,
    "dhcp": 60,
    "broadcast_name": 50,
    "weak_service": 45,
    # An OS-only signal (e.g. the "android" token in a hostname, DHCP vendor
    # class, or OS connectivity-check domain). It identifies the operating
    # system but NOT the form factor, so it sits below every form-factor signal
    # and, crucially, below "dhcp" (60) so a genuine phone/stack fingerprint
    # still wins. Always overridden by real evidence.
    "os_hint": 40,
    # An mDNS *query* for a service the device wants is a weak OS signal
    # (below weak_service): it only nudges an otherwise-unknown device and is
    # always overridden by real evidence.
    "mdns_query": 40,
    # p0f-style TCP SYN OS fingerprint: a weak OS signal, always overridden by
    # real evidence.
    "syn_fp": 40,
    "vendor": 35,
}

# Protocol/service semantics are preferred over brand-only guesses.
# These signatures work across many vendors and device generations.
SERVICE_HINTS = [
    # Printing / scanning
    (b"_printer._tcp", "Printer"),
    (b"_ipp._tcp", "Printer"),
    (b"_ipps._tcp", "Printer"),
    (b"_pdl-datastream._tcp", "Printer"),
    (b"_scanner._tcp", "Printer / Scanner"),
    (b"_uscan._tcp", "Printer / Scanner"),
    (b"_uscans._tcp", "Printer / Scanner"),
    (b"printbasic", "Printer"),
    (b"printdevice", "Printer"),
    (b"printerservice", "Printer"),
    (b"scanservice", "Printer / Scanner"),

    # Cameras / video surveillance -- EXPLICIT ONVIF device types and explicit
    # camera identifiers only; all high-confidence (SCORES["service"]). Generic
    # onvif/onvif.org is intentionally NOT here -- it only proves "some ONVIF
    # device" and lives in WEAK_SERVICE_HINTS -> Video Surveillance Device at a
    # lower score, so later explicit NVT/NVS evidence (85 > 45) refines it.
    #   NVS (storage)      -> Network Video Recorder
    #   NVT (transmitter)  -> Security Camera
    #   ip/network camera  -> Security Camera
    (b"networkvideostorage", "Network Video Recorder"),
    (b"network_video_storage", "Network Video Recorder"),
    (b"networkvideotransmitter", "Security Camera"),
    (b"network_video_transmitter", "Security Camera"),
    (b"ipcamera", "Security Camera"),
    (b"networkcamera", "Security Camera"),

    # TV / streaming / media
    (b"mediarenderer", "Smart TV / Media Device"),
    (b"mediaserver", "Smart TV / Media Device"),
    (b"_googlecast._tcp", "Smart TV / Media Device"),
    (b"dial-multiscreen-org", "Smart TV / Media Device"),
    (b"roku", "Smart TV / Media Device"),
    (b"webos", "Smart TV / Media Device"),
    (b"bravia", "Smart TV / Media Device"),

    # Smart speakers / audio
    (b"_spotify-connect._tcp", "Smart Speaker / Media Device"),
    (b"sonos", "Smart Speaker / Media Device"),

    # Computers / servers / storage
    (b"_workstation._tcp", "Computer"),
    (b"_adisk._tcp", "NAS / Server"),
    (b"synology", "NAS / Server"),
    (b"qnap", "NAS / Server"),

    # Network infrastructure
    (b"internetgatewaydevice", "Router"),
    (b"wanipconnection", "Router"),
    (b"wandevice", "Router"),

    # Smart-home / IoT
    (b"_homekit._tcp", "IoT Device"),
    (b"_hap._tcp", "IoT Device"),
    (b"_matter._tcp", "IoT Device"),
    (b"_matterc._udp", "IoT Device"),
    (b"philips hue", "IoT Device"),

    # Consoles
    (b"xbox", "Game Console"),
    (b"playstation", "Game Console"),
    (b"nintendo", "Game Console"),
]

# These services are useful clues, but not enough on their own for a hard type.
WEAK_SERVICE_HINTS = [
    (b"_airplay._tcp", "Apple Device"),
    (b"_raop._tcp", "Apple Device"),
    (b"_smb._tcp", "Computer / Server"),
    (b"_ssh._tcp", "Computer / Server"),
    # Generic ONVIF only proves "some ONVIF device" (camera/recorder/encoder/
    # display). Broad + low-confidence (weak_service) so an explicit ONVIF
    # device type (SCORES["service"]) refines it to Camera or NVR.
    (b"onvif.org", "Video Surveillance Device"),
    (b"onvif", "Video Surveillance Device"),
]

# A port hint is used only on a SYN+ACK sent BY the device.
PORT_HINTS = {
    # RTSP alone cannot separate a camera from an NVR/recorder or any other
    # RTSP server, so port evidence yields only the broad surveillance category.
    554: "Video Surveillance Device",
    8554: "Video Surveillance Device",
    515: "Printer",
    631: "Printer",
    9100: "Printer",
    3389: "Computer",
    445: "Computer / Server",
    5900: "Computer",
    8008: "Smart TV / Media Device",
    8009: "Smart TV / Media Device",
    32400: "Smart TV / Media Device",
}

# Ports consumed by the active-probe classifier, which sees the whole SET of
# open ports (unlike the passive single SYN+ACK path).
CAMERA_PORTS = {554, 8554}           # RTSP: broad surveillance evidence
SURVEILLANCE_MGMT_PORTS = {8000}     # mgmt/SDK (e.g. Hikvision): corroborating only


def surveillance_type_from_ports(open_ports):
    """Return "Video Surveillance Device" if RTSP is open, else None.

    Port evidence alone cannot tell a standalone camera from an NVR/recorder or
    any other RTSP server, so the only port-level verdict is the broad
    surveillance category -- never Security Camera and never NVR. A management
    port such as 8000 WITHOUT RTSP is just http-alt and yields None; with RTSP
    it only corroborates (it does not change the verdict) and is recorded in the
    evidence string. Explicit identity (model/hostname/ONVIF) refines the type
    later via higher-scored evidence.
    """
    ports = set()
    for p in open_ports:
        try:
            ports.add(int(p))
        except (TypeError, ValueError):
            continue
    if ports & CAMERA_PORTS:
        return "Video Surveillance Device"
    return None

# DHCP Parameter Request List (option 55) signatures are supporting evidence only.
# Matched tolerantly (see type_from_dhcp_signature): a signature matches when it
# is an ordered subsequence of the observed PRL and covers >= 75% of it, so OS
# updates that add options (e.g. 114, or 108 / RFC 8925 IPv6-Only Preferred)
# still match. New entries below the original set were derived empirically from
# param-request-lists observed on devices already identified at high confidence
# on this network (not guessed from memory).
#
# The Android option-55 list is sent identically by Android phones, tablets, TVs
# and set-top boxes, so it identifies only the OS -> "Android Device", merged at
# SCORES["os_hint"] (not a form factor). Apple/Windows fingerprints keep their
# type and are merged at SCORES["dhcp"].
DHCP_SIGNATURES = {
    (1, 121, 3, 6, 15, 119, 252): "Apple Device",
    (1, 121, 3, 6, 15, 119, 252, 95, 44, 46): "Apple Device",
    (1, 3, 6, 15, 26, 28, 51, 58, 59, 43): "Android Device",
    (1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114): "Android Device",
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252): "Computer",
    (1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43): "Computer",
    (1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42): "Computer",
    # Confirmed on this network: modern iOS/iPadOS (2 devices identified by mDNS
    # model at class_score 90/100).
    (1, 121, 3, 6, 15, 108, 114, 119, 162, 252): "Apple Device",
    # Confirmed on this network: Windows PRL on the Dell laptop "lujain".
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252, 114): "Computer",
}

# DHCP vendor class (option 60) hints -- ORDERED, first substring match wins, so
# more-specific entries MUST precede generic ones. Restricted to unambiguous
# strings only (never bare "MSFT"/"udhcp"/"dhcpcd", which are shared). Merged at
# SCORES["dhcp_vendor"] (65) -- above bare-vendor but below service/model, so a
# real TV/service advertisement still overrides android-dhcp (also sent by
# Android TV boxes).
VENDOR_CLASS_HINTS = [
    ("xbox", "Game Console"),            # specific -- must precede "msft 5.0"
    ("msft 5.0", "Computer"),            # Windows DHCP client (generic, last)
]
# "android-dhcp-..." is sent by Android phones, tablets, TVs and set-top boxes
# alike, so it only identifies the OS, never the form factor. It is handled as
# an OS token (see OS_HINTS / type_from_os_hint) at SCORES["os_hint"], NOT here.

# mDNS *query* service-types -> weak OS hint. A device multicasts queries for
# services it wants to USE, visible even when only its broadcasts reach us. Only
# services that identify the *querier* as an Apple device belong here.
#
# Restricted to the Apple peer-to-peer Continuity services (_companion-link =
# Continuity, _rdlink = Rapport/remote-display): these are Apple-proprietary and
# only Apple's own OS queries them. Deliberately EXCLUDED, because querying them
# means "I want to connect to an Apple device", not "I am one":
#   _apple-mobdev2  -- iTunes/Apple Devices for Windows queries it to sync.
#   _airplay/_raop  -- Windows/Android casting apps query these to find receivers.
#   _googlecast     -- not OS-discriminating (iPhones w/ YouTube, desktop Chrome).
# Only the matched service-type needle is stored.
MDNS_QUERY_HINTS = [
    ("_companion-link._tcp", "Apple Device"),  # Apple Continuity -- Apple-only
    ("_rdlink._tcp", "Apple Device"),          # Apple Rapport/remote-display -- Apple-only
]

# Querying an Apple-exclusive Continuity service also infers the querier's
# vendor. Same needle set as the Apple-only entries above; used only as a weak,
# gated inference (see vendor_from_mdns_query_needle() and its handle() call
# site, which requires the source MAC to have no real OUI vendor). Displayed as
# "Apple Inc. (inferred)" -- never presented as OUI ground truth.
MDNS_QUERY_VENDOR_HINTS = {
    "_companion-link._tcp": "Apple Inc.",
    "_rdlink._tcp": "Apple Inc.",
}

# DNS query substrings are weak, easily-spoofed evidence -- only the matched
# needle (never the full query name) is ever stored or logged; see
# type_from_dns_query() and its call site in handle().
DOMAIN_HINTS = [
    # Apple -- more specific OS-level endpoints must come before the general
    # "apple.com"/"icloud.com" entries, since _first_match() returns the first
    # substring hit and captive.apple.com/mesu.apple.com contain "apple.com".
    ("captive.apple.com", "Apple Device"),
    ("mesu.apple.com", "Apple Device"),
    ("apple.com", "Apple Device"),
    ("icloud.com", "Apple Device"),
    ("aaplimg.com", "Apple Device"),
    ("mzstatic.com", "Apple Device"),
    ("apple-dns.net", "Apple Device"),

    # Android connectivity-check / Play Services infrastructure. These prove the
    # OS (Android), not the form factor -- Android TVs and boxes hit the same
    # endpoints -- so they map to the neutral OS label and are scored at
    # SCORES["os_hint"] by the caller (see OS_LEVEL_TYPES).
    ("connectivitycheck.gstatic.com", "Android Device"),
    ("android.clients.google.com", "Android Device"),
    ("play.googleapis.com", "Android Device"),

    # Windows Network Connectivity Status Indicator
    ("msftconnecttest.com", "Computer"),
    ("msftncsi.com", "Computer"),

    ("samsungcloudsolution", "Smart TV / Media Device"),
    ("samsungotn", "Smart TV / Media Device"),
    ("samsungtvpaid", "Smart TV / Media Device"),
    ("roku", "Smart TV / Media Device"),
    ("nest.com", "Security Camera"),
    ("ring.com", "Security Camera"),
    ("wyze", "Security Camera"),
    ("tuya", "IoT Device"),
    ("smartthings", "IoT Device"),
    ("xiaomi", "IoT Device"),
    ("hpeprint", "Printer"),
    ("brother.com", "Printer"),
    ("epson", "Printer"),
    ("windowsupdate", "Computer"),
    ("playstation", "Game Console"),
    ("xboxlive", "Game Console"),
    ("nintendo", "Game Console"),
]

HOSTNAME_HINTS = [
    ("iphone", "Mobile (Apple)"),
    ("ipad", "Tablet (Apple)"),
    # Bare "android" is an OS token, not a form factor -- handled weakly via
    # OS_HINTS. Only phone-specific families are a form-factor signal here.
    ("galaxy", "Mobile (Android)"),
    ("z-flip", "Mobile (Android)"),
    ("z-fold", "Mobile (Android)"),
    ("redmi", "Mobile (Android)"),
    ("pixel", "Mobile (Android)"),
    ("macbook", "Computer"),
    ("imac", "Computer"),
    ("desktop", "Computer"),
    ("laptop", "Computer"),
    ("-pc", "Computer"),
    ("printer", "Printer"),
    ("laserjet", "Printer"),
    ("officejet", "Printer"),
    ("deskjet", "Printer"),
    ("pixma", "Printer"),
    ("brother", "Printer"),
    ("epson", "Printer"),
    # Recorder identity must win over the generic camera needles below.
    ("network video recorder", "Network Video Recorder"),
    ("nvr", "Network Video Recorder"),
    ("dvr", "Network Video Recorder"),
    ("camera", "Security Camera"),
    ("ipcam", "Security Camera"),
    # Brand-only hostname text (e.g. "reolink") is NOT classified here: at the
    # hostname score (90) it would block later explicit ONVIF NVT/NVS (85). A
    # bare surveillance brand is handled weakly via VENDOR_HINTS instead.
    ("roku", "Smart TV / Media Device"),
    ("chromecast", "Smart TV / Media Device"),
    ("bravia", "Smart TV / Media Device"),
    ("webos", "Smart TV / Media Device"),
    ("smart-tv", "Smart TV / Media Device"),
    ("appletv", "Smart TV / Media Device"),
    ("homepod", "Smart Speaker / Media Device"),
    ("sonos", "Smart Speaker / Media Device"),
    ("playstation", "Game Console"),
    ("ps4", "Game Console"),
    ("ps5", "Game Console"),
    ("xbox", "Game Console"),
    ("nintendo", "Game Console"),
    ("synology", "NAS / Server"),
    ("qnap", "NAS / Server"),
    ("tl-sg105e", "Managed Switch"),
    ("tl-wr802n", "Access Point"),
    ("assas access point", "Access Point"),
    ("router", "Router"),
    ("gateway", "Router"),
]

# OS-level tokens that identify only the operating system, never the form
# factor. "android" appears in the hostnames, DHCP vendor classes
# ("android-dhcp-...") and OS connectivity domains of Android phones, tablets,
# TVs and set-top boxes alike. Classified at SCORES["os_hint"] (weak) so that
# any real form-factor evidence -- a TV service, a TV/box model, or a
# phone/tablet model/hostname family -- overrides it. Match is substring,
# lowercased (see type_from_os_hint()).
OS_HINTS = [
    ("android", "Android Device"),
]

# The set of verdicts that are OS-only. A caller that resolves one of these
# from any table must enter it at SCORES["os_hint"], regardless of which table
# produced it (e.g. an Android OS connectivity domain in DOMAIN_HINTS).
OS_LEVEL_TYPES = frozenset(dtype for _, dtype in OS_HINTS)

# Vendor-only classification is intentionally conservative.  OUI lookup still
# identifies the manufacturer for thousands of vendors, but type is assigned
# only when the manufacturer is strongly associated with one device class.
VENDOR_HINTS = [
    ("roku", "Smart TV / Media Device"),
    ("sonos", "Smart Speaker / Media Device"),
    # A surveillance brand alone (these vendors ship cameras AND NVRs/DVRs) is
    # not enough to decide camera vs recorder -> broad category only, at the weak
    # vendor score (35) so explicit ONVIF/hostname/model evidence refines it.
    ("hikvision", "Video Surveillance Device"),
    ("hangzhou hikvision", "Video Surveillance Device"),
    ("dahua", "Video Surveillance Device"),
    ("axis communications", "Video Surveillance Device"),
    ("reolink", "Video Surveillance Device"),
    ("brother", "Printer"),
    ("epson", "Printer"),
    ("lexmark", "Printer"),
    ("synology", "NAS / Server"),
    ("qnap", "NAS / Server"),
    ("espressif", "IoT Device"),
    ("tuya", "IoT Device"),
    ("nintendo", "Game Console"),
    ("sony interactive entertainment", "Game Console"),
    ("dell", "Computer"),
    ("lenovo", "Computer"),
    ("intel corporate", "Computer"),
    ("asustek", "Computer"),
    ("micro-star", "Computer"),
    ("ubiquiti", "Network Device"),
    ("aruba", "Network Device"),
    ("mikrotik", "Network Device"),
    ("juniper", "Network Device"),
    ("cisco systems", "Network Device"),
]

# Known board identifiers observed in ASSAS testing.  These aliases are
# conveniences only; every other vendor/model is handled generically below.
MODEL_ALIASES = {
    "d211ap": ("iPhone 8 Plus", "Mobile (Apple)"),
    "j171aap": ("iPad (8th generation)", "Tablet (Apple)"),
    "j407ap": ("iPad Air (5th generation)", "Tablet (Apple)"),
    "j537ap": ("iPad Air 13-inch (M2)", "Tablet (Apple)"),
    "j637ap": ("iPad Air 13-inch (M3)", "Tablet (Apple)"),
}

MODEL_TYPE_HINTS = [
    ("iphone", "Mobile (Apple)"),
    ("ipad", "Tablet (Apple)"),
    ("apple tv", "Smart TV / Media Device"),
    ("appletv", "Smart TV / Media Device"),
    ("galaxy tab", "Tablet (Android)"),  # tablet -- must precede "galaxy"
    ("galaxy", "Mobile (Android)"),
    ("z-flip", "Mobile (Android)"),
    ("z-fold", "Mobile (Android)"),
    ("redmi", "Mobile (Android)"),
    # Samsung Galaxy PHONE model-code prefixes only (SM-S/A/G/F/N). Tablet
    # prefixes (SM-T/X/P) are deliberately excluded so tablets are never
    # classified as phones.
    ("sm-s", "Mobile (Android)"),
    ("sm-a", "Mobile (Android)"),
    ("sm-g", "Mobile (Android)"),
    ("sm-f", "Mobile (Android)"),
    ("sm-n", "Mobile (Android)"),
    ("pixel", "Mobile (Android)"),
    ("chromecast", "Smart TV / Media Device"),
    ("roku", "Smart TV / Media Device"),
    ("bravia", "Smart TV / Media Device"),
    ("webos", "Smart TV / Media Device"),
    ("oled", "Smart TV / Media Device"),
    ("qled", "Smart TV / Media Device"),
    # Android-based TVs / set-top boxes. These are form-factor evidence (a TV),
    # unlike the bare "android" OS token.
    ("android tv", "Smart TV / Media Device"),
    ("androidtv", "Smart TV / Media Device"),
    ("mitv", "Smart TV / Media Device"),
    ("mi tv", "Smart TV / Media Device"),
    ("mibox", "Smart TV / Media Device"),
    ("mi box", "Smart TV / Media Device"),
    ("shield", "Smart TV / Media Device"),
    ("fire tv", "Smart TV / Media Device"),
    ("firetv", "Smart TV / Media Device"),
    ("laserjet", "Printer"),
    ("officejet", "Printer"),
    ("deskjet", "Printer"),
    ("pixma", "Printer"),
    ("ecotank", "Printer"),
    ("workforce", "Printer"),
    ("imageclass", "Printer"),
    # Explicit recorder/camera wording is classified; brand-only model text is
    # NOT (at the model score 95 it would block later explicit ONVIF NVT/NVS at
    # 85). A bare surveillance brand is handled weakly via VENDOR_HINTS instead.
    ("network video recorder", "Network Video Recorder"),
    ("nvr", "Network Video Recorder"),
    ("dvr", "Network Video Recorder"),
    ("ip camera", "Security Camera"),
    ("network camera", "Security Camera"),
    ("synology", "NAS / Server"),
    ("qnap", "NAS / Server"),
    ("playstation", "Game Console"),
    ("ps4", "Game Console"),
    ("ps5", "Game Console"),
    ("xbox", "Game Console"),
    ("nintendo", "Game Console"),
    ("homepod", "Smart Speaker / Media Device"),
    ("sonos", "Smart Speaker / Media Device"),
]

# Passive model extraction from common mDNS TXT / UPnP / vendor fields.
# The patterns are generic and not tied to one manufacturer.
MODEL_PATTERNS = [
    ("UPnP modelName", 100, re.compile(rb"<modelName>\s*([^<]{2,120})\s*</modelName>", re.I)),
    ("UPnP modelNumber", 95, re.compile(rb"<modelNumber>\s*([^<]{2,120})\s*</modelNumber>", re.I)),
    ("mDNS model", 95, re.compile(rb"(?:^|[\x00-\x20;,])model=([^;\x00-\x1f\x7f]{2,120})", re.I)),
    ("mDNS md", 92, re.compile(rb"(?:^|[\x00-\x20;,])md=([^;\x00-\x1f\x7f]{2,120})", re.I)),
    ("printer ty", 95, re.compile(rb"(?:^|[\x00-\x20;,])ty=([^;\x00-\x1f\x7f]{2,120})", re.I)),
    ("printer product", 92, re.compile(rb"(?:^|[\x00-\x20;,])product=\(?([^;\x00-\x1f\x7f]{2,120}?)\)?", re.I)),
    ("USB model", 95, re.compile(rb"(?:^|[\x00-\x20;,])usb_MDL=([^;\x00-\x1f\x7f]{2,120})", re.I)),
    ("Apple board", 90, re.compile(rb"(?:^|[\x00-\x20;,])am=([A-Za-z0-9._,+-]{2,80})", re.I)),
]

MANUFACTURER_PATTERNS = [
    re.compile(rb"<manufacturer>\s*([^<]{2,120})\s*</manufacturer>", re.I),
    re.compile(rb"<(?:[A-Za-z0-9_.-]+:)?Manufacturer>\s*([^<]{2,120})\s*</(?:[A-Za-z0-9_.-]+:)?Manufacturer>", re.I),
    re.compile(rb"(?:^|[\x00-\x20;,])manufacturer=([^;\x00-\x1f\x7f]{2,120})", re.I),
    re.compile(rb"(?:^|[\x00-\x20;,])usb_MFG=([^;\x00-\x1f\x7f]{2,120})", re.I),
    re.compile(rb"(?:^|[\x00-\x20;,])mfg=([^;\x00-\x1f\x7f]{2,120})", re.I),
]

FRIENDLY_NAME_PATTERNS = [
    re.compile(rb"<friendlyName>\s*([^<]{2,120})\s*</friendlyName>", re.I),
    re.compile(rb"<(?:[A-Za-z0-9_.-]+:)?FriendlyName>\s*([^<]{2,120})\s*</(?:[A-Za-z0-9_.-]+:)?FriendlyName>", re.I),
    re.compile(rb"(?:^|[\x00-\x20;,])fn=([^;\x00-\x1f\x7f]{2,120})", re.I),
]

SSDP_LOCATION_RE = re.compile(rb"(?im)^location:\s*(https?://[^\s\r\n]+)")
ONVIF_SCOPE_RE = re.compile(
    rb"onvif://www\.onvif\.org/(name|hardware|type)/([^\s<\"]+)", re.I
)



def clean_observed_text(value):
    if value is None:
        return None
    value = value.replace("\x00", " ").strip().strip('"').strip("'")
    value = re.sub(r"\s+", " ", value)
    if not value or len(value) < 2 or len(value) > 140:
        return None
    if value.lower() in {"unknown", "generic", "device", "model", "none", "null"}:
        return None
    return value


def normalize_model(model):
    """Normalize an observed identifier; never invent a model."""
    model = clean_observed_text(model)
    if not model:
        return None, None
    alias = MODEL_ALIASES.get(model.lower())
    if alias:
        return alias
    return model, type_from_model(model)


def _best_model_candidate(raw_candidates):
    """Pick the highest-scoring (model, dtype, score, source) candidate.

    raw_candidates is an iterable of (source, score, raw_value) triples;
    raw_value is cleaned and normalized here so each protocol-specific
    extractor only has to build its own candidate list.
    """
    best = None
    for source, score, raw_value in raw_candidates:
        raw = clean_observed_text(raw_value)
        if not raw:
            continue
        model, dtype = normalize_model(raw)
        if not model:
            continue
        if raw.strip().lower() in MODEL_ALIASES:
            score = max(score, 100)
            source = f"{source} (mapped identifier)"
        candidate = (model, dtype, score, source)
        if best is None or score > best[2]:
            best = candidate
    return best or (None, None, 0, None)


# Strong product/model families whose manufacturer is unambiguous.
# Used only as fallback when OUI/vendor metadata is missing or unreliable.
# Do NOT add generic technologies such as Android TV, Roku TV, ESP32, Tuya,
# AirPlay, Matter, etc. because they do not uniquely identify manufacturer.
MODEL_VENDOR_HINTS = [
    # Apple
    ("iphone", "Apple Inc."),
    ("ipad", "Apple Inc."),
    ("macbook", "Apple Inc."),
    ("imac", "Apple Inc."),
    ("apple tv", "Apple Inc."),
    ("appletv", "Apple Inc."),
    ("homepod", "Apple Inc."),

    # Samsung
    ("galaxy", "Samsung Electronics"),

    # Google
    ("pixel", "Google"),
    ("chromecast", "Google"),
    ("google nest", "Google"),
    ("nest hub", "Google"),
    ("nest audio", "Google"),

    # Sony
    ("bravia", "Sony"),
    ("playstation", "Sony"),
    ("ps4", "Sony"),
    ("ps5", "Sony"),

    # Microsoft
    ("xbox", "Microsoft"),
    ("surface", "Microsoft"),

    # Nintendo
    ("nintendo", "Nintendo"),

    # Audio / smart devices
    ("sonos", "Sonos"),

    # Storage
    ("synology", "Synology"),
    ("qnap", "QNAP"),

    # Printers
    ("laserjet", "HP"),
    ("officejet", "HP"),
    ("deskjet", "HP"),
    ("pixma", "Canon"),
    ("imageclass", "Canon"),
    ("ecotank", "Epson"),
    ("workforce", "Epson"),

    # Cameras
    ("reolink", "Reolink"),
    ("hikvision", "Hikvision"),
    ("dahua", "Dahua"),

    # Network infrastructure
    ("tl-sg105e", "TP-Link"),
    ("tl-wr802n", "TP-Link"),
    ("unifi", "Ubiquiti"),
    ("mikrotik", "MikroTik"),

    # Mobile / consumer electronics
    ("xiaomi", "Xiaomi"),
    ("redmi", "Xiaomi"),
]


def vendor_from_model(model):
    """Infer manufacturer only from strong, vendor-specific model families."""
    if not model:
        return None

    text = model.strip().lower()

    for needle, vendor in MODEL_VENDOR_HINTS:
        if needle in text:
            return vendor

    return None


# Needles this short are fine as free substrings of a narrow, real model
# identifier (MODEL_VENDOR_HINTS' only input), but unsafe as free substrings
# of an arbitrary free-form hostname (e.g. "ps4" inside "corpsforce4-pc",
# "imac" inside "animaciones-pc") -- require a whole-token match for these.
_SHORT_NEEDLE_MAX_LEN = 4


def vendor_from_model_in_hostname(hostname):
    """Infer manufacturer from MODEL_VENDOR_HINTS needles found in a hostname.

    Reuses the same table as vendor_from_model(), but hostnames are
    free-form text (unlike a real device-model string), so needles of
    _SHORT_NEEDLE_MAX_LEN characters or fewer must match a whole token
    (hostname split on -, _, ., and spaces) rather than an arbitrary
    substring.
    """
    if not hostname:
        return None

    text = hostname.strip().lower()
    tokens = None

    for needle, vendor in MODEL_VENDOR_HINTS:
        if len(needle) > _SHORT_NEEDLE_MAX_LEN:
            if needle in text:
                return vendor
            continue
        if tokens is None:
            tokens = re.split(r"[-_.\s]+", text)
        if needle in tokens:
            return vendor

    return None


# Domain-based vendor inference is intentionally restricted to Apple
# OS-level endpoints (the captive-portal check and software-update
# service) -- these are only ever queried by Apple's own OS software.
# The broader Apple domains in DOMAIN_HINTS (apple.com, icloud.com, etc.)
# are deliberately excluded here: they're also hit by non-Apple devices
# (e.g. a Windows PC running iTunes/iCloud for Windows, or any browser
# visiting apple.com), so they stay device-type-only evidence.
DOMAIN_VENDOR_HINTS = [
    ("captive.apple.com", "Apple Inc."),
    ("mesu.apple.com", "Apple Inc."),
]


def vendor_from_domain_needle(needle):
    """Infer manufacturer only from the small Apple-exclusive needle set.

    Must be called with the exact `needle` returned by type_from_dns_query()
    (never the full qname) -- this both preserves the DNS-privacy contract
    and keeps vendor inference restricted to a fixed, auditable list.
    """
    if not needle:
        return None
    for domain_needle, vendor in DOMAIN_VENDOR_HINTS:
        if domain_needle == needle:
            return vendor
    return None


# Phone-family brands such as "galaxy" and "redmi" also ship tablets (Galaxy
# Tab, Redmi Pad) and TVs (Redmi TV). A bare family name means a phone, but when
# the name ALSO carries a non-phone form-factor word it is not a phone. Matched
# as whole tokens (split on -, _, ., space) so an incidental substring like the
# "tab" inside "database" never triggers a false veto.
_NON_PHONE_FORM_FACTOR_TOKENS = frozenset(("pad", "tab", "tv"))


def _android_phone_family_form_factor(dtype, text):
    """Correct a phone-family verdict when the name also names a non-phone form
    factor. Only ever adjusts "Mobile (Android)"; every other dtype passes
    through unchanged.
    """
    if dtype != "Mobile (Android)":
        return dtype
    tokens = set(re.split(r"[-_.\s]+", (text or "").lower()))
    if "tv" in tokens:
        return "Smart TV / Media Device"
    if "pad" in tokens or "tab" in tokens:
        return "Tablet (Android)"
    return dtype


def type_from_model(model):
    if not model:
        return None
    alias = MODEL_ALIASES.get(model.strip().lower())
    if alias:
        return alias[1]
    text = model.lower()
    for needle, dtype in MODEL_TYPE_HINTS:
        if needle in text:
            return _android_phone_family_form_factor(dtype, text)
    return None


def is_locally_administered_mac(mac):
    """True if the MAC's locally-administered bit is set (randomized MAC)."""
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0x02)


def _first_match(text, table):
    """Return the first dtype whose needle substring-matches text (lowercased).

    Works for both str tables (HOSTNAME_HINTS/VENDOR_HINTS) and bytes tables
    (SERVICE_HINTS/WEAK_SERVICE_HINTS) -- callers must never cross-feed
    bytes into a str-keyed table or vice versa.
    """
    if not text:
        return None
    lowered = text.lower()
    for needle, dtype in table:
        if needle.lower() in lowered:
            return dtype
    return None


def type_from_hostname(hostname):
    return _android_phone_family_form_factor(
        _first_match(hostname, HOSTNAME_HINTS), hostname
    )


def type_from_os_hint(text):
    """Return an OS-only verdict ("Android Device") from a hostname or DHCP
    vendor-class string, or None. The caller must merge this at
    SCORES["os_hint"] so any form-factor evidence overrides it.
    """
    return _first_match(text, OS_HINTS)


def type_from_vendor(vendor):
    if not vendor:
        return None
    return _first_match(vendor, VENDOR_HINTS)


def type_from_payload(payload):
    return _first_match(payload, SERVICE_HINTS)


def weak_type_from_payload(payload):
    return _first_match(payload, WEAK_SERVICE_HINTS)


def type_from_dns_query(qname):
    """Match a DNS query name against DOMAIN_HINTS.

    Returns (dtype, needle) -- callers must only ever store/log `needle`
    (a short fixed keyword), never the full qname, to avoid persisting
    a device's browsing/service history.
    """
    if not qname:
        return None, None
    lowered = qname.lower()
    for needle, dtype in DOMAIN_HINTS:
        if needle in lowered:
            return dtype, needle
    return None, None


# A known signature must cover at least this fraction of the observed PRL, so a
# short signature cannot match a much longer unrelated list by chance.
_DHCP_SIG_MIN_COVERAGE = 0.75


def _is_ordered_subsequence(needle, haystack):
    """True if every element of `needle` appears in `haystack` in the same
    relative order (extra elements between/around them are allowed)."""
    it = iter(haystack)
    return all(element in it for element in needle)


def type_from_dhcp_signature(prl):
    """Tolerantly classify a DHCP option-55 Parameter Request List.

    A known signature matches when it is an ordered subsequence of the observed
    `prl` AND covers at least _DHCP_SIG_MIN_COVERAGE of it. This lets OS updates
    that insert/append options (e.g. 114, or 108 = RFC 8925 IPv6-Only Preferred)
    still match, while the coverage floor stops a short signature matching a long
    unrelated list. The longest matching signature wins (most specific); a tie
    between equally long matches that disagree on type is ambiguous -> None.
    Exact matches still work (a tuple is an ordered subsequence of itself).
    """
    observed = tuple(prl)
    if not observed:
        return None
    min_len = _DHCP_SIG_MIN_COVERAGE * len(observed)
    best_len = 0
    best_type = None
    ambiguous = False
    for sig, dtype in DHCP_SIGNATURES.items():
        if len(sig) < min_len:
            continue
        if not _is_ordered_subsequence(sig, observed):
            continue
        if len(sig) > best_len:
            best_len, best_type, ambiguous = len(sig), dtype, False
        elif len(sig) == best_len and dtype != best_type:
            ambiguous = True
    if ambiguous:
        return None
    return best_type


def type_from_vendor_class(vendor_class):
    """Match a DHCP option-60 vendor class against VENDOR_CLASS_HINTS.

    Ordered first-match, so more-specific entries (listed first) win over
    generic ones. Returns (dtype, needle) -- callers log only `needle`,
    never the full vendor-class string.
    """
    if not vendor_class:
        return None, None
    lowered = vendor_class.lower()
    for needle, dtype in VENDOR_CLASS_HINTS:
        if needle in lowered:
            return dtype, needle
    return None, None


# Huawei devices send a DHCP option-60 vendor class of the form
# "HUAWEI:android:<CODE>", where <CODE> is the model-line prefix (e.g. DBY-W09 ->
# "DBY"). The "android" token alone is OS-only, but a KNOWN model-code prefix is
# form-factor evidence. Unknown codes are deliberately left to the existing
# OS-only path (type_from_os_hint -> "Android Device").
HUAWEI_VENDOR_CLASS_PREFIX = "huawei:"
HUAWEI_MODEL_CODE_HINTS = {
    "dby": "Tablet (Android)",   # MatePad 11 (DBY-W09)
    "mna": "Mobile (Android)",   # P60 Pro (MNA-LX9)
}


def vendor_from_vendor_class(vendor_class):
    """Infer the manufacturer from a DHCP option-60 vendor class.

    Only the unambiguous Huawei "HUAWEI:..." prefix is recognised. The caller
    must gate this on the MAC having no real OUI vendor (as with the other
    inferred-vendor paths), so a genuine OUI vendor is never overwritten.
    """
    if not vendor_class:
        return None
    if vendor_class.lower().startswith(HUAWEI_VENDOR_CLASS_PREFIX):
        return "Huawei"
    return None


def type_from_huawei_vendor_class(vendor_class):
    """Return a form factor from a known Huawei model-code prefix, or None.

    Returns None for a non-Huawei vendor class and for an unknown Huawei code,
    so unknown codes fall back to the OS-only "Android Device" classification.
    """
    if not vendor_class:
        return None
    lowered = vendor_class.lower()
    if not lowered.startswith(HUAWEI_VENDOR_CLASS_PREFIX):
        return None
    code = lowered.rsplit(":", 1)[-1].strip()
    for prefix, dtype in HUAWEI_MODEL_CODE_HINTS.items():
        if code.startswith(prefix):
            return dtype
    return None


def type_from_mdns_query(qname):
    """Match an mDNS *query* service-type against MDNS_QUERY_HINTS.

    Returns (dtype, needle); callers store/log only the short service-type
    needle, never the full queried name.
    """
    if not qname:
        return None, None
    lowered = qname.lower()
    for needle, dtype in MDNS_QUERY_HINTS:
        if needle in lowered:
            return dtype, needle
    return None, None


def vendor_from_mdns_query_needle(needle):
    """Infer the querier's vendor from an Apple-exclusive Continuity needle.

    Must be called with the exact `needle` returned by type_from_mdns_query()
    (an entry of MDNS_QUERY_HINTS), never a raw qname. The caller must also gate
    this on the source MAC having no real OUI vendor -- the query only proves the
    querier runs Apple's OS, so it must never overwrite a genuine OUI vendor.
    """
    if not needle:
        return None
    return MDNS_QUERY_VENDOR_HINTS.get(needle)


# macOS/iOS SYN TCP option-kind order (trailing EOL/NOP ignored). Only the
# Apple stack is fingerprinted here -- see fingerprint_tcp_syn().
_SYN_APPLE_OPTS = ("MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp", "SAckOK")


def fingerprint_tcp_syn(packet):
    """Return (os_family, device_type) from a pure-SYN packet, or (None, None).

    p0f-style, but Apple-only on this network: initial TTL 64 plus the
    macOS/iOS TCP option order -> "Apple Device". The Windows and
    Linux/Android buckets were validated as unreachable here -- the Dell
    Windows box's SYNs never reach eth1 (devices on the Huawei WiFi do not
    mirror their client SYNs to us), so those buckets are omitted rather than
    shipped without live confirmation. Only the resulting OS-family label is
    used; no destination IP/port or per-flow data is read or stored. Weak
    tier (SCORES["syn_fp"]).
    """
    if IP not in packet or TCP not in packet:
        return None, None
    try:
        ttl = int(packet[IP].ttl)
        opt_kinds = tuple(o[0] for o in packet[TCP].options)
    except Exception:
        return None, None

    trimmed = list(opt_kinds)
    while trimmed and trimmed[-1] in ("EOL", "NOP"):
        trimmed.pop()
    trimmed = tuple(trimmed)

    # Observed TTL <= initial; on a LAN the hop count is small (initial 64).
    if 0 < ttl <= 64 and trimmed[:len(_SYN_APPLE_OPTS)] == _SYN_APPLE_OPTS:
        return "Apple", "Apple Device"
    return None, None


def is_unclassified(dtype):
    """Whether a stored device_type still counts as needing classification.

    Used identically by the probe triggers and the probe workers' post-delay
    re-check so the two never disagree -- a stored "Generic / Unknown" is
    unclassified, not classified.
    """
    return not dtype or dtype == "Generic / Unknown"


def merge_candidate(current, dtype, score, source):
    """Keep the strongest classification candidate for this packet/event."""
    if not dtype:
        return current
    if current is None or score > current[1]:
        return (dtype, score, source)
    return current
