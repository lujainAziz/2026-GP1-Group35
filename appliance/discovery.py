#!/usr/bin/env python3
"""ASSAS v12 - resilient subnet inventory + passive evidence separation.

Core mechanism (always on): passive capture of SPAN-mirrored traffic on
CAPTURE_INTERFACE. This only reads packets already flowing on the mirror
port -- no traffic is blocked, modified, or TLS-intercepted. SPAN
observations (ARP/DHCP/mDNS responses+queries/SSDP/WS-Discovery/LLDP/DNS/
NBNS/LLMNR/TCP SYN+SYN-ACK) enrich
device identity and record traffic visibility, while the TL-WR802N
wireless-station list is an optional, independent indicator of Assas-Test
association. No signal is allowed to silently stand in for another.

Beyond that core, six independently-gated mechanisms send traffic of
their own and can each be disabled without affecting the others:
  - ARP subnet scan: an initial scan at startup plus periodic refresh.
    ASSAS_SKIP_INITIAL_DISCOVERY=1 skips the initial scan;
    ASSAS_DISCOVERY_REFRESH_SECONDS=0 disables the periodic refresh.
  - TP-Link AP admin polling: only runs if ASSAS_AP_PASSWORD or
    ASSAS_AP_CLIENTS is set.
  - UPnP/SSDP probing: only runs if ASSAS_UPNP_ENRICH=1.
  - Active nmap port probe: a one-time fallback for devices that remain
    unclassified after ASSAS_ACTIVE_PROBE_DELAY_SECONDS. Only runs if
    ASSAS_ACTIVE_PROBE=1.
  - Light-active unicast mDNS (DNS-SD) probe: a one-time-per-runtime
    fallback that sends a single DNS-SD query to a still-unclassified
    device's own mDNS port (UDP 5353) and routes replies through the
    existing mDNS metadata pipeline. Only runs if ASSAS_MDNS_PROBE=1
    (delay: ASSAS_MDNS_PROBE_DELAY_SECONDS, default 60).
  - Light-active unicast NetBIOS name probe: a one-time-per-runtime
    fallback that sends a single NBSTAT node-status request to a
    still-unclassified device's own NetBIOS port (UDP 137). A reply
    yields the host's own NetBIOS name (unique 0x00/0x20 entries only)
    and marks it a NetBIOS responder (weak Computer evidence). Only runs
    if ASSAS_NBNS_PROBE=1 (delay: ASSAS_NBNS_PROBE_DELAY_SECONDS, default 10).

For a fully passive deployment, set:
  ASSAS_SKIP_INITIAL_DISCOVERY=1 ASSAS_DISCOVERY_REFRESH_SECONDS=0
and leave ASSAS_AP_PASSWORD, ASSAS_AP_CLIENTS, ASSAS_UPNP_ENRICH,
ASSAS_ACTIVE_PROBE, ASSAS_MDNS_PROBE, and ASSAS_NBNS_PROBE unset.
"""

import argparse
import base64
import hashlib
import ipaddress
import os
import re
import sqlite3
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

from service_fingerprints import parse_nmap_identity

from scapy.all import sniff, Ether, IP, IPv6, ARP, UDP, TCP, DHCP, DNS, DNSQR
from scapy.layers.netbios import (
    NBNSHeader, NBNSQueryResponse, NBNSRegistrationRequest,
    NBNSNodeStatusRequest, NBNSNodeStatusResponse,
)
from scapy.layers.llmnr import LLMNRResponse

DB_PATH = os.getenv("ASSAS_DB_PATH", "/home/assas/assas/assas.db")

# Active discovery interface.
# Leave unset to auto-detect it from the default route.
# You can override it with: ASSAS_DISCOVERY_IFACE=<iface>
DISCOVERY_INTERFACE = os.getenv("ASSAS_DISCOVERY_IFACE")

# Dedicated SPAN / mirrored-traffic capture interface.
# IMPORTANT: set this to the real no-IP SPAN interface on the Pi.
# Override with: ASSAS_CAPTURE_IFACE=<iface>
CAPTURE_INTERFACE = os.getenv("ASSAS_CAPTURE_IFACE", "eth1")

OUI_FILE = "/usr/share/arp-scan/ieee-oui.txt"
OUI_FALLBACK_FILES = ("/usr/share/nmap/nmap-mac-prefixes",
                      "/usr/local/share/nmap/nmap-mac-prefixes")

# Optional local metadata enrichment.
# Disabled by default because the formal ASSAS design emphasizes passive monitoring.
# Enable only if the team accepts a lightweight local UPnP metadata request:
#   ASSAS_UPNP_ENRICH=1
ENABLE_UPNP_ENRICHMENT = os.getenv("ASSAS_UPNP_ENRICH", "0").lower() in {
    "1", "true", "yes", "on"
}
UPNP_TIMEOUT_SECONDS = 2.0
UPNP_MAX_BYTES = 128 * 1024

# Evidence source labels stored in model_source / class_source.
SRC_HOSTNAME_MODEL_CODE = "hostname model code"
SRC_MODEL_DATABASE = "device model identifier (model database)"

# ASSAS-Test client membership source.  The TL-WR802N is the authoritative
# source for which wireless stations are actually associated to the SSID.
AP_URL = os.getenv("ASSAS_AP_URL", "http://192.168.100.2").rstrip("/")
AP_USER = os.getenv("ASSAS_AP_USER", "admin")
AP_PASSWORD = os.getenv("ASSAS_AP_PASSWORD")
AP_SSID = os.getenv("ASSAS_AP_SSID", "Assas-Test")
AP_MAC = os.getenv("ASSAS_AP_MAC", "b8:fb:b3:cb:b3:56").lower()
AP_POLL_SECONDS = max(3, int(os.getenv("ASSAS_AP_POLL_SECONDS", "5")))

def _parse_manual_client_macs(value):
    macs = set()
    for raw in re.split(r"[,;\s]+", value or ""):
        raw = raw.strip().lower().replace("-", ":")
        if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", raw):
            macs.add(raw)
    return macs

MANUAL_AP_CLIENTS = _parse_manual_client_macs(os.getenv("ASSAS_AP_CLIENTS", ""))

# When UPnP enrichment is enabled, ASSAS can issue a small local SSDP M-SEARCH
# burst for devices already confirmed by ASSAS.  This speeds up model discovery
# without changing the core SPAN/passive monitoring path.
SSDP_PROBE_TIMEOUT_SECONDS = 1.5
SSDP_MULTICAST = ("239.255.255.250", 1900)

CACHE_WRITE_INTERVAL = 60

# Keep the subnet inventory fresh after the initial scan. This is deliberately
# separate from SPAN traffic visibility: an ARP response means "present on the
# subnet", not "observed on the mirrored port". Set refresh to 0 to disable.
DISCOVERY_REFRESH_SECONDS = max(0, int(os.getenv("ASSAS_DISCOVERY_REFRESH_SECONDS", "45")))
DISCOVERY_STALE_SECONDS = max(60, int(os.getenv("ASSAS_DISCOVERY_STALE_SECONDS", "120")))

# Skip even the one-time startup ARP scan. Combined with
# ASSAS_DISCOVERY_REFRESH_SECONDS=0 and no ASSAS_AP_PASSWORD/ASSAS_AP_CLIENTS,
# this yields a fully passive deployment via env vars alone.
SKIP_INITIAL_DISCOVERY = os.getenv("ASSAS_SKIP_INITIAL_DISCOVERY", "0").lower() in {
    "1", "true", "yes", "on"
}

# Historical records older than this are purged during housekeeping.
# Set ASSAS_DELETE_AFTER_DAYS=0 to retain everything indefinitely.
DELETE_AFTER_DAYS = int(os.getenv("ASSAS_DELETE_AFTER_DAYS", "30"))

# Optional one-time active nmap port probe for devices that stay
# unclassified after ASSAS_ACTIVE_PROBE_DELAY_SECONDS. Disabled by default --
# this is the most active mechanism in this file (it sends packets directly
# to a target device rather than only observing/joining existing traffic).
# Enable with: ASSAS_ACTIVE_PROBE=1
ENABLE_ACTIVE_PROBE = os.getenv("ASSAS_ACTIVE_PROBE", "0").lower() in {
    "1", "true", "yes", "on"
}
ACTIVE_PROBE_DELAY_SECONDS = max(0, int(os.getenv("ASSAS_ACTIVE_PROBE_DELAY_SECONDS", "120")))
ACTIVE_PROBE_PORTS = "22,80,443,445,515,554,631,1883,3389,5900,8000,8001,8008,8009,8080,8443,8554,9100,32400"
NMAP_PROBE_SLOTS = threading.BoundedSemaphore(2)

# Optional one-time light-active unicast mDNS (DNS-SD) probe for devices that
# stay unclassified after ASSAS_MDNS_PROBE_DELAY_SECONDS. Disabled by default.
# Lighter than the nmap probe (a single DNS-SD query to the device's own
# mDNS port), so it can run a bit sooner. Enable with: ASSAS_MDNS_PROBE=1
ENABLE_MDNS_PROBE = os.getenv("ASSAS_MDNS_PROBE", "0").lower() in {
    "1", "true", "yes", "on"
}
MDNS_PROBE_DELAY_SECONDS = max(0, int(os.getenv("ASSAS_MDNS_PROBE_DELAY_SECONDS", "60")))

# Optional one-time light-active unicast NetBIOS name probe (NBSTAT node
# status) for devices that stay unclassified after
# ASSAS_NBNS_PROBE_DELAY_SECONDS. Disabled by default. A single NBSTAT
# request to the device's own NetBIOS port (UDP 137); Windows/Samba hosts
# answer with their own name table. Enable with: ASSAS_NBNS_PROBE=1
ENABLE_NBNS_PROBE = os.getenv("ASSAS_NBNS_PROBE", "0").lower() in {
    "1", "true", "yes", "on"
}
NBNS_PROBE_DELAY_SECONDS = max(0, int(os.getenv("ASSAS_NBNS_PROBE_DELAY_SECONDS", "10")))

# Passive TCP SYN OS fingerprint: adding pure SYNs to the capture filter means
# the daemon sees local devices' outbound connections, so fingerprinting is
# rate-limited to at most one per source MAC per this interval to bound CPU.
SYN_FP_INTERVAL_SECONDS = max(0, int(os.getenv("ASSAS_SYN_FP_INTERVAL_SECONDS", "300")))

write_cache = {}
oui_dict = {}
infra_hints = {}
monitored_networks = []
local_macs = set()
local_ips = set()
db_lock = threading.Lock()
metadata_lock = threading.Lock()
metadata_urls_seen = set()
ssdp_targets_probed = set()
active_probed = set()
active_probe_lock = threading.Lock()
mdns_probed = set()
mdns_probe_lock = threading.Lock()
nbns_probed = set()
nbns_probe_lock = threading.Lock()
syn_fp_last = {}
syn_fp_lock = threading.Lock()
ssdp_probe_lock = threading.Lock()
discovery_ipv4 = None
ap_membership_lock = threading.Lock()
last_ap_membership = set()
last_ap_error = None
_tplink_auth_cache = {"mode": None, "headers": None, "station_url": None, "time": None}
TPLINK_AUTH_TTL_SECONDS = max(60, int(os.getenv("ASSAS_AP_AUTH_TTL_SECONDS", "600")))

import model_db

# Higher score = stronger classification evidence.
from classification import (
    SCORES,
    SERVICE_HINTS,
    WEAK_SERVICE_HINTS,
    PORT_HINTS,
    DHCP_SIGNATURES,
    VENDOR_CLASS_HINTS,
    MDNS_QUERY_HINTS,
    MDNS_QUERY_VENDOR_HINTS,
    HOSTNAME_HINTS,
    VENDOR_HINTS,
    MODEL_ALIASES,
    MODEL_TYPE_HINTS,
    MODEL_PATTERNS,
    MANUFACTURER_PATTERNS,
    FRIENDLY_NAME_PATTERNS,
    SSDP_LOCATION_RE,
    ONVIF_SCOPE_RE,
    MODEL_VENDOR_HINTS,
    clean_observed_text,
    normalize_model,
    _best_model_candidate,
    vendor_from_model,
    vendor_from_model_in_hostname,
    vendor_from_domain_needle,
    type_from_model,
    is_locally_administered_mac,
    _first_match,
    type_from_hostname,
    type_from_os_hint,
    OS_LEVEL_TYPES,
    ANDROID_FAMILY_TYPES,
    type_from_vendor,
    type_from_payload,
    weak_type_from_payload,
    type_from_dns_query,
    type_from_vendor_class,
    type_from_dhcp_signature,
    vendor_from_vendor_class,
    type_from_huawei_vendor_class,
    type_from_mdns_query,
    vendor_from_mdns_query_needle,
    fingerprint_tcp_syn,
    is_unclassified,
    is_general_type,
    needs_type_probe,
    needs_service_probe,
    surveillance_type_from_ports,
    CAMERA_PORTS,
    SURVEILLANCE_MGMT_PORTS,
    merge_candidate,
)


def extract_model_info(payload):
    """Return model metadata from non-DNS-SD payloads such as XML/SOAP."""
    if not payload:
        return None, None, 0, None

    candidates = []
    for source, score, pattern in MODEL_PATTERNS:
        # DNS-SD TXT data is parsed structurally by extract_mdns_metadata().
        # Do not apply raw mDNS regexes to a binary DNS packet, because the
        # next TXT-string length byte can be mistaken for part of the value.
        if source.startswith("mDNS") or source.startswith("printer") or source == "USB model" or source == "Apple board":
            continue
        match = pattern.search(payload)
        if not match:
            continue
        raw = match.group(1).decode("utf-8", errors="ignore")
        candidates.append((source, score, raw))

    return _best_model_candidate(candidates)


def _dns_rrs(section):
    """Yield DNS resource records across Scapy versions."""
    if section is None:
        return
    if isinstance(section, (list, tuple)):
        for rr in section:
            if rr is not None:
                yield rr
        return

    rr = section
    seen = 0
    while rr is not None and hasattr(rr, "type") and seen < 256:
        yield rr
        seen += 1
        nxt = getattr(rr, "payload", None)
        if nxt is None or not hasattr(nxt, "type"):
            break
        rr = nxt


def _split_txt_rdata(value):
    """Normalize Scapy TXT rdata into individual RFC 6763 strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value.encode("utf-8", errors="ignore")]
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            out.extend(_split_txt_rdata(item))
        return out
    if not isinstance(value, (bytes, bytearray)):
        return [str(value).encode("utf-8", errors="ignore")]

    raw = bytes(value)
    if not raw:
        return []

    # Some Scapy versions expose TXT rdata as the already-decoded string,
    # while others may expose the on-wire <length><string> representation.
    # Parse the latter only when the whole byte sequence is structurally valid.
    parts = []
    pos = 0
    valid = True
    while pos < len(raw):
        length = raw[pos]
        pos += 1
        if pos + length > len(raw):
            valid = False
            break
        parts.append(raw[pos:pos + length])
        pos += length
    if valid and pos == len(raw) and parts:
        return parts
    return [raw]


def dns_txt_strings(packet):
    """Return only the constituent TXT strings from an mDNS response."""
    if DNS not in packet:
        return []
    dns = packet[DNS]
    strings = []
    for section_name in ("an", "ns", "ar"):
        for rr in _dns_rrs(getattr(dns, section_name, None)):
            try:
                rr_type = int(rr.type)
            except (TypeError, ValueError):
                continue
            if rr_type != 16:  # TXT
                continue
            strings.extend(_split_txt_rdata(getattr(rr, "rdata", None)))
    return [s for s in strings if s]


def parse_txt_kv(txt_strings):
    """Parse DNS-SD TXT strings as key/value pairs without crossing boundaries."""
    parsed = {}
    for item in txt_strings:
        if isinstance(item, str):
            raw = item.encode("utf-8", errors="ignore")
        else:
            raw = bytes(item)
        if b"=" in raw:
            key, value = raw.split(b"=", 1)
        else:
            key, value = raw, b""
        key_text = key.decode("ascii", errors="ignore").strip().lower()
        if not key_text or key_text in parsed:
            continue
        parsed[key_text] = value
    return parsed


def extract_mdns_metadata(packet):
    """Return (model, type, score, source, manufacturer, friendly_name)."""
    kv = parse_txt_kv(dns_txt_strings(packet))
    if not kv:
        return None, None, 0, None, None, None

    manufacturer = None
    for key in ("manufacturer", "usb_mfg", "mfg"):
        if key in kv:
            manufacturer = clean_observed_text(kv[key].decode("utf-8", errors="ignore"))
            if manufacturer:
                break

    friendly = None
    for key in ("fn", "name"):
        if key in kv:
            friendly = clean_observed_text(kv[key].decode("utf-8", errors="ignore"))
            if friendly:
                break

    model_keys = [
        ("model", 95, "mDNS model"),
        ("md", 92, "mDNS md"),
        ("ty", 95, "mDNS printer model"),
        ("product", 92, "mDNS product"),
        ("usb_mdl", 95, "mDNS USB model"),
        ("am", 95, "mDNS Apple model identifier"),
    ]

    candidates = []
    for key, score, source in model_keys:
        if key not in kv:
            continue
        raw = kv[key].decode("utf-8", errors="ignore").strip()
        if key == "product":
            raw = raw.strip("()")
        candidates.append((source, score, raw))

    model, dtype, score, source = _best_model_candidate(candidates)
    return model, dtype, score, source, manufacturer, friendly


def _dns_name_to_str(raw):
    """Decode a scapy rrname/rdata to text (keeping backslash escapes)."""
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", errors="ignore")
    return str(raw)


def _split_dns_labels(name):
    """Split a DNS name into labels on UNescaped dots, decoding \\DDD and \\x.

    DNS-SD instance labels may legitimately contain dots/spaces encoded on the
    wire as \\. or \\032; those must stay inside a single label, so splitting
    has to respect the escaping rather than a naive str.split('.').
    """
    labels = []
    cur = []
    i = 0
    n = len(name)
    while i < n:
        ch = name[i]
        if ch == "\\" and i + 1 < n:
            nxt = name[i + 1]
            if nxt.isdigit() and i + 4 <= n and name[i + 1:i + 4].isdigit():
                try:
                    cur.append(chr(int(name[i + 1:i + 4])))
                except ValueError:
                    cur.append(nxt)
                i += 4
            else:
                cur.append(nxt)
                i += 2
            continue
        if ch == ".":
            labels.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    if cur:
        labels.append("".join(cur))
    # Drop a trailing empty label produced by the root dot.
    if labels and labels[-1] == "":
        labels.pop()
    return labels


def _usable_mdns_name(value):
    """Accept only a literal, human-readable mDNS-derived name, else None.

    Rejects empty/generic values, service-type labels, reverse-DNS, IP/numeric
    strings, and opaque hex identifiers. Nothing is inferred -- the text must be
    present verbatim in the record.
    """
    value = clean_observed_text(value)
    if not value:
        return None
    low = value.lower()
    if low.startswith("_"):
        return None                       # a service-type label, not a name
    if "._tcp" in low or "._udp" in low:
        return None                       # still a service name
    if low.endswith(".arpa") or "in-addr" in low or "ip6.arpa" in low:
        return None                       # reverse-DNS
    if not re.search(r"[A-Za-z]", value):
        return None                       # numeric / IP-like (no letters)
    if re.fullmatch(r"[0-9a-f]{16,}", low):
        return None                       # opaque hex/UUID identifier
    if is_generic_friendly_name(value):
        return None
    return value


def extract_mdns_hostname(packet):
    """Hostname from an mDNS A/AAAA record owner name ending in .local.

    Response packets only; the owner name of an address record is the device's
    own hostname (e.g. "Living-Room-TV.local" -> "Living-Room-TV").
    """
    if DNS not in packet or int(packet[DNS].qr) != 1:
        return None                            # response packets only
    for section in ("an", "ns", "ar"):
        for rr in _dns_rrs(getattr(packet[DNS], section, None)):
            try:
                if int(rr.type) not in (1, 28):   # A / AAAA
                    continue
            except (TypeError, ValueError):
                continue
            labels = _split_dns_labels(_dns_name_to_str(getattr(rr, "rrname", b"")))
            if len(labels) >= 2 and labels[-1].lower() == "local":
                name = _usable_mdns_name(".".join(labels[:-1]))
                if name:
                    return name
    return None


def extract_mdns_instance_name(packet):
    """Friendly name from a DNS-SD service-instance label in an mDNS response.

    For <instance>._service._tcp.local / ._udp.local (PTR rdata target or SRV
    owner name), return only the <instance> portion, never the service type.
    """
    if DNS not in packet or int(packet[DNS].qr) != 1:
        return None                            # response packets only
    for section in ("an", "ns", "ar"):
        for rr in _dns_rrs(getattr(packet[DNS], section, None)):
            try:
                rr_type = int(rr.type)
            except (TypeError, ValueError):
                continue
            if rr_type == 12:        # PTR: instance is the rdata target
                source = getattr(rr, "rdata", None)
            elif rr_type == 33:      # SRV: instance is the owner (rrname)
                source = getattr(rr, "rrname", None)
            else:
                continue
            labels = _split_dns_labels(_dns_name_to_str(source))
            proto_idx = next(
                (i for i, lab in enumerate(labels) if lab.lower() in ("_tcp", "_udp")),
                None,
            )
            # Need at least <instance>._service before the _tcp/_udp label.
            if proto_idx is None or proto_idx < 2:
                continue
            if not labels[proto_idx - 1].startswith("_"):
                continue             # label before _tcp/_udp must be the service
            name = _usable_mdns_name(".".join(labels[:proto_idx - 1]))
            if name:
                return name
    return None


def mdns_name_candidate(packet, txt_friendly=None):
    """Best mDNS-derived name: TXT fn/name, then A/AAAA owner, then instance.

    Returns (name, source_label) or (None, None). Pure extraction of literal
    record text; precedence against existing names is enforced downstream by
    update_device()/hostname_quality().
    """
    if txt_friendly:
        return txt_friendly, "mDNS friendly name"
    host = extract_mdns_hostname(packet)
    if host:
        return host, "mDNS A-record hostname"
    inst = extract_mdns_instance_name(packet)
    if inst:
        return inst, "mDNS service-instance name"
    return None, None


# NBT name suffix codes (RFC1002 sect 4.2.1) as encoded by scapy's SUFFIX
# ShortEnumField -- only these two identify a device's own hostname service;
# every other suffix (messenger 0x03, domain master browser 0x1B, domain
# controller 0x1C, browser election 0x1E, etc.) is a special-purpose service
# name, never a device's own hostname, and must be rejected.
_NBNS_SUFFIX_WORKSTATION = 0x4141  # raw suffix byte 0x00
_NBNS_SUFFIX_FILE_SERVER = 0x4341  # raw suffix byte 0x20


def extract_nbns_name(packet):
    """Return a device's own NetBIOS name from a registration only.

    NBNS plain queries (OPCODE 0) ask about a name that may belong to a
    different host on the segment, so they are never trusted. Only name
    registration requests (OPCODE 5 -- the device broadcasting its own name
    to claim it) are used, and only for a *unique* name (never a group name
    like WORKGROUP or a domain name) with the workstation/file-server
    suffix (never messenger, browser-election, or domain-controller
    service names, which do not identify the registering host itself).
    """
    if NBNSHeader not in packet or NBNSRegistrationRequest not in packet:
        return None
    reg = packet[NBNSRegistrationRequest]
    if int(reg.G) != 0:  # 0 = "Unique name", 1 = "Group name"
        return None
    if int(reg.SUFFIX) not in (_NBNS_SUFFIX_WORKSTATION, _NBNS_SUFFIX_FILE_SERVER):
        return None
    name = reg.QUESTION_NAME
    if isinstance(name, bytes):
        name = name.decode("ascii", errors="ignore")
    return clean_observed_text(name.strip())


# In an NBSTAT node-status *response*, each name-table entry carries the raw
# 1-byte suffix (0x00 workstation, 0x20 file server, 0x1b/0x1c/0x1e/0x03
# special services) and a NAME_FLAGS byte whose high bit (0x80) is the Group
# flag -- unlike registration requests, whose SUFFIX is the NBT-encoded short.
_NBNS_NODE_SUFFIX_WORKSTATION = 0x00
_NBNS_NODE_SUFFIX_FILE_SERVER = 0x20
_NBNS_NODE_GROUP_FLAG = 0x80


def extract_nbns_nodestatus_name(packet):
    """Return a device's own NetBIOS name from an NBSTAT node-status response.

    Same attribution rules as extract_nbns_name(): only a *unique* name
    (group flag clear) with the workstation (0x00) or file-server (0x20)
    suffix is the host's own hostname. Group names (WORKGROUP / the domain)
    and special-service suffixes (0x1b domain master browser, 0x1c domain
    controller, 0x1e browser election, 0x03 messenger) are never a hostname.
    """
    if NBNSNodeStatusResponse not in packet:
        return None
    names = packet[NBNSNodeStatusResponse].NODE_NAME or []
    for entry in names:
        try:
            if int(entry.NAME_FLAGS) & _NBNS_NODE_GROUP_FLAG:
                continue  # group name (WORKGROUP / domain), not a hostname
            if int(entry.SUFFIX) not in (
                _NBNS_NODE_SUFFIX_WORKSTATION, _NBNS_NODE_SUFFIX_FILE_SERVER
            ):
                continue
        except (TypeError, ValueError):
            continue
        raw = entry.NETBIOS_NAME
        if isinstance(raw, bytes):
            raw = raw.decode("ascii", errors="ignore")
        cleaned = clean_observed_text(raw.strip())
        if cleaned:
            return cleaned
    return None


def extract_llmnr_name(packet):
    """Return a device's own hostname from an LLMNR *response* only.

    LLMNR queries ask about a name that may belong to another host on the
    segment; only responses (where the replying device is asserting its own
    A/AAAA record) are safe to attribute to the sending MAC.
    """
    if LLMNRResponse not in packet:
        return None
    resp = packet[LLMNRResponse]
    if int(resp.qr) != 1 or not resp.qd:
        return None
    entry = resp.qd[0] if isinstance(resp.qd, (list, tuple)) else resp.qd
    qname = getattr(entry, "qname", None)
    if not qname:
        return None
    if isinstance(qname, bytes):
        qname = qname.decode("utf-8", errors="ignore")
    return clean_observed_text(qname.rstrip(".").strip())


def extract_manufacturer(payload):
    if not payload:
        return None
    for pattern in MANUFACTURER_PATTERNS:
        match = pattern.search(payload)
        if match:
            value = match.group(1).decode("utf-8", errors="ignore")
            value = clean_observed_text(value)
            if value:
                return value
    return None


def extract_ssdp_location(payload):
    if not payload:
        return None
    match = SSDP_LOCATION_RE.search(payload)
    if not match:
        return None
    return match.group(1).decode("utf-8", errors="ignore").strip()


def extract_wsd_metadata(payload):
    """Extract conservative ONVIF/WSD metadata from UDP/3702 payloads."""
    if not payload:
        return None, None, None, None

    friendly = extract_friendly_name(payload)
    manufacturer = extract_manufacturer(payload)
    model = None
    dtype = type_from_payload(payload)

    # ONVIF defines optional scopes for name/hardware/type.  Hardware is an
    # advertised identifier, so it is safe to keep as a model only when it is
    # a useful non-generic value.
    for kind_raw, value_raw in ONVIF_SCOPE_RE.findall(payload):
        kind = kind_raw.decode("ascii", errors="ignore").lower()
        value = urllib.parse.unquote(
            value_raw.decode("utf-8", errors="ignore")
        ).replace("+", " ")
        value = clean_observed_text(value)
        if not value:
            continue
        if kind == "name" and not friendly:
            friendly = value
        elif kind == "hardware" and not model and not _is_protocol_or_version_label(value):
            model = value
        elif kind == "type" and "network_video_transmitter" in value.lower() \
                and dtype != "Network Video Recorder":
            # A transmitter scope must not downgrade an NVR already identified
            # from a NetworkVideoStorage (NVS) token elsewhere in the payload.
            dtype = "Security Camera"

    if model:
        normalized, model_type = normalize_model(model)
        model = normalized
        dtype = model_type or dtype

    return model, manufacturer, friendly, dtype


def parse_lldp(payload):
    """Parse the small LLDP subset useful for inventory classification."""
    if not payload:
        return None, None, None

    pos = 0
    system_name = None
    system_description = None
    enabled_caps = 0

    while pos + 2 <= len(payload):
        header = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        tlv_type = (header >> 9) & 0x7F
        length = header & 0x1FF
        if pos + length > len(payload):
            break
        value = payload[pos:pos + length]
        pos += length

        if tlv_type == 0:
            break
        if tlv_type == 5:  # System Name
            system_name = clean_observed_text(value.decode("utf-8", errors="ignore"))
        elif tlv_type == 6:  # System Description
            system_description = clean_observed_text(value.decode("utf-8", errors="ignore"))
        elif tlv_type == 7 and len(value) >= 4:  # System Capabilities
            enabled_caps = int.from_bytes(value[2:4], "big")

    dtype = infer_type_from_text(system_name, system_description)
    if not dtype:
        if enabled_caps & 0x0010:
            dtype = "Router"
        elif enabled_caps & 0x0008:
            dtype = "Access Point"
        elif enabled_caps & 0x0004:
            dtype = "Managed Switch"
        elif enabled_caps:
            dtype = "Network Device"

    return system_name, system_description, dtype


def connect_db():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = connect_db()
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            vendor TEXT,
            first_seen TEXT,
            last_seen TEXT,
            status TEXT
        )
    """)

    migrations = {
        "hostname": "TEXT",
        "device_type": "TEXT",
        "model": "TEXT",
        "model_score": "INTEGER DEFAULT 0",
        "model_source": "TEXT",
        "dhcp_signature": "TEXT",
        "class_score": "INTEGER DEFAULT 0",
        "class_source": "TEXT",
        "is_monitored": "INTEGER DEFAULT 0",
        "last_span_seen": "TEXT",
        "session_seen": "INTEGER DEFAULT 0",
        "upnp_location": "TEXT",
        "vendor_class": "TEXT",
        "is_ap_client": "INTEGER DEFAULT 0",
        "ap_associated": "INTEGER DEFAULT 0",
        "last_ap_seen": "TEXT",
        "membership_source": "TEXT",
        # v11 keeps discovery, traffic visibility, and AP association separate.
        "discovered_current": "INTEGER DEFAULT 0",
        "last_discovery_seen": "TEXT",
        "traffic_seen": "INTEGER DEFAULT 0",
        "last_traffic_seen": "TEXT",
        # Set when `vendor` came from inference (e.g. "inferred: model")
        # rather than a real OUI lookup -- see vendor_from_model()/
        # display_vendor(). Added ahead of the inference feature itself so
        # the backfill below can guard against ever overwriting an inferred
        # vendor.
        "vendor_source": "TEXT",
        # User recognition state, set only via the API (PUT /devices/{mac}/trust)
        # and never written or reset by discovery. Separate from classification,
        # device_type, and monitoring: marking a device Trusted does not change
        # discovery, traffic capture, or later anomaly detection. Defaults to 0
        # (Unrecognized) so every newly discovered device starts untrusted.
        "trusted": "INTEGER NOT NULL DEFAULT 0",
        # Per-family last-seen address columns. The legacy `ip` column keeps its
        # existing behaviour (last address of ANY family), which is what made the
        # same card flip between IPv4, global IPv6 and link-local fe80:: forms.
        # These additive columns record the last address of each family
        # separately so the API can present one stable address (IPv4 preferred,
        # then global IPv6, then fe80:: only as a last resort). MAC stays the
        # device identity; nothing here feeds classification.
        "last_ipv4": "TEXT",
        "last_ipv6_global": "TEXT",
        "last_ipv6_ll": "TEXT",
    }

    existing = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
    for column, definition in migrations.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE devices ADD COLUMN {column} {definition}")

    # Preserve legacy addresses before another family overwrites devices.ip.
    for mac, ip in conn.execute("SELECT mac, ip FROM devices WHERE ip IS NOT NULL").fetchall():
        family = _ip_family_column(ip)
        if family:
            conn.execute(f"UPDATE devices SET {family}=COALESCE({family}, ?) WHERE mac=?", (ip, mac))

    # One-time (but idempotent) cleanup of fake vendor text previously stored
    # for randomized MACs (e.g. "(locally administered / randomized MAC)",
    # arp-scan's own "(Unknown: locally administered)" with DUP suffixes,
    # "(randomised address)", etc.). The locally-administered bit alone is
    # NOT enough to decide a vendor is fake: a device can self-report a real
    # manufacturer (e.g. a UPnP/mDNS "manufacturer=" field) while using a
    # randomized MAC, and that genuine value must survive. So this also
    # requires the stored text itself to look like one of the known
    # placeholder wordings -- vendor_source IS NULL additionally guards
    # against ever wiping a real inferred vendor (vendor_source starting
    # with "inferred"), which is stored in this same column for exactly
    # these MACs and must never be reset on every service restart.
    conn.execute("""
        UPDATE devices SET vendor = NULL
        WHERE vendor IS NOT NULL
          AND vendor_source IS NULL
          AND substr(mac, 2, 1) IN ('2','3','6','7','a','A','b','B','e','E','f','F')
          AND (
              lower(vendor) LIKE '%unknown%'
              OR lower(vendor) LIKE '%locally administered%'
              OR lower(vendor) LIKE '%random%'
          )
    """)

    # Globally administered MACs never match the locally-administered cleanup
    # above, so a genuine missing-OUI arp-scan placeholder that leaked past
    # normalization (e.g. the "(Unknown) (DUP: 2)" stored before
    # normalize_arpscan_vendor() existed) would otherwise persist forever.
    # Reset ONLY the exact known arp-scan unknown placeholders -- with or
    # without a trailing "(DUP: N)" annotation -- so a real vendor is never
    # cleared. vendor_source IS NULL guards inferred vendors as above.
    conn.execute("""
        UPDATE devices SET vendor = NULL
        WHERE vendor IS NOT NULL
          AND vendor_source IS NULL
          AND substr(mac, 2, 1) NOT IN ('2','3','6','7','a','A','b','B','e','E','f','F')
          AND (
              vendor IN ('(Unknown)', 'Unknown')
              OR vendor LIKE '(Unknown) (DUP: %)'
              OR vendor LIKE 'Unknown (DUP: %)'
          )
    """)

    # Persistent app settings, single row (id is pinned to 1). This is the
    # canonical schema owner; api.py has a narrow guard that creates the same
    # table if it must answer GET/PUT /settings before discovery has restarted.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            id            INTEGER PRIMARY KEY CHECK (id = 1),
            active_probes INTEGER NOT NULL DEFAULT 0
        )
    """)
    # New installations default to OFF. A persisted user choice survives restart.
    env_seed = 0  # PBI-25: new installations require explicit user opt-in.
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (id, active_probes) VALUES (1, ?)",
        (env_seed,),
    )

    conn.commit()
    conn.close()


def read_active_probes_setting():
    """Return the persisted active_probes flag as a bool.

    Returns None if the value could not be read (e.g. a transient DB error), so
    callers can keep the current runtime state rather than flap the probe gates.
    A missing row means "not seeded yet" and reads as False (the default).
    """
    try:
        conn = connect_db()
        try:
            row = conn.execute(
                "SELECT active_probes FROM app_settings WHERE id = 1"
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    return False if row is None else bool(row[0])


def reload_runtime_settings():
    """Apply the persisted active_probes flag to all optional identification probes.

    active_probes is the single user switch exposed by api.py (GET/PUT /settings)
    and the Flutter app. It gates the optional active identification probes together
    -- unicast mDNS, NBNS, SSDP/UPnP, and the limited nmap probe -- and nothing
    else: passive sniffing, ARP discovery, inventory, Suricata, and passive-
    evidence classification are untouched. SSDP/UPnP shares this same switch. Called at startup
    and periodically (housekeeping), so a change saved in the app applies without
    a manual restart. On a transient read failure the gates are left as-is.
    """
    global ENABLE_MDNS_PROBE, ENABLE_NBNS_PROBE, ENABLE_ACTIVE_PROBE, ENABLE_UPNP_ENRICHMENT
    active = read_active_probes_setting()
    if active is None:
        return None
    ENABLE_MDNS_PROBE = active
    ENABLE_NBNS_PROBE = active
    ENABLE_ACTIVE_PROBE = active
    ENABLE_UPNP_ENRICHMENT = active
    return active


def load_oui():
    """Use arp-scan's registry first, filling gaps from installed Nmap data."""
    loaded = {}
    for path in (OUI_FILE, *OUI_FALLBACK_FILES):
        try:
            with open(path, encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) != 2:
                        continue
                    prefix = parts[0].replace(":", "").replace("-", "").lower()
                    if not re.fullmatch(r"(?:[0-9a-f]{6}|[0-9a-f]{7}|[0-9a-f]{9})", prefix):
                        continue
                    vendor = parts[1].strip()
                    if vendor:
                        loaded.setdefault(prefix, vendor)
        except OSError:
            continue
    oui_dict.clear()
    oui_dict.update(loaded)
    print(f"[*] Loaded {len(oui_dict)} OUI/vendor prefixes")


def load_gateway():
    global DISCOVERY_INTERFACE

    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True,
            timeout=5,
        )
        for line in out.splitlines():
            if not line.startswith("default "):
                continue

            parts = line.split()

            if "via" in parts:
                gw = parts[parts.index("via") + 1]
                infra_hints[gw] = "Router"
                print(f"[*] Gateway detected: {gw}")

            if DISCOVERY_INTERFACE is None and "dev" in parts:
                DISCOVERY_INTERFACE = parts[parts.index("dev") + 1]
                print(
                    f"[*] Discovery interface auto-detected: "
                    f"{DISCOVERY_INTERFACE}"
                )
            return
    except Exception as exc:
        print(f"[!] Could not determine default route: {exc}")


def load_network_context():
    """Learn ASSAS's own addresses and the subnet attached to discovery."""
    global discovery_ipv4
    local_macs.clear()
    local_ips.clear()
    monitored_networks.clear()
    discovery_ipv4 = None

    net_root = "/sys/class/net"
    if os.path.isdir(net_root):
        for iface in os.listdir(net_root):
            try:
                path = os.path.join(net_root, iface, "address")
                with open(path, "r", encoding="ascii") as f:
                    mac = f.read().strip().lower()
                if mac:
                    local_macs.add(mac)
            except OSError:
                pass

    try:
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show"],
            text=True,
            timeout=5,
        )
        for line in out.splitlines():
            match = re.search(r"\binet\s+(\d+(?:\.\d+){3})/(\d+)\b", line)
            if match:
                local_ips.add(match.group(1))
    except Exception as exc:
        print(f"[!] Could not read local IPv4 addresses: {exc}")

    if DISCOVERY_INTERFACE:
        try:
            out = subprocess.check_output(
                ["ip", "-4", "-o", "addr", "show", "dev", DISCOVERY_INTERFACE],
                text=True,
                timeout=5,
            )
            for line in out.splitlines():
                match = re.search(r"\binet\s+(\d+(?:\.\d+){3}/\d+)\b", line)
                if match:
                    iface_cidr = match.group(1)
                    if discovery_ipv4 is None:
                        discovery_ipv4 = iface_cidr.split("/", 1)[0]
                    monitored_networks.append(
                        ipaddress.ip_network(iface_cidr, strict=False)
                    )
            if monitored_networks:
                print(
                    "[*] Discovery subnet: "
                    + ", ".join(str(n) for n in monitored_networks)
                )
        except Exception as exc:
            print(f"[!] Could not determine discovery subnet: {exc}")


def load_ipv6_context():
    if not DISCOVERY_INTERFACE:
        return
    try:
        out = subprocess.check_output(
            ["ip", "-6", "-o", "addr", "show", "dev", DISCOVERY_INTERFACE],
            text=True, timeout=5)
        for cidr in re.findall(r"\binet6\s+([0-9a-fA-F:]+/\d+)", out):
            interface = ipaddress.ip_interface(cidr)
            local_ips.add(str(interface.ip))
            monitored_networks.append(interface.network)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"[!] Could not read local IPv6 context: {exc}")


def purge_self_records():
    """Remove stale records that belong to the ASSAS appliance itself."""
    clauses = []
    params = []
    if local_macs:
        placeholders = ",".join("?" for _ in local_macs)
        clauses.append(f"LOWER(mac) IN ({placeholders})")
        params.extend(sorted(m.lower() for m in local_macs))
    if local_ips:
        placeholders = ",".join("?" for _ in local_ips)
        clauses.append(f"ip IN ({placeholders})")
        params.extend(sorted(local_ips))
    if not clauses:
        return

    with db_lock:
        conn = connect_db()
        cur = conn.execute(
            "DELETE FROM devices WHERE " + " OR ".join(clauses),
            tuple(params),
        )
        removed = cur.rowcount
        conn.commit()
        conn.close()
    if removed:
        print(f"[*] Removed {removed} stale ASSAS self-record(s) from inventory")


def reset_session_state():
    """Start a fresh runtime view without deleting historical inventory."""
    with db_lock:
        conn = connect_db()
        # These are runtime/current-state flags only. Historical evidence remains.
        conn.execute(
            "UPDATE devices SET session_seen=0, discovered_current=0, ap_associated=0"
        )
        conn.execute(
            "UPDATE devices SET status='offline' "
            "WHERE status IN ('online','candidate','observed')"
        )
        conn.commit()
        conn.close()


def _normalize_mac(raw):
    if not raw:
        return None
    mac = str(raw).strip().lower().replace("-", ":")
    if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        return mac
    return None


def _tplink_auth_cookie(password_value):
    raw = f"{AP_USER}:{password_value}".encode("utf-8")
    token = base64.b64encode(raw).decode("ascii")
    # Old-style TP-Link web UIs store the Basic token in an Authorization
    # cookie rather than using standard HTTP Basic auth headers.
    return "Authorization=" + urllib.parse.quote("Basic " + token, safe="")


def _http_get_text(url, headers=None, timeout=3.0):
    req = urllib.request.Request(
        url,
        headers=headers or {},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(512 * 1024).decode("utf-8", errors="ignore")


def _extract_tplink_session_token(text):
    patterns = [
        r"https?://[^/]+/([A-Za-z0-9_-]{8,})/userRpm/",
        r"location(?:\.href)?\s*=\s*['\"](?:https?://[^/]+)?/([A-Za-z0-9_-]{8,})/userRpm/",
        r"/([A-Za-z0-9_-]{8,})/userRpm/(?:Index|Status|WlanStation)Rpm\.htm",
    ]
    for pattern in patterns:
        match = re.search(pattern, text or "", re.I)
        if match:
            return match.group(1)
    return None


def _parse_tplink_station_page(text):
    """Return wireless-station MACs from TL-WR802N Wireless Statistics HTML."""
    if not text:
        return set(), False

    station_macs = set()
    # The classic TP-Link UI exposes current clients in JS hostList arrays.
    blocks = re.findall(
        r"var\s+hostList\s*=\s*new\s+Array\s*\((.*?)\);",
        text,
        flags=re.I | re.S,
    )
    for block in blocks:
        for raw in re.findall(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", block):
            mac = _normalize_mac(raw)
            if mac:
                station_macs.add(mac)

    page_is_station_page = bool(
        blocks
        or re.search(r"Wireless\s+Stations?.*Connected", text, re.I | re.S)
        or re.search(r"Wireless\s+Statistics", text, re.I)
        or "wlanHostPara" in text
    )

    # Some firmware renders a literal table instead of a hostList array.
    # Only use the whole-page fallback after positively identifying the page.
    if page_is_station_page and not blocks:
        for raw in re.findall(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", text):
            mac = _normalize_mac(raw)
            if mac:
                station_macs.add(mac)

    station_macs.discard(_normalize_mac(AP_MAC))
    return station_macs, page_is_station_page


def _tplink_authenticate():
    """Full TP-Link login sequence: try md5-cookie, plain-cookie, then HTTP Basic.

    Returns (mode, headers, station_url) on success, or (None, None, None).
    Does not fetch the station list itself -- callers do that with the
    returned headers/station_url, and may cache them via _tplink_auth_cache.
    """
    if not AP_PASSWORD:
        return None, None, None

    login_url = f"{AP_URL}/userRpm/LoginRpm.htm?Save=Save"
    variants = [
        ("md5-cookie", hashlib.md5(AP_PASSWORD.encode("utf-8")).hexdigest()),
        ("plain-cookie", AP_PASSWORD),
    ]

    for mode, password_value in variants:
        cookie = _tplink_auth_cookie(password_value)
        headers = {
            "Cookie": cookie,
            "Referer": AP_URL + "/",
            "User-Agent": "ASSAS/1.0 TP-Link station reader",
        }
        try:
            login_text = _http_get_text(login_url, headers=headers, timeout=3.0)
            token = _extract_tplink_session_token(login_text)
            if not token:
                # Some firmware families allow the station page directly.
                station_url = f"{AP_URL}/userRpm/WlanStationRpm.htm?Page=1"
            else:
                station_url = f"{AP_URL}/{token}/userRpm/WlanStationRpm.htm?Page=1"

            station_headers = dict(headers)
            station_headers["Referer"] = station_url
            text = _http_get_text(station_url, headers=station_headers, timeout=3.0)
            clients, ok = _parse_tplink_station_page(text)
            if ok:
                return mode, station_headers, station_url
        except Exception:
            pass

    # Final compatibility path for firmware that really uses HTTP Basic.
    try:
        basic = base64.b64encode(
            f"{AP_USER}:{AP_PASSWORD}".encode("utf-8")
        ).decode("ascii")
        station_url = f"{AP_URL}/userRpm/WlanStationRpm.htm?Page=1"
        headers = {
            "Authorization": "Basic " + basic,
            "Referer": station_url,
            "User-Agent": "ASSAS/1.0 TP-Link station reader",
        }
        text = _http_get_text(station_url, headers=headers, timeout=3.0)
        clients, ok = _parse_tplink_station_page(text)
        if ok:
            return "HTTP Basic", headers, station_url
    except Exception:
        pass

    return None, None, None


def _fetch_tplink_clients_with_password():
    """Query TL-WR802N Wireless Statistics without logging the password.

    Re-authenticating on every poll (every AP_POLL_SECONDS, default 5s) is
    wasteful and noisy against the AP, so a successful auth is cached for
    TPLINK_AUTH_TTL_SECONDS and reused with a cheap GET; a full re-auth only
    happens when the cache is stale or the cached session stops working.
    """
    if not AP_PASSWORD:
        return None, "ASSAS_AP_PASSWORD is not set"

    now = time.monotonic()
    cache = _tplink_auth_cache
    cache_fresh = cache["time"] is not None and (now - cache["time"]) < TPLINK_AUTH_TTL_SECONDS

    if cache_fresh:
        try:
            text = _http_get_text(cache["station_url"], headers=cache["headers"], timeout=3.0)
            clients, ok = _parse_tplink_station_page(text)
            if ok:
                return clients, f"TP-Link Wireless Statistics ({cache['mode']}, cached session)"
        except Exception:
            pass
        # Cached session no longer works -- fall through to a full re-auth.
        cache["time"] = None

    mode, headers, station_url = _tplink_authenticate()
    if mode is None:
        return None, "authentication failed"

    cache.update(mode=mode, headers=headers, station_url=station_url, time=now)
    try:
        text = _http_get_text(station_url, headers=headers, timeout=3.0)
        clients, ok = _parse_tplink_station_page(text)
        if ok:
            return clients, f"TP-Link Wireless Statistics ({mode})"
    except Exception as exc:
        return None, str(exc)

    return None, "router replied, but Wireless Statistics could not be parsed"


def fetch_ap_clients():
    """Return (clients, source, error). None clients means provider failure."""
    if AP_PASSWORD:
        clients, result = _fetch_tplink_clients_with_password()
        if clients is not None:
            return clients, result, None
        if MANUAL_AP_CLIENTS:
            return set(MANUAL_AP_CLIENTS), "ASSAS_AP_CLIENTS fallback", result
        return None, None, result

    if MANUAL_AP_CLIENTS:
        return set(MANUAL_AP_CLIENTS), "ASSAS_AP_CLIENTS", None

    return None, None, (
        "no AP membership provider configured; set ASSAS_AP_PASSWORD locally "
        "or ASSAS_AP_CLIENTS for a manual test"
    )


def apply_ap_membership(clients, source):
    """Record Assas-Test association as an independent inventory attribute."""
    global last_ap_membership
    clients = {_normalize_mac(m) for m in clients}
    clients.discard(None)
    clients.discard(_normalize_mac(AP_MAC))
    now = datetime.now().isoformat(timespec="seconds")

    with ap_membership_lock:
        previous = set(last_ap_membership)

        # Ensure associated stations exist in the inventory even if an idle client
        # did not answer the initial ARP scan. Association does not imply SPAN traffic.
        for mac in sorted(clients):
            update_device(mac, vendor=get_vendor(mac), seen_on_span=False, seen_in_discovery=False)

        with db_lock:
            conn = connect_db()
            conn.execute(
                "UPDATE devices SET ap_associated=0, "
                "status=CASE WHEN COALESCE(discovered_current,0)=1 THEN 'online' "
                "ELSE 'offline' END "
                "WHERE COALESCE(ap_associated,0)=1"
            )
            for mac in sorted(clients):
                conn.execute(
                    "UPDATE devices SET is_ap_client=1, ap_associated=1, "
                    "last_ap_seen=?, membership_source=?, status='online', last_seen=? "
                    "WHERE mac=?",
                    (now, source, now, mac),
                )
            conn.commit()
            conn.close()

        joined = clients - previous
        left = previous - clients
        for mac in sorted(joined):
            print(f"[ASSOCIATED] {mac} joined {AP_SSID}")
        for mac in sorted(left):
            print(f"[DISASSOCIATED] {mac} left {AP_SSID}")
        last_ap_membership = set(clients)

    # AP membership is useful for this attribute only. Optional enrichment may
    # still use the client's IP, but association never becomes inventory membership.
    if ENABLE_UPNP_ENRICHMENT and clients:
        with db_lock:
            conn = connect_db()
            targets = {
                ip: mac for mac, ip in conn.execute(
                    "SELECT mac, ip FROM devices "
                    "WHERE COALESCE(ap_associated,0)=1 AND ip IS NOT NULL"
                ).fetchall()
            }
            conn.close()
        if targets:
            threading.Thread(
                target=probe_ssdp_for_targets,
                args=(targets,),
                daemon=True,
            ).start()


def refresh_ap_membership(verbose=False):
    global last_ap_error
    clients, source, error = fetch_ap_clients()
    if clients is None:
        if verbose or error != last_ap_error:
            print(f"[!] AP membership unavailable: {error}")
        last_ap_error = error
        return False

    last_ap_error = None
    apply_ap_membership(clients, source)
    if verbose:
        print(
            f"[*] AP membership source: {source}; "
            f"{len(clients)} station(s) associated to {AP_SSID}"
        )
    return True


def ap_membership_loop():
    while True:
        time.sleep(AP_POLL_SECONDS)
        refresh_ap_membership(verbose=False)


def is_current_ap_client(mac):
    mac = _normalize_mac(mac)
    if not mac:
        return False
    with ap_membership_lock:
        return mac in last_ap_membership


def test_ap_membership():
    clients, source, error = fetch_ap_clients()
    if clients is None:
        print(f"[!] Could not read AP wireless stations: {error}")
        return 1
    print(f"[*] Membership source: {source}")
    print(f"[*] SSID: {AP_SSID}")
    print(f"[*] Associated stations: {len(clients)}")
    for mac in sorted(clients):
        print(f"    {mac.upper()}")
    return 0


def _rebind_local_url(url, ip):
    """Reuse a saved UPnP path when a known device's DHCP address changes."""
    if not url or not ip:
        return url
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return url
        port = f":{parsed.port}" if parsed.port else ""
        return urllib.parse.urlunparse(
            (parsed.scheme, f"{ip}{port}", parsed.path or "/",
             parsed.params, parsed.query, parsed.fragment)
        )
    except (ValueError, TypeError):
        return url


def probe_ssdp_for_targets(targets):
    """Optional one-shot SSDP enrichment for already-known local devices."""
    if not ENABLE_UPNP_ENRICHMENT or not targets or not discovery_ipv4:
        return

    # targets is {ip: mac}; only those replies are accepted.
    targets = {ip: mac.lower() for ip, mac in targets.items()
               if ip and mac and probe_target_current(mac.lower(), ip, "ENABLE_UPNP_ENRICHMENT")}
    if not targets:
        return

    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                        socket.inet_aton(discovery_ipv4))
        sock.bind((discovery_ipv4, 0))
        sock.settimeout(0.25)
        sock.sendto(message, SSDP_MULTICAST)
        deadline = time.monotonic() + SSDP_PROBE_TIMEOUT_SECONDS
        hits = set()

        while time.monotonic() < deadline:
            try:
                payload, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            ip = addr[0]
            mac = targets.get(ip)
            if not mac:
                continue
            location = extract_ssdp_location(payload)
            if not location:
                continue
            hits.add(mac)
            # Active metadata replies enrich an already-known device only.
            # They do not alter discovery, traffic, or AP-association state.
            update_device(
                mac, ip=ip, upnp_location=location,
                mark_current=False, seen_on_span=False,
            )
            schedule_upnp_enrichment(
                mac, ip, location, span_confirmed=False
            )

        if hits:
            print(f"[*] Fast UPnP enrichment found metadata for {len(hits)} local device(s)")
    except OSError as exc:
        print(f"[!] Fast SSDP enrichment unavailable: {exc}")
    finally:
        if sock is not None:
            sock.close()


def schedule_ssdp_probe(mac, ip):
    def ssdp_worker(target_mac, target_ip):
        if probe_target_current(target_mac, target_ip, "ENABLE_UPNP_ENRICHMENT"):
            probe_ssdp_for_targets({target_ip: target_mac})
    schedule_bounded_probe(mac, ip, "ENABLE_UPNP_ENRICHMENT",
                           ssdp_targets_probed, ssdp_probe_lock, ssdp_worker)



def probe_target_current(mac, ip, flag):
    """Do not probe an old address or apply its reply to a moved device."""
    if not globals()[flag] or not ip or not local_monitored_ip(ip):
        return False
    # Read the persisted switch before sending; do not wait for periodic reload.
    if read_active_probes_setting() is not True:
        return False
    # Current light-active transports use IPv4 sockets/nmap invocation.
    if ipaddress.ip_address(ip).version != 4:
        return False
    with db_lock:
        conn = connect_db()
        try:
            row = conn.execute("SELECT ip FROM devices WHERE mac=?", (mac,)).fetchone()
            return row is not None and row[0] == ip
        finally:
            conn.close()


PROBE_RETRY_SECONDS = 60
PROBE_MAX_ATTEMPTS = 3
probe_attempts = {}


def schedule_bounded_probe(mac, ip, flag, pending, lock, worker):
    if not globals()[flag] or not ip:
        return
    mac = mac.lower()
    key = (flag, mac, ip, worker.__name__)
    with lock:
        count, last = probe_attempts.get(key, (0, float('-inf')))
        if mac in pending or count >= PROBE_MAX_ATTEMPTS or time.monotonic()-last < PROBE_RETRY_SECONDS:
            return
        pending.add(mac)
        probe_attempts[key] = (count+1, time.monotonic())
    def run():
        try:
            worker(mac, ip)
        except (sqlite3.Error, OSError) as exc:
            print(f"[PROBE-ERR] {mac}: {exc}")
        finally:
            with lock:
                pending.discard(mac)
                probe_attempts[key] = (count+1, time.monotonic())
    threading.Thread(target=run, daemon=True).start()


def probe_device_ports(mac, ip):
    """One-time active nmap fallback for a device that stays unclassified.

    Opt-in via ASSAS_ACTIVE_PROBE=1. Waits ACTIVE_PROBE_DELAY_SECONDS, then
    re-checks the device is still unclassified before sending any packets --
    the delay gives passive evidence (mDNS/SSDP/DHCP/hostname/etc.) a chance
    to classify the device first, so the probe is a last resort.
    """
    time.sleep(ACTIVE_PROBE_DELAY_SECONDS)
    if not probe_target_current(mac, ip, "ENABLE_ACTIVE_PROBE"):
        print(f"[PROBE-SKIP] {mac} ({ip}) disabled or changed target")
        return

    with db_lock:
        conn = connect_db()
        row = conn.execute(
            "SELECT device_type, class_score FROM devices WHERE mac=?", (mac,)
        ).fetchone()
        conn.close()
    if row is None or not needs_service_probe(row[0], row[1]):
        reason = "no DB row" if row is None else f"already classified as {row[0]}"
        print(f"[PROBE-SKIP] {mac} ({ip}) {reason}")
        return

    try:
        with NMAP_PROBE_SLOTS:
            if not probe_target_current(mac, ip, "ENABLE_ACTIVE_PROBE"):
                return
            out = subprocess.check_output(
                ["nmap", "-n", "-Pn", "-sT", "-sV", "--version-light",
                 "--host-timeout", "30s", "--max-retries", "1", "-T3",
                 "-oX", "-", "-p", ACTIVE_PROBE_PORTS, ip],
                text=True, stderr=subprocess.DEVNULL, timeout=60,
            )
    except Exception as exc:
        if isinstance(exc, FileNotFoundError):
            print(f"[PROBE-ERR] {mac} ({ip}) nmap not installed")
        elif isinstance(exc, subprocess.TimeoutExpired):
            print(f"[PROBE-TIMEOUT] {mac} ({ip}) nmap timed out")
        else:
            print(f"[PROBE-ERR] {mac} ({ip}) nmap failed: {exc}")
        return

    if not probe_target_current(mac, ip, "ENABLE_ACTIVE_PROBE"):
        return
    try:
        candidate, open_ports = parse_nmap_identity(out, ip)
    except ValueError:
        print(f"[PROBE-ERR] {mac} ({ip}) invalid nmap output")
        return
    if candidate:
        print(f"[PROBED] {mac} ({ip}) -> {candidate[0]} via {candidate[2]}")
        update_device(mac, ip=ip, candidate=candidate)
    elif open_ports:
        print(f"[PROBE-NORESULT] {mac} ({ip}) open ports {open_ports} but no type hint")
    else:
        print(f"[PROBE-NORESULT] {mac} ({ip}) no open ports")


def _name_enrichment_eligible(device_type, hostname):
    """Eligible for the NAME probes (existing mDNS/NBNS) when a device is still
    unclassified OR has no usable hostname yet.

    Broader than is_unclassified() on purpose: a device can be confidently
    classified (e.g. "Apple Device") yet still have no name, and those should
    get one more chance at a name. The one-time-per-runtime probed-set guards
    and the probe workers' own re-checks keep this from probing repeatedly or
    probing a device that already has a usable hostname.
    """
    return needs_type_probe(device_type) or not (hostname or "").strip()


def _probe_type_candidate_allowed(stored_type, candidate):
    """Keep a general OS verdict sticky against weak probe evidence.

    A probe may refine a general type (e.g. "Android Device") only with
    port-tier evidence or stronger; a weak-tier type hint -- an NBNS responder,
    an AirPlay/RAOP/SMB/SSH/ONVIF mDNS service -- must not flip it to a wrong
    specific type. Returns the candidate unchanged for non-general stored types
    (the normal score-based merge in update_device applies), and None when a
    weak candidate is suppressed. The device's name/model enrichment is passed
    to update_device separately and is unaffected.
    """
    if candidate and is_general_type(stored_type) and candidate[1] < SCORES["port"]:
        return None
    return candidate


def schedule_active_probe(mac, ip):
    schedule_bounded_probe(mac, ip, "ENABLE_ACTIVE_PROBE", active_probed, active_probe_lock, probe_device_ports)



def _mdns_query_packet(names, qtype="PTR"):
    """Build one DNS-SD query for the given names (unicast mDNS)."""
    return DNS(rd=0, qd=[DNSQR(qname=n, qtype=qtype) for n in names])


def _mdns_unicast_query(ip, names, qtype="PTR", timeout=2.0):
    """Send one unicast DNS-SD query to ip:5353 and collect replies.

    Uses a plain UDP socket (no raw-socket/root needed) and is fully
    self-contained -- it does not rely on the reply being SPAN-mirrored.
    Returns a list of parsed scapy DNS objects.
    """
    raw = bytes(_mdns_query_packet(names, qtype))
    replies = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(raw, (ip, 5353))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                break
            if not data:
                continue
            try:
                replies.append(DNS(data))
            except Exception:
                continue
    finally:
        sock.close()
    return replies


def _mdns_device_info_instance(pkt):
    """Return the _device-info._tcp PTR instance name in an mDNS reply, or None.

    A _device-info._tcp PTR record only names the service instance; its
    model= key lives in the instance's TXT record, which a device may omit
    from the enumeration reply -- in which case a follow-up TXT query for
    this instance name is needed.
    """
    if DNS not in pkt:
        return None
    for section in ("an", "ns", "ar"):
        for rr in _dns_rrs(getattr(pkt[DNS], section, None)):
            try:
                if int(rr.type) != 12:  # PTR
                    continue
            except (TypeError, ValueError):
                continue
            rrname = getattr(rr, "rrname", b"")
            rrname = (rrname.decode("utf-8", errors="ignore")
                      if isinstance(rrname, bytes) else str(rrname))
            if "_device-info._tcp" not in rrname.lower():
                continue
            rdata = getattr(rr, "rdata", None)
            if isinstance(rdata, bytes):
                rdata = rdata.decode("utf-8", errors="ignore")
            if rdata:
                return str(rdata).rstrip(".")
    return None


def _mdns_needs_followup_txt(pkt):
    """True if a reply has a _device-info instance but no usable model TXT yet."""
    model = extract_mdns_metadata(pkt)[0]
    if model:
        return False
    return _mdns_device_info_instance(pkt) is not None


def _apply_mdns_reply(mac, ip, pkt, stored_type=None):
    """Route one probe mDNS reply through the same pipeline as passive mDNS.

    Returns True if the reply yielded a usable model (so no follow-up TXT
    query is needed). When stored_type is a general OS verdict, a weak-tier
    type hint from this reply is suppressed (see _probe_type_candidate_allowed)
    while name/model enrichment still applies; the passive caller passes no
    stored_type, so its behavior is unchanged.
    """
    raw = bytes(pkt)
    candidate = None
    candidate = merge_candidate(
        candidate, type_from_payload(raw), SCORES["service"],
        "mDNS probe advertisement",
    )
    candidate = merge_candidate(
        candidate, weak_type_from_payload(raw), SCORES["weak_service"],
        "mDNS probe AirPlay/RAOP",
    )
    model, model_type, model_score, model_source, vendor, friendly = \
        extract_mdns_metadata(pkt)
    candidate = merge_candidate(
        candidate, model_type, SCORES["model"], "device model identifier"
    )
    hostname = None
    mdns_name, mdns_name_src = mdns_name_candidate(pkt, friendly)
    if mdns_name:
        hostname = mdns_name
        candidate = merge_candidate(
            candidate, type_from_hostname(mdns_name), SCORES["hostname"],
            f"{mdns_name_src} (probe)",
        )
    candidate = _probe_type_candidate_allowed(stored_type, candidate)
    if candidate or model or hostname or vendor:
        update_device(
            mac, ip=ip, vendor=vendor, hostname=hostname,
            model=model, model_score=model_score, model_source=model_source,
            candidate=candidate, seen_on_span=False,
        )
    return bool(model)


def mdns_probe_device(mac, ip):
    """One-time light-active unicast DNS-SD probe for an unclassified device.

    Opt-in via ASSAS_MDNS_PROBE=1. Waits MDNS_PROBE_DELAY_SECONDS to give
    passive evidence a chance first, re-checks the device is still
    unclassified, then sends a single DNS-SD enumeration query (with one
    follow-up TXT query only if _device-info gave an instance name but no
    model). All network I/O is best-effort and never affects capture.
    """
    time.sleep(MDNS_PROBE_DELAY_SECONDS)
    if not probe_target_current(mac, ip, "ENABLE_MDNS_PROBE"):
        return

    with db_lock:
        conn = connect_db()
        row = conn.execute(
            "SELECT device_type, hostname FROM devices WHERE mac=?", (mac,)
        ).fetchone()
        conn.close()
    if row is None or not _name_enrichment_eligible(row[0], row[1]):
        return
    stored_type = row[0]

    # Diagnostic start line so the journal can distinguish "probe ran but got
    # no usable reply" (common for randomized-MAC Android phones, which do not
    # answer unicast DNS-SD) from "probe never scheduled".
    print(f"[MDNS-PROBE] {mac} ({ip}) querying unicast DNS-SD")
    try:
        replies = _mdns_unicast_query(
            ip, ["_services._dns-sd._udp.local", "_device-info._tcp.local"],
            qtype="PTR",
        )
        model_found = False
        instance = None
        for pkt in replies:
            if not probe_target_current(mac, ip, "ENABLE_MDNS_PROBE"):
                return
            if _apply_mdns_reply(mac, ip, pkt, stored_type=stored_type):
                model_found = True
                print(f"[MDNS-PROBE] {mac} ({ip}) -> model via DNS-SD reply")
            if instance is None and _mdns_needs_followup_txt(pkt):
                instance = _mdns_device_info_instance(pkt)

        # Follow-up: the model= key lives in the instance's TXT record, which
        # may not have been included as an additional record above.
        if not model_found and instance and probe_target_current(mac, ip, "ENABLE_MDNS_PROBE"):
            for pkt in _mdns_unicast_query(ip, [instance], qtype="TXT"):
                if not probe_target_current(mac, ip, "ENABLE_MDNS_PROBE"):
                    return
                if _apply_mdns_reply(mac, ip, pkt, stored_type=stored_type):
                    model_found = True
                    print(f"[MDNS-PROBE] {mac} ({ip}) -> model via _device-info TXT")

        if not model_found:
            print(
                f"[MDNS-PROBE] {mac} ({ip}) no usable reply "
                f"({len(replies)} packet(s); device likely does not answer "
                "unicast DNS-SD, e.g. an Android phone)"
            )
    except Exception as exc:
        # Best-effort: a probe failure must never disturb passive capture.
        print(f"[MDNS-PROBE] {mac} ({ip}) probe error: {exc!r}")
        return


def schedule_mdns_probe(mac, ip):
    schedule_bounded_probe(mac, ip, "ENABLE_MDNS_PROBE", mdns_probed, mdns_probe_lock, mdns_probe_device)



def _nbns_nodestatus_request_packet():
    """Build a NetBIOS NBSTAT node-status request (qtype 0x21, name '*')."""
    return NBNSHeader(QDCOUNT=1) / NBNSNodeStatusRequest()


def _nbns_nodestatus_query(ip, timeout=2.0):
    """Send one unicast NBSTAT request to ip:137 and return a parsed
    node-status response, but only if it came from the probed IP.

    Uses a plain UDP socket (no raw-socket/root needed) and is fully
    self-contained. Returns the parsed NBNSHeader packet or None.
    """
    raw = bytes(_nbns_nodestatus_request_packet())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(raw, (ip, 137))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                break
            # Only trust a reply whose source IP is the device we probed.
            if not data or addr[0] != ip:
                continue
            try:
                pkt = NBNSHeader(data)
            except Exception:
                continue
            if NBNSNodeStatusResponse in pkt:
                return pkt
    finally:
        sock.close()
    return None


def nbns_probe_device(mac, ip):
    """One-time light-active unicast NBSTAT probe for an unclassified device.

    Opt-in via ASSAS_NBNS_PROBE=1. Waits NBNS_PROBE_DELAY_SECONDS, re-checks
    the device is still unclassified, then sends a single NBSTAT node-status
    request. A valid reply means the host runs a NetBIOS responder
    (Windows/Samba) -> weak "Computer" evidence; a unique 0x00/0x20 name in
    the reply becomes the hostname. Best-effort; never disturbs capture.
    """
    time.sleep(NBNS_PROBE_DELAY_SECONDS)
    if not probe_target_current(mac, ip, "ENABLE_NBNS_PROBE"):
        return

    with db_lock:
        conn = connect_db()
        row = conn.execute(
            "SELECT device_type, hostname FROM devices WHERE mac=?", (mac,)
        ).fetchone()
        conn.close()
    if row is None or not _name_enrichment_eligible(row[0], row[1]):
        return
    stored_type = row[0]

    print(f"[NBNS-PROBE] {mac} ({ip}) querying NBSTAT node status")
    try:
        reply = _nbns_nodestatus_query(ip)
        if not probe_target_current(mac, ip, "ENABLE_NBNS_PROBE"):
            return
        if reply is None:
            print(f"[NBNS-PROBE] {mac} ({ip}) no reply (no NetBIOS responder)")
            return

        # A valid NBSTAT reply means a NetBIOS responder is present -- weak
        # Computer evidence, low enough that any NAS/printer/service signal
        # (SCORES["service"]=85) always wins over it.
        candidate = merge_candidate(
            None, "Computer", SCORES["weak_service"], "NetBIOS responder"
        )
        name = extract_nbns_nodestatus_name(reply)
        hostname = None
        if name:
            hostname = name
            candidate = merge_candidate(
                candidate, type_from_hostname(name), SCORES["broadcast_name"],
                "NBNS name",
            )
        candidate = _probe_type_candidate_allowed(stored_type, candidate)
        update_device(
            mac, ip=ip, hostname=hostname, candidate=candidate,
            seen_on_span=False,
        )
        print(
            f"[NBNS-PROBE] {mac} ({ip}) -> NetBIOS responder"
            + (f", name {name}" if name else " (no unique name)")
        )
    except Exception as exc:
        # Best-effort: a probe failure must never disturb passive capture.
        print(f"[NBNS-PROBE] {mac} ({ip}) probe error: {exc!r}")
        return


def schedule_nbns_probe(mac, ip):
    schedule_bounded_probe(mac, ip, "ENABLE_NBNS_PROBE", nbns_probed, nbns_probe_lock, nbns_probe_device)



def warm_start_upnp_enrichment():
    """Immediately reuse saved SSDP locations for known devices seen this run."""
    if not ENABLE_UPNP_ENRICHMENT:
        return
    with db_lock:
        conn = connect_db()
        rows = conn.execute(
            "SELECT mac, ip, upnp_location FROM devices "
            "WHERE (COALESCE(discovered_current,0)=1 OR COALESCE(ap_associated,0)=1) "
            "AND upnp_location IS NOT NULL AND upnp_location<>''"
        ).fetchall()
        conn.close()

    scheduled = 0
    for mac, ip, url in rows:
        if not ip:
            continue
        url = _rebind_local_url(url, ip)
        schedule_upnp_enrichment(mac, ip, url, span_confirmed=False)
        scheduled += 1
    if scheduled:
        print(f"[*] Warm-start UPnP enrichment scheduled for {scheduled} current inventory device(s)")




def fast_start_upnp_enrichment():
    """Issue one bounded SSDP probe for devices in the current subnet inventory."""
    if not ENABLE_UPNP_ENRICHMENT or not discovery_ipv4:
        return
    with db_lock:
        conn = connect_db()
        rows = conn.execute(
            "SELECT mac, ip FROM devices "
            "WHERE COALESCE(discovered_current,0)=1 AND ip IS NOT NULL"
        ).fetchall()
        conn.close()
    targets = {ip: mac for mac, ip in rows if ip}
    if not targets:
        return
    threading.Thread(
        target=probe_ssdp_for_targets,
        args=(targets,),
        daemon=True,
    ).start()

def is_self_device(mac=None, ip=None):
    if mac and mac.lower() in local_macs:
        return True
    if ip and ip in local_ips:
        return True
    return False


def local_monitored_ip(ip):
    """Return an IP only when it belongs to the local discovery subnet."""
    if not ip or ip == "0.0.0.0":
        return None

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    if addr.version == 6 and addr.is_link_local:
        return ip
    if monitored_networks and not any(
        addr.version == network.version and addr in network for network in monitored_networks
    ):
        return None

    return ip


def _ip_family_column(ip):
    """Map an observed address to its dedicated per-family column name.

    Returns "last_ipv4" for an IPv4 address, "last_ipv6_global" for a routable
    IPv6 address, "last_ipv6_ll" for a link-local fe80:: address, or None when
    the value is empty or unparseable. update_device() uses this to additively
    record the last address of each family for a MAC so the API never flips a
    device card between address forms. Any IPv6 zone suffix (e.g. "%eth0") is
    stripped before parsing. The return value is always one of a fixed set of
    column names, so it is safe to interpolate into the UPDATE statement.
    """
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return None
    if addr.version == 4:
        return "last_ipv4"
    if addr.is_link_local:
        return "last_ipv6_ll"
    return "last_ipv6_global"


def is_valid_host_mac(mac):
    try:
        mac = mac.lower()
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False

    if mac == "00:00:00:00:00:00":
        return False
    if first & 0x01:  # multicast/broadcast source
        return False
    return True




def get_vendor(mac):
    if is_locally_administered_mac(mac):
        return None

    plain = re.sub(r"[^0-9A-Fa-f]", "", mac).lower()

    # Some arp-scan files include 36/28/24-bit prefixes.
    for length in (9, 7, 6):
        vendor = oui_dict.get(plain[:length])
        if vendor:
            return vendor
    return None




def extract_friendly_name(payload):
    if not payload:
        return None
    for pattern in FRIENDLY_NAME_PATTERNS:
        match = pattern.search(payload)
        if match:
            value = match.group(1).decode("utf-8", errors="ignore")
            value = clean_observed_text(value)
            if value:
                return value
    return None


def is_local_metadata_url(url):
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        host = ipaddress.ip_address(parsed.hostname)
    except (ValueError, TypeError):
        return False

    return any(host in network for network in monitored_networks)


def xml_text(root, wanted):
    wanted = wanted.lower()
    for elem in root.iter():
        tag = elem.tag.split("}", 1)[-1].lower()
        if tag == wanted and elem.text:
            value = clean_observed_text(elem.text)
            if value:
                return value
    return None


def infer_type_from_text(*values):
    text = " ".join(v for v in values if v).lower()
    if not text:
        return None

    # Service/device-class terms first.
    generic = [
        ("printer", "Printer"),
        ("scanner", "Printer / Scanner"),
        ("camera", "Security Camera"),
        ("videotransmitter", "Security Camera"),
        ("mediarenderer", "Smart TV / Media Device"),
        ("television", "Smart TV / Media Device"),
        ("smart tv", "Smart TV / Media Device"),
        ("speaker", "Smart Speaker / Media Device"),
        ("router", "Router"),
        ("gateway", "Router"),
        ("access point", "Network Device"),
        ("switch", "Managed Switch"),
        ("nas", "NAS / Server"),
        ("storage", "NAS / Server"),
        ("xbox", "Game Console"),
        ("playstation", "Game Console"),
        ("nintendo", "Game Console"),
    ]
    for needle, dtype in generic:
        if needle in text:
            return dtype

    for value in values:
        dtype = type_from_model(value) or type_from_hostname(value)
        if dtype:
            return dtype
    return None


def _looks_specific_model_code(value):
    """True for product-like identifiers such as HG8245W5 or UA65MU7350."""
    value = clean_observed_text(value)
    if not value:
        return False
    compact = re.sub(r"[\s._-]+", "", value)
    return (
        len(compact) >= 5
        and re.search(r"[A-Za-z]", compact) is not None
        and re.search(r"\d", compact) is not None
    )


def _is_protocol_or_version_label(value):
    value = clean_observed_text(value)
    if not value:
        return True
    low = value.lower().replace(" ", "")
    if re.fullmatch(r"v?\d+(?:\.\d+){1,3}", low):
        return True
    if re.fullmatch(r"allshare\d*(?:\.\d+)?", low):
        return True
    if low in {"upnp", "dlna", "igd", "device", "huaweidevice"}:
        return True
    return False


def choose_upnp_model(manufacturer, model_name, model_number):
    """Choose a stable user-facing UPnP model without protocol/version noise."""
    manufacturer = clean_observed_text(manufacturer) or ""
    name = clean_observed_text(model_name)
    number = clean_observed_text(model_number)
    maker = manufacturer.lower()

    # Samsung descriptions often expose the actual TV code as modelName and
    # use modelNumber for DLNA/AllShare protocol-version text.
    if "samsung" in maker:
        if name and _looks_specific_model_code(name):
            return name
        if number and _looks_specific_model_code(number) and not _is_protocol_or_version_label(number):
            return number

    # In the ASSAS deployment the TP-Link unit is configured as an AP.
    # Preserve its hardware revision when UPnP supplies one.
    if "tp-link" in maker or "tplink" in maker:
        if name and number and re.fullmatch(r"\d+(?:\.\d+){1,3}", number):
            return f"{name} {number}"

    # Prefer a concrete alphanumeric code over generic family wording.
    if number and _looks_specific_model_code(number) and not _is_protocol_or_version_label(number):
        if not name or not _looks_specific_model_code(name):
            return number
    if name and _looks_specific_model_code(name):
        if number and _looks_specific_model_code(number) and not _is_protocol_or_version_label(number):
            if number.lower() not in name.lower():
                return f"{name} {number}"
        return name

    if name and not _is_protocol_or_version_label(name):
        return name
    if number and not _is_protocol_or_version_label(number):
        return number
    return None


def hostname_quality(value):
    """Rank observed names so generic UPnP labels do not replace better names."""
    value = clean_observed_text(value)
    if not value:
        return 0
    low = value.lower()
    if "assas access point" in low:
        return 200
    score = 60
    if _looks_specific_model_code(value):
        score += 30
    if low.startswith("[tv]") or "samsung" in low or "series" in low:
        score += 15
    generic_tokens = (
        "wps access point", "wireless n router", "internet gateway",
        " igd", "router", "gateway", "upnp device", "media renderer",
    )
    if any(token in low for token in generic_tokens):
        score -= 35
    return score


def is_generic_friendly_name(value):
    value = clean_observed_text(value)
    if not value:
        return True
    low = value.lower()
    generic = (
        "wps access point", "wireless n router", "internet gateway",
        "igd", "upnp device", "media renderer",
    )
    return any(token in low for token in generic)


def deployment_role_override(ip, hostname, model):
    """Return a role override only for formally documented ASSAS infrastructure."""
    text = " ".join(x for x in (hostname, model) if x).lower()
    if "tl-wr802n" in text or "assas access point" in text:
        return ("Access Point", 110, "ASSAS deployment role (AP mode)")
    return None


def deployment_model_override(hostname, model):
    """Use formally documented ASSAS infrastructure model names when exact."""
    text = " ".join(x for x in (hostname, model) if x).lower()
    if "tl-sg105e" in text:
        return ("TL-SG105E", 98, "ASSAS deployment inventory")
    # TL-WR802N is normally learned from UPnP, but this is a safe fallback
    # because the formal proposal documents that exact device in AP mode.
    if "tl-wr802n" in text and not model:
        return ("TL-WR802N", 98, "ASSAS deployment inventory")
    return None


def enrich_upnp_metadata(mac, ip, url, span_confirmed=False):
    """Optional local-only UPnP description lookup for richer model metadata."""
    if not probe_target_current(mac, ip, "ENABLE_UPNP_ENRICHMENT"):
        return
    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "ASSAS/1.0"},
            method="GET",
        )
        with urllib.request.urlopen(request, timeout=UPNP_TIMEOUT_SECONDS) as resp:
            data = resp.read(UPNP_MAX_BYTES + 1)
        if len(data) > UPNP_MAX_BYTES:
            return

        if not probe_target_current(mac, ip, "ENABLE_UPNP_ENRICHMENT"):
            return
        root = ET.fromstring(data)
        friendly = xml_text(root, "friendlyName")
        manufacturer = xml_text(root, "manufacturer")
        model_name = xml_text(root, "modelName")
        model_number = xml_text(root, "modelNumber")
        device_type_text = xml_text(root, "deviceType")

        model = choose_upnp_model(manufacturer, model_name, model_number)

        if model and _looks_specific_model_code(model) and is_generic_friendly_name(friendly):
            maker = clean_observed_text(manufacturer)
            friendly = f"{maker} {model}" if maker else model

        dtype = infer_type_from_text(
            friendly, manufacturer, model_name, model_number, device_type_text
        )
        candidate = None
        if dtype:
            candidate = (dtype, SCORES["model"], "UPnP device description")

        role_override = deployment_role_override(ip, friendly, model)
        if role_override:
            candidate = role_override

        update_device(
            mac,
            ip=ip,
            vendor=manufacturer,
            vendor_source="inferred: UPnP manufacturer" if manufacturer else None,
            hostname=friendly,
            model=model,
            model_score=100 if model else 0,
            model_source="UPnP device description" if model else None,
            candidate=candidate,
            upnp_location=url,
            mark_current=False,
            seen_on_span=span_confirmed,
        )
    except Exception:
        # Metadata enrichment is best-effort and must never break sniffing.
        return


def schedule_upnp_enrichment(mac, ip, url, span_confirmed=False):
    if not url or not is_local_metadata_url(url):
        return
    def upnp_worker(target_mac, target_ip):
        enrich_upnp_metadata(target_mac, target_ip, url, span_confirmed)
    schedule_bounded_probe(mac, ip, "ENABLE_UPNP_ENRICHMENT",
                           metadata_urls_seen, metadata_lock, upnp_worker)



def vendor_evidence_rank(mac, source):
    source = (source or '').lower()
    if not source:
        return 20 if is_locally_administered_mac(mac) else 100
    if 'upnp' in source or 'manufacturer' in source:
        return 90
    if 'model' in source:
        return 80
    if 'dhcp' in source:
        return 65
    if 'hostname' in source:
        return 50
    return 30


def update_device(mac, ip=None, vendor=None, vendor_source=None, hostname=None,
                  model=None, model_score=0, model_source=None, dhcp_sig=None,
                  vendor_class=None, upnp_location=None,
                  candidate=None, seen_on_span=False, seen_in_discovery=False,
                  mark_current=False):
    """Merge device identity while keeping discovery/traffic/AP state separate."""
    mac = mac.lower()
    if not is_valid_host_mac(mac):
        return
    if is_self_device(mac=mac, ip=ip):
        return

    now = datetime.now()
    cached = write_cache.get(mac)
    first_span_confirmation = seen_on_span and not (cached and cached.get("span_seen"))
    has_new_info = bool(
        vendor or hostname or model or dhcp_sig or vendor_class or upnp_location or candidate
        or first_span_confirmation or seen_in_discovery or mark_current
    )

    if (cached and not has_new_info and ip == cached.get("ip") and
            (now - cached["time"]).total_seconds() < CACHE_WRITE_INTERVAL):
        return

    if not vendor:
        vendor = get_vendor(mac)
        # get_vendor() is a real OUI hit (or None) -- never inferred.
        vendor_source = None

    if not model:
        hostname_model = model_db.model_from_hostname(hostname)
        if hostname_model:
            model = hostname_model
            model_score = SCORES["hostname"]
            model_source = SRC_HOSTNAME_MODEL_CODE
            _, model_type = normalize_model(model)
            candidate = merge_candidate(candidate, model_type, model_score, model_source)

    # A randomized/local MAC cannot provide a trustworthy OUI vendor.
    # If passive metadata gives us an unambiguous model or hostname
    # identity, use that stronger evidence instead of leaving the
    # manufacturer unset. vendor_source is only ever assigned in the same
    # branch that assigns vendor, so the two columns can't drift out of
    # sync (a real OUI vendor must never carry an "inferred: ..." tag).
    if not vendor:
        model_vendor = vendor_from_model(model)
        if model_vendor:
            vendor, vendor_source = model_vendor, "inferred: model"
        else:
            hostname_vendor = vendor_from_model_in_hostname(hostname)
            if hostname_vendor:
                vendor, vendor_source = hostname_vendor, "inferred: hostname"

    candidate = merge_candidate(
        candidate, type_from_hostname(hostname), SCORES["hostname"], "hostname"
    )
    candidate = merge_candidate(
        candidate, type_from_os_hint(hostname), SCORES["os_hint"],
        "android OS hostname"
    )
    candidate = merge_candidate(
        candidate, type_from_vendor(vendor), SCORES["vendor"], "MAC vendor"
    )

    role_override = deployment_role_override(ip, hostname, model)
    if role_override:
        candidate = merge_candidate(candidate, *role_override)

    deployment_model = deployment_model_override(hostname, model)
    if deployment_model and not model:
        model, model_score, model_source = deployment_model

    # Model database: store a bare model code as "Marketing Name (CODE)".
    # display_model() returns None for unknown codes and for text that is
    # already a name, so an observed name is never overwritten.
    if model:
        model = model_db.display_model(model) or model

    if ip and ip in infra_hints:
        candidate = merge_candidate(
            candidate, infra_hints[ip], SCORES["gateway"], "default gateway"
        )

    now_str = now.isoformat(timespec="seconds")

    with db_lock:
        conn = connect_db()
        cur = conn.cursor()
        row = cur.execute(
            "SELECT device_type, class_score, hostname, model, vendor, "
            "COALESCE(is_monitored, 0), COALESCE(model_score, 0), "
            "COALESCE(session_seen, 0), vendor_source, class_source "
            "FROM devices WHERE mac=?",
            (mac,),
        ).fetchone()

        if row is None:
            dtype = candidate[0] if candidate else None
            score = candidate[1] if candidate else 0
            source = candidate[2] if candidate else None
            traffic_ever = 1 if seen_on_span else 0
            span_seen = now_str if seen_on_span else None
            session_traffic = 1 if seen_on_span else 0
            discovered = 1 if seen_in_discovery else 0
            discovery_seen = now_str if seen_in_discovery else None
            if discovered:
                status = "online"
            elif seen_on_span:
                status = "observed"
            else:
                status = "candidate"

            cur.execute("""
                INSERT INTO devices (
                    mac, ip, vendor, vendor_source, hostname, device_type, model,
                    model_score, model_source,
                    dhcp_signature, vendor_class, class_score, class_source,
                    is_monitored, last_span_seen, session_seen, upnp_location,
                    first_seen, last_seen, status,
                    discovered_current, last_discovery_seen,
                    traffic_seen, last_traffic_seen
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                mac, ip, vendor, vendor_source, hostname, dtype, model,
                model_score if model else 0,
                model_source if model else None,
                dhcp_sig, vendor_class, score, source,
                traffic_ever, span_seen, session_traffic, upnp_location,
                now_str, now_str, status,
                discovered, discovery_seen,
                traffic_ever, span_seen,
            ))

            if seen_in_discovery:
                label = "DISCOVERED"
            elif seen_on_span:
                label = "SPAN"
            else:
                label = "CANDIDATE"
            print(
                f"[{label}] {mac}  ip={ip or '-'}  "
                f"type={dtype or 'Generic / Unknown'}  "
                f"vendor={display_vendor(mac, vendor, vendor_source)}"
            )
            if ip and needs_service_probe(dtype, score):
                schedule_active_probe(mac, ip)
            if ip and _name_enrichment_eligible(dtype, hostname):
                schedule_mdns_probe(mac, ip)
                schedule_nbns_probe(mac, ip)
        else:
            (
                old_type, old_score, old_hostname, old_model,
                old_vendor, old_monitored, old_model_score, old_session_seen,
                old_vendor_source, old_class_source,
            ) = row
            old_score = old_score or 0
            if old_class_source and 'hostname' in old_class_source.lower():
                old_score = min(old_score, SCORES['hostname'])
            old_model_score = old_model_score or 0

            # Re-evaluate documented infrastructure using both newly observed
            # and already-stored identity. This lets migrations improve old
            # records without requiring the device to re-advertise its name.
            effective_hostname = hostname or old_hostname
            effective_model = model or old_model

            # Existing records may already contain a strong model/hostname
            # identity even when the current ARP/discovery event provides
            # none. Use that stored identity to enrich a missing vendor.
            # vendor_source is only ever assigned alongside vendor itself.
            if not vendor:
                stored_model_vendor = vendor_from_model(effective_model)
                if stored_model_vendor:
                    vendor, vendor_source = stored_model_vendor, "inferred: model"
                else:
                    stored_hostname_vendor = vendor_from_model_in_hostname(effective_hostname)
                    if stored_hostname_vendor:
                        vendor, vendor_source = stored_hostname_vendor, "inferred: hostname"

            stored_role_override = deployment_role_override(
                ip, effective_hostname, effective_model
            )
            if stored_role_override:
                candidate = merge_candidate(candidate, *stored_role_override)

            stored_deployment_model = deployment_model_override(
                effective_hostname, effective_model
            )
            if stored_deployment_model:
                dep_model, dep_score, dep_source = stored_deployment_model
                incoming_score = model_score if model else 0
                if (not old_model or dep_score > old_model_score) and dep_score >= incoming_score:
                    model, model_score, model_source = dep_model, dep_score, dep_source

            if hostname and old_hostname:
                if hostname_quality(hostname) <= hostname_quality(old_hostname):
                    hostname = None

            candidate = merge_candidate(
                candidate,
                type_from_hostname(hostname or old_hostname),
                SCORES["hostname"],
                "stored hostname",
            )
            candidate = merge_candidate(
                candidate,
                type_from_os_hint(hostname or old_hostname),
                SCORES["os_hint"],
                "android OS hostname",
            )

            new_type = None
            new_score = old_score
            new_source = None
            previous = (old_type, old_score, old_class_source) if old_type else None
            resolved = merge_candidate(previous, *candidate) if candidate else previous
            if resolved and resolved != previous:
                new_type, new_score, new_source = resolved

            replace_vendor = bool(vendor) and (not old_vendor or
                vendor_evidence_rank(mac, vendor_source) > vendor_evidence_rank(mac, old_vendor_source))
            cur.execute("""
                UPDATE devices SET
                    ip = COALESCE(?, ip),
                    vendor = CASE
                        WHEN ?
                        THEN ? ELSE vendor
                    END,
                    vendor_source = CASE
                        WHEN ?
                        THEN ? ELSE vendor_source
                    END,
                    hostname = COALESCE(?, hostname),
                    model = CASE
                        WHEN ? IS NOT NULL
                             AND (model IS NULL OR model = ''
                                  OR ? > COALESCE(model_score, 0))
                        THEN ? ELSE model END,
                    model_score = CASE
                        WHEN ? IS NOT NULL
                             AND (model IS NULL OR model = ''
                                  OR ? > COALESCE(model_score, 0))
                        THEN ? ELSE model_score END,
                    model_source = CASE
                        WHEN ? IS NOT NULL
                             AND (model IS NULL OR model = ''
                                  OR ? > COALESCE(model_score, 0))
                        THEN ? ELSE model_source END,
                    dhcp_signature = COALESCE(?, dhcp_signature),
                    vendor_class = COALESCE(?, vendor_class),
                    upnp_location = COALESCE(?, upnp_location),
                    device_type = COALESCE(?, device_type),
                    class_score = CASE WHEN ? IS NOT NULL
                                       THEN ? ELSE class_score END,
                    class_source = CASE WHEN ? IS NOT NULL
                                        THEN ? ELSE class_source END,
                    is_monitored = CASE WHEN ? THEN 1 ELSE is_monitored END,
                    last_span_seen = CASE WHEN ? THEN ? ELSE last_span_seen END,
                    session_seen = CASE WHEN ? THEN 1 ELSE session_seen END,
                    traffic_seen = CASE WHEN ? THEN 1 ELSE traffic_seen END,
                    last_traffic_seen = CASE WHEN ? THEN ? ELSE last_traffic_seen END,
                    discovered_current = CASE WHEN ? THEN 1 ELSE discovered_current END,
                    last_discovery_seen = CASE WHEN ? THEN ? ELSE last_discovery_seen END,
                    last_seen = ?,
                    status = CASE
                        WHEN ? THEN 'online'
                        WHEN ? AND COALESCE(discovered_current,0)=0
                             AND COALESCE(ap_associated,0)=0 THEN 'observed'
                        ELSE status END
                WHERE mac = ?
            """, (
                ip,
                replace_vendor, vendor,
                replace_vendor, vendor_source,
                hostname,
                model, model_score, model,
                model, model_score, model_score,
                model, model_score, model_source,
                dhcp_sig, vendor_class, upnp_location,
                new_type,
                new_type, new_score,
                new_type, new_source,
                1 if seen_on_span else 0,
                1 if seen_on_span else 0, now_str,
                1 if seen_on_span else 0,
                1 if seen_on_span else 0,
                1 if seen_on_span else 0, now_str,
                1 if seen_in_discovery else 0,
                1 if seen_in_discovery else 0, now_str,
                now_str,
                1 if seen_in_discovery else 0,
                1 if seen_on_span else 0,
                mac,
            ))

            # Log only the first SPAN observation in this runtime. Use the
            # serialized DB state rather than the in-memory cache so parallel
            # discovery/enrichment threads cannot emit duplicate TRAFFIC lines.
            if seen_on_span and not old_session_seen:
                print(f"[TRAFFIC] {mac} observed on SPAN {CAPTURE_INTERFACE}")
            if new_type and new_type != old_type:
                print(
                    f"[CLASSIFIED] {mac} -> {new_type} "
                    f"({new_source}, score={new_score})"
                )
            if hostname and hostname != old_hostname:
                print(f"[NAME] {mac} -> {hostname}")
            if model and (not old_model or model_score > old_model_score) and model != old_model:
                print(
                    f"[MODEL] {mac} -> {model} "
                    f"({model_source or 'observed metadata'})"
                )

            # Trigger the fallback probes for a device that is STILL
            # unclassified after this update -- not just brand-new devices.
            # The target randomized-MAC unknowns already exist in the DB, so a
            # new-device-only trigger would never probe them. The probed sets
            # make this once-per-runtime; the workers self-gate on ENABLE_*.
            effective_type = new_type or old_type
            effective_name = hostname or old_hostname
            if ip and needs_service_probe(effective_type, new_score):
                schedule_active_probe(mac, ip)
            if ip and _name_enrichment_eligible(effective_type, effective_name):
                schedule_mdns_probe(mac, ip)
                schedule_nbns_probe(mac, ip)

        # Additive per-family IP tracking (consumed by api._resolve_display_ip):
        # record the last IPv4 / global IPv6 / link-local IPv6 observed for this
        # MAC in its own column, in the same transaction as the identity write
        # above. The legacy `ip` column is left exactly as the queries above set
        # it; this only fills the dedicated column for whichever family `ip`
        # belongs to, so the app can stop flipping between address forms. MAC
        # remains the identity and no classification is affected.
        ip_family_column = _ip_family_column(ip)
        if ip_family_column:
            cur.execute(
                f"UPDATE devices SET {ip_family_column} = ? WHERE mac = ?",
                (ip, mac),
            )

        conn.commit()
        conn.close()

    previous_span = cached.get("span_seen", False) if cached else False
    write_cache[mac] = {
        "time": now,
        "ip": ip,
        "span_seen": previous_span or seen_on_span,
    }


# arp-scan appends a duplicate-response annotation like " (DUP: 2)" to the
# vendor/description column when a host answers more than once. That suffix is
# not part of the vendor name, so strip it before judging the remaining text.
ARP_SCAN_DUP_SUFFIX_RE = re.compile(r"\s*\(DUP:\s*\d+\)\s*$", re.IGNORECASE)


def normalize_arpscan_vendor(vendor):
    """Clean an arp-scan vendor/description field.

    Strips a trailing "(DUP: N)" duplicate-response annotation, then maps the
    known arp-scan unknown placeholders ("(Unknown)", "Unknown",
    empty/whitespace) to None. Legitimate vendor text is preserved, including a
    real vendor that happened to carry a DUP suffix (e.g. "Some Vendor (DUP: 2)"
    -> "Some Vendor"). This does not touch the locally-administered /
    private-MAC handling, which stays authoritative on its own.
    """
    if not vendor:
        return None
    cleaned = ARP_SCAN_DUP_SUFFIX_RE.sub("", vendor).strip()
    if cleaned.lower() in ("(unknown)", "unknown", ""):
        return None
    return cleaned


def arp_scan(verbose=True):
    """Active ARP discovery of devices on the configured local subnet."""
    if not DISCOVERY_INTERFACE:
        if verbose:
            print("[!] No discovery interface is configured or auto-detected")
        return None

    cmd = ["arp-scan", f"--interface={DISCOVERY_INTERFACE}", "--localnet"]
    if os.path.exists(OUI_FILE):
        cmd.append(f"--ouifile={OUI_FILE}")

    if verbose:
        print(f"[*] ARP scan on {DISCOVERY_INTERFACE} ...")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=50,
            check=False,
        )
    except FileNotFoundError:
        if verbose:
            print("[!] arp-scan is not installed")
        return None
    except subprocess.TimeoutExpired:
        if verbose:
            print("[!] arp-scan timed out")
        return None

    if result.returncode != 0:
        if verbose:
            err = result.stderr.strip()
            print(f"[!] arp-scan failed: {err or 'unknown error'}")
        return None

    devices = []
    pattern = re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"
        r"(?:\s+(.*))?$"
    )

    for line in result.stdout.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        ip, mac, vendor = match.groups()
        vendor = normalize_arpscan_vendor(vendor)
        mac = mac.lower()
        if is_locally_administered_mac(mac):
            # Discard whatever text arp-scan printed for a randomized MAC
            # (wording/DUP-suffix varies) -- the bit test is authoritative.
            vendor = None
        if is_self_device(mac=mac, ip=ip):
            continue
        devices.append((ip, mac, vendor))

    return devices


def _current_discovered_macs():
    with db_lock:
        conn = connect_db()
        rows = conn.execute(
            "SELECT mac FROM devices WHERE COALESCE(discovered_current,0)=1"
        ).fetchall()
        conn.close()
    return {row[0].lower() for row in rows}


def _all_known_macs():
    with db_lock:
        conn = connect_db()
        rows = conn.execute("SELECT mac FROM devices").fetchall()
        conn.close()
    return {row[0].lower() for row in rows}


def span_stale_cutoff(now=None):
    """ISO cutoff below which a last_span_seen timestamp is considered stale.

    Reuses DISCOVERY_STALE_SECONDS so passive-SPAN recency and ARP-discovery
    recency share one freshness window (no separate threshold/config).
    """
    now = now or datetime.now()
    return (now - timedelta(seconds=DISCOVERY_STALE_SECONDS)).isoformat(timespec="seconds")


def presence_status(discovered_current, ap_associated, last_span_seen, now=None):
    """Single source of truth for a device's live presence status.

    'observed' means passive SPAN traffic seen *recently* (within
    DISCOVERY_STALE_SECONDS), NOT merely at some point this runtime --
    session_seen is deliberately not consulted here and stays a
    runtime-historical metric. The DB writer (mark_stale_discovery_records),
    the CLI inventory view, and -- via the stored status column -- the API all
    derive status from this same rule so they cannot disagree.
    """
    if discovered_current or ap_associated:
        return "online"
    # last_span_seen is stored as isoformat(timespec="seconds"); string compare
    # matches chronological order and the SQL used in mark_stale below.
    if last_span_seen and last_span_seen >= span_stale_cutoff(now):
        return "observed"
    return "offline"


def mark_stale_discovery_records():
    """Age out subnet presence without erasing traffic/history evidence.

    Two independent decays, both bounded by DISCOVERY_STALE_SECONDS:
      1. A device previously confirmed on the subnet (discovered_current=1)
         that stops replying to ARP loses discovered_current.
      2. Every lifecycle row's status is re-derived from *recent* evidence via
         presence_status(): online if discovered/AP-associated, else 'observed'
         only while last_span_seen is still fresh, else 'offline'. This lets a
         device that left become offline without a service restart, and lets a
         fresh SPAN packet restore 'observed' -- all without touching
         session_seen (kept as the runtime-historical traffic metric).
    """
    now = datetime.now()
    cutoff = span_stale_cutoff(now)
    with db_lock:
        conn = connect_db()
        # (1) Report + clear subnet-discovery presence that has gone stale.
        stale_rows = conn.execute(
            "SELECT mac, ip, COALESCE(ap_associated,0), last_span_seen "
            "FROM devices "
            "WHERE COALESCE(discovered_current,0)=1 "
            "AND last_discovery_seen IS NOT NULL AND last_discovery_seen < ?",
            (cutoff,),
        ).fetchall()
        if stale_rows:
            conn.execute(
                "UPDATE devices SET discovered_current=0 "
                "WHERE COALESCE(discovered_current,0)=1 "
                "AND last_discovery_seen IS NOT NULL AND last_discovery_seen < ?",
                (cutoff,),
            )
        # (2) Re-derive status for every lifecycle row. This SQL mirrors
        # presence_status() exactly; 'candidate' (pre-presence) is left alone.
        conn.execute(
            "UPDATE devices SET status = CASE "
            "WHEN COALESCE(discovered_current,0)=1 OR COALESCE(ap_associated,0)=1 "
            "THEN 'online' "
            "WHEN last_span_seen IS NOT NULL AND last_span_seen >= ? THEN 'observed' "
            "ELSE 'offline' END "
            "WHERE status IN ('online','observed','offline')",
            (cutoff,),
        )
        conn.commit()
        conn.close()

    for mac, ip, ap_associated, last_span_seen in stale_rows:
        # discovered_current is now 0 for these rows; report the resulting state.
        resulting = presence_status(0, ap_associated, last_span_seen, now)
        if resulting == "online":  # still AP-associated
            print(
                f"[ARP-STALE] {mac}  ip={ip or '-'}  "
                "not replying to subnet discovery; still associated to Assas-Test"
            )
        elif resulting == "observed":
            print(
                f"[OBSERVED] {mac}  ip={ip or '-'}  "
                f"not replying to subnet discovery; traffic still visible on SPAN {CAPTURE_INTERFACE}"
            )
        else:
            print(
                f"[OFFLINE] {mac}  ip={ip or '-'}  "
                "no longer confirmed by subnet discovery"
            )
    return len(stale_rows)


def apply_discovery_snapshot(devices, initial=False):
    """Merge one ARP scan into current inventory and preserve history safely."""
    previous = _current_discovered_macs()
    known_before = _all_known_macs()
    found = set()

    for ip, mac, vendor in devices:
        found.add(mac)
        update_device(
            mac,
            ip=ip,
            vendor=vendor,
            seen_on_span=False,
            seen_in_discovery=True,
            mark_current=False,
        )

    if not initial:
        for mac in sorted((found - previous) & known_before):
            print(f"[ONLINE] {mac} returned to subnet inventory")

    mark_stale_discovery_records()
    return found


def initial_discovery():
    devices = arp_scan(verbose=True)
    if devices is None:
        print("[!] Initial subnet discovery did not complete; passive ARP observation remains active")
        devices = []
    else:
        apply_discovery_snapshot(devices, initial=True)
        if not devices:
            print(
                "[!] WARNING: initial ARP scan completed but found 0 devices -- "
                "this is unusual for a live subnet; check discovery interface/privileges"
            )
    print(f"[*] Initial discovery found {len(devices)} device(s) on the subnet")
    print(
        "[*] State model: DISCOVERED=subnet inventory; "
        "TRAFFIC=seen on SPAN; ASSAS-TEST=wireless association (optional)"
    )


def discovery_refresh_loop():
    """Periodic reconciliation so joins/leaves do not require a restart."""
    if DISCOVERY_REFRESH_SECONDS <= 0:
        return
    while True:
        time.sleep(DISCOVERY_REFRESH_SECONDS)
        try:
            devices = arp_scan(verbose=False)
            if devices is not None:
                # A successful empty scan is still a valid reconciliation result.
                apply_discovery_snapshot(devices, initial=False)
            # On scan failure, preserve the last known presence state rather than
            # turning the whole inventory offline because a tool/interface failed.
        except Exception as exc:
            print(f"[!] Discovery refresh error: {exc}")


def handle_discovery_arp(packet):
    """Passively learn ARP joins on the discovery LAN without marking SPAN traffic."""
    if Ether not in packet or ARP not in packet:
        return
    mac = packet[Ether].src.lower()
    if not is_valid_host_mac(mac) or is_self_device(mac=mac):
        return
    ip = local_monitored_ip(packet[ARP].psrc)
    if not ip:
        return
    update_device(
        mac,
        ip=ip,
        seen_on_span=False,
        seen_in_discovery=True,
        mark_current=False,
    )


def discovery_arp_observer_loop():
    """Observe join-related ARP broadcasts/replies on the management LAN."""
    if not DISCOVERY_INTERFACE or DISCOVERY_INTERFACE == CAPTURE_INTERFACE:
        return
    try:
        sniff(
            iface=DISCOVERY_INTERFACE,
            filter="arp",
            prn=handle_discovery_arp,
            store=False,
        )
    except PermissionError:
        print(f"[!] ARP observer on {DISCOVERY_INTERFACE} requires capture privileges")
    except OSError as exc:
        print(f"[!] Could not observe ARP on {DISCOVERY_INTERFACE}: {exc}")


def housekeeping():
    while True:
        time.sleep(5)
        # Pick up an active_probes change saved via the API without a restart.
        # This loop always runs (unlike the optional refresh loop), so it is the
        # reliable place to reconcile runtime gates with the persisted setting.
        reload_runtime_settings()
        if DELETE_AFTER_DAYS <= 0:
            continue
        stale = (datetime.now() - timedelta(days=DELETE_AFTER_DAYS)).isoformat(
            timespec="seconds"
        )
        try:
            with db_lock:
                conn = connect_db()
                conn.execute(
                    "DELETE FROM devices WHERE COALESCE(discovered_current,0)=0 "
                    "AND COALESCE(ap_associated,0)=0 "
                    "AND COALESCE(session_seen,0)=0 AND last_seen < ?",
                    (stale,),
                )
                conn.commit()
                conn.close()
        except sqlite3.Error as exc:
            print(f"[!] Housekeeping DB error: {exc}")

def handle_dhcp(packet):
    hostname = None
    dhcp_sig = None
    vendor_class = None
    candidate = None

    for opt in packet[DHCP].options:
        if not isinstance(opt, tuple):
            continue

        key, value = opt[0], opt[1]

        if key == "hostname":
            hostname = (
                value.decode("utf-8", errors="ignore")
                if isinstance(value, bytes)
                else str(value)
            ).strip()
            dtype = type_from_hostname(hostname)
            candidate = merge_candidate(
                candidate, dtype, SCORES["hostname"], "DHCP hostname"
            )

        elif key in ("vendor_class_id", "vendor_class"):
            vendor_class = (
                value.decode("utf-8", errors="ignore")
                if isinstance(value, bytes)
                else str(value)
            ).strip()
            # Keep the full string as metadata for evidence/debugging, but only
            # classify from provably-unambiguous substrings (VENDOR_CLASS_HINTS);
            # shared strings like bare MSFT/udhcp are deliberately excluded.
            # Weight dhcp_vendor (65) stays below service/model, so a real TV
            # advertisement still overrides android-dhcp (Android TV boxes send
            # it too). Only the matched needle is logged, never the full string.
            vc_dtype, vc_needle = type_from_vendor_class(vendor_class)
            if vc_dtype:
                candidate = merge_candidate(
                    candidate, vc_dtype, SCORES["dhcp_vendor"],
                    f"DHCP vendor class ({vc_needle})"
                )
            # "android-dhcp-..." identifies only the OS (phones, tablets, TVs,
            # boxes all send it), so it is a weak os_hint, never a form factor.
            candidate = merge_candidate(
                candidate, type_from_os_hint(vendor_class), SCORES["os_hint"],
                "android OS (DHCP vendor class)"
            )

        elif key == "param_req_list":
            try:
                sig = tuple(int(x) for x in value)
                dhcp_sig = ",".join(str(x) for x in sig)
                dtype = type_from_dhcp_signature(sig)
                # The Android option-55 list is OS-only (phones/tablets/TVs all
                # send it) -> os_hint; Apple/Windows fingerprints stay at dhcp.
                dhcp_score = (
                    SCORES["os_hint"] if dtype in OS_LEVEL_TYPES
                    else SCORES["dhcp"]
                )
                candidate = merge_candidate(
                    candidate, dtype, dhcp_score, "DHCP fingerprint"
                )
            except (TypeError, ValueError):
                pass

    return hostname, dhcp_sig, vendor_class, candidate


def handle(packet):
    if Ether not in packet:
        return

    mac = packet[Ether].src.lower()
    if not is_valid_host_mac(mac) or is_self_device(mac=mac):
        return

    observed_ip = None
    hostname = None
    model = None
    model_score = 0
    model_source = None
    observed_vendor = None
    observed_vendor_source = None
    dhcp_sig = None
    vendor_class = None
    upnp_location = None
    candidate = None

    if ARP in packet:
        observed_ip = packet[ARP].psrc
    elif IP in packet:
        observed_ip = packet[IP].src
    elif IPv6 in packet:
        observed_ip = packet[IPv6].src

    ip = local_monitored_ip(observed_ip)
    # Routed internet traffic carries a local router MAC, not the sender MAC.
    if observed_ip and observed_ip != '0.0.0.0' and ip is None:
        return

    ether_dst = packet[Ether].dst.lower()
    ether_type = int(packet[Ether].type)

    # STP/PVST is strong switch/bridge evidence.  Do not classify every
    # 01:80:c2 multicast frame as STP because LLDP uses the same OUI range.
    if ether_dst in {"01:80:c2:00:00:00", "01:00:0c:cc:cc:cd"}:
        candidate = merge_candidate(
            candidate, "Managed Switch", SCORES["service"], "STP/BPDU"
        )

    if ether_type == 0x88CC or ether_dst == "01:80:c2:00:00:0e":
        lldp_name, lldp_desc, lldp_type = parse_lldp(bytes(packet[Ether].payload))
        candidate = merge_candidate(
            candidate, lldp_type, SCORES["lldp"], "LLDP system capabilities"
        )
        if lldp_name and not hostname:
            hostname = lldp_name

    if DHCP in packet:
        hostname, dhcp_sig, vendor_class, dhcp_candidate = handle_dhcp(packet)
        if dhcp_candidate:
            candidate = merge_candidate(candidate, *dhcp_candidate)

        # Huawei's "HUAWEI:android:<CODE>" vendor class: a KNOWN model-code
        # prefix is form-factor evidence (above the generic android os_hint),
        # and the "HUAWEI:" prefix infers the manufacturer when the MAC has no
        # real OUI vendor (same gate as the mDNS-query inference below).
        if vendor_class:
            candidate = merge_candidate(
                candidate, type_from_huawei_vendor_class(vendor_class),
                SCORES["dhcp_vendor"], "Huawei DHCP vendor class"
            )
            vc_vendor = vendor_from_vendor_class(vendor_class)
            if vc_vendor and (
                is_locally_administered_mac(mac) or get_vendor(mac) is None
            ):
                observed_vendor = vc_vendor
                observed_vendor_source = "inferred: DHCP vendor class"
            # Model database: name the Huawei model line ("HUAWEI MatePad
            # (DBY)") only when this packet carried no model. The stored model
            # is replaced only when empty or weaker, so a real mDNS/UPnP model
            # (score 90+) is never overwritten by this one.
            vc_model = model_db.model_from_huawei_vendor_class(vendor_class)
            if vc_model and not model:
                model, model_score = vc_model, SCORES["dhcp_vendor"]
                model_source = "Huawei DHCP vendor class"

    if UDP in packet:
        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)

        if sport == 5353 or dport == 5353:
            payload = bytes(packet[UDP].payload)
            is_response = DNS in packet and int(packet[DNS].qr) == 1

            if is_response:
                dtype = type_from_payload(payload)
                candidate = merge_candidate(
                    candidate, dtype, SCORES["service"],
                    "mDNS advertisement"
                )

                weak_dtype = weak_type_from_payload(payload)
                candidate = merge_candidate(
                    candidate, weak_dtype, SCORES["weak_service"],
                    "mDNS AirPlay/RAOP"
                )

                (
                    observed_model, model_type,
                    observed_model_score, observed_model_source,
                    mdns_vendor, friendly_name,
                ) = extract_mdns_metadata(packet)
                observed_vendor = mdns_vendor or observed_vendor

                if observed_model and observed_model_score >= model_score:
                    model = observed_model
                    model_score = observed_model_score
                    model_source = observed_model_source

                candidate = merge_candidate(
                    candidate, model_type, SCORES["model"],
                    "device model identifier"
                )

                mdns_name, mdns_name_src = mdns_name_candidate(packet, friendly_name)
                if mdns_name and not hostname:
                    hostname = mdns_name
                    candidate = merge_candidate(
                        candidate,
                        type_from_hostname(mdns_name),
                        SCORES["hostname"],
                        mdns_name_src,
                    )

            elif DNS in packet and int(packet[DNS].qdcount):
                # mDNS QUERY: the device is asking for a service it wants to
                # use. Weak OS hint, attributed to the querying source MAC.
                qd = packet[DNS].qd
                questions = qd if isinstance(qd, (list, tuple)) else [qd]
                seen_needles = set()
                for q in questions:
                    qn = getattr(q, "qname", None)
                    if not qn:
                        continue
                    if isinstance(qn, bytes):
                        qn = qn.decode("utf-8", errors="ignore")
                    dtype, needle = type_from_mdns_query(qn)
                    if dtype and needle not in seen_needles:
                        seen_needles.add(needle)
                        candidate = merge_candidate(
                            candidate, dtype, SCORES["mdns_query"],
                            f"mDNS query ({needle})",
                        )
                        print(
                            f"[MDNS-QUERY] {mac} needle={needle} tier=mdns_query"
                        )
                        # Vendor inference from an Apple-exclusive Continuity
                        # query. Gate on the MAC, NOT on `not observed_vendor`:
                        # this is per-packet so observed_vendor is always empty
                        # here, and gating on it would let a real-OUI device (the
                        # Dell) be relabelled Apple. Only infer when the MAC has
                        # no trustworthy OUI vendor (randomized, or an OUI miss).
                        mdns_vendor = vendor_from_mdns_query_needle(needle)
                        if mdns_vendor and (
                            is_locally_administered_mac(mac)
                            or get_vendor(mac) is None
                        ):
                            observed_vendor = mdns_vendor
                            observed_vendor_source = (
                                f"inferred: mDNS query ({needle})"
                            )

        if sport == 1900 or dport == 1900:
            payload = bytes(packet[UDP].payload)
            upper = payload.lstrip().upper()
            is_advertisement = (
                upper.startswith(b"NOTIFY ")
                or upper.startswith(b"HTTP/1.1 200")
            )

            if is_advertisement:
                dtype = type_from_payload(payload)
                candidate = merge_candidate(
                    candidate, dtype, SCORES["service"],
                    "SSDP advertisement"
                )

                weak_dtype = weak_type_from_payload(payload)
                candidate = merge_candidate(
                    candidate, weak_dtype, SCORES["weak_service"],
                    "SSDP AirPlay/RAOP"
                )

                observed_vendor = extract_manufacturer(payload) or observed_vendor

                (
                    observed_model, model_type,
                    observed_model_score, observed_model_source,
                ) = extract_model_info(payload)
                if observed_model and observed_model_score >= model_score:
                    model = observed_model
                    model_score = observed_model_score
                    model_source = observed_model_source

                candidate = merge_candidate(
                    candidate, model_type, SCORES["model"],
                    "device model identifier"
                )

                friendly_name = extract_friendly_name(payload)
                if friendly_name and not hostname:
                    hostname = friendly_name
                    dtype = type_from_hostname(friendly_name)
                    candidate = merge_candidate(
                        candidate, dtype, SCORES["hostname"],
                        "SSDP friendly name"
                    )

                location = extract_ssdp_location(payload)
                if location:
                    upnp_location = location
                schedule_upnp_enrichment(mac, ip, location, span_confirmed=True)

        if sport == 3702 or dport == 3702:
            payload = bytes(packet[UDP].payload)

            wsd_model, wsd_vendor, friendly_name, dtype = extract_wsd_metadata(payload)
            candidate = merge_candidate(
                candidate, dtype, SCORES["service"],
                "WS-Discovery / ONVIF advertisement"
            )
            # Generic ONVIF (no explicit NVT/NVS/camera token) is only broad
            # evidence -> Video Surveillance Device via WEAK_SERVICE_HINTS, kept
            # at a lower score so explicit NVT/NVS (above) can refine it later.
            candidate = merge_candidate(
                candidate, weak_type_from_payload(payload), SCORES["weak_service"],
                "WS-Discovery / ONVIF (generic)"
            )

            observed_vendor = wsd_vendor or extract_manufacturer(payload) or observed_vendor

            if wsd_model:
                normalized_model, model_type = normalize_model(wsd_model)
                if normalized_model and 96 >= model_score:
                    model = normalized_model
                    model_score = 96
                    model_source = "WS-Discovery / ONVIF advertised hardware"
                candidate = merge_candidate(
                    candidate, model_type, SCORES["model"],
                    "WS-Discovery model identifier"
                )
            else:
                (
                    observed_model, model_type,
                    observed_model_score, observed_model_source,
                ) = extract_model_info(payload)
                if observed_model and observed_model_score >= model_score:
                    model = observed_model
                    model_score = observed_model_score
                    model_source = observed_model_source
                candidate = merge_candidate(
                    candidate, model_type, SCORES["model"],
                    "device model identifier"
                )

            if friendly_name and not hostname:
                hostname = friendly_name
                candidate = merge_candidate(
                    candidate,
                    type_from_hostname(friendly_name),
                    SCORES["hostname"],
                    "WS-Discovery friendly name",
                )

        if sport == 53 or dport == 53:
            if DNS in packet and int(packet[DNS].qr) == 0 and packet[DNS].qdcount:
                try:
                    qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                except Exception:
                    qname = None
                # Only the matched needle (a short fixed keyword) is ever
                # kept -- the qname itself is discarded once matched, to
                # avoid persisting a device's browsing/service history.
                dtype, needle = type_from_dns_query(qname)
                if dtype:
                    # An OS-only verdict (e.g. an Android connectivity domain,
                    # also hit by Android TVs) enters at the weak os_hint tier;
                    # every other domain stays at weak_service.
                    dns_score = (
                        SCORES["os_hint"] if dtype in OS_LEVEL_TYPES
                        else SCORES["weak_service"]
                    )
                    candidate = merge_candidate(
                        candidate, dtype, dns_score,
                        f"DNS query (matched: {needle})"
                    )
                domain_vendor = vendor_from_domain_needle(needle)
                if domain_vendor and not observed_vendor:
                    observed_vendor = domain_vendor
                    observed_vendor_source = f"inferred: domain ({needle})"

        if sport == 137 or dport == 137:
            nbns_name = extract_nbns_name(packet)
            if nbns_name and not hostname:
                hostname = nbns_name
                candidate = merge_candidate(
                    candidate,
                    type_from_hostname(nbns_name),
                    SCORES["broadcast_name"],
                    "NBNS name",
                )

        if sport == 5355 or dport == 5355:
            llmnr_name = extract_llmnr_name(packet)
            if llmnr_name and not hostname:
                hostname = llmnr_name
                candidate = merge_candidate(
                    candidate,
                    type_from_hostname(llmnr_name),
                    SCORES["broadcast_name"],
                    "LLMNR name",
                )

    if TCP in packet:
        flags = int(packet[TCP].flags)
        is_syn_ack = (flags & 0x12) == 0x12
        is_pure_syn = (flags & 0x12) == 0x02
        if is_syn_ack:
            dtype = PORT_HINTS.get(int(packet[TCP].sport))
            candidate = merge_candidate(
                candidate, dtype, SCORES["port"],
                f"open TCP/{packet[TCP].sport} observed"
            )
        elif is_pure_syn:
            # p0f-style OS fingerprint from a LOCAL device's connection SYN.
            # Local-only: an inbound internet SYN carries the router's MAC and
            # a foreign source IP, so `ip` (local_monitored_ip) is None -> skip.
            if not ip:
                return
            now_mono = time.monotonic()
            do_fp = False
            with syn_fp_lock:
                last = syn_fp_last.get(mac)
                if last is None or (now_mono - last) >= SYN_FP_INTERVAL_SECONDS:
                    syn_fp_last[mac] = now_mono
                    do_fp = True
            # Limit fingerprint work, never the observation of device presence.
            if do_fp:
                os_family, dtype = fingerprint_tcp_syn(packet)
                if dtype:
                    candidate = merge_candidate(
                        candidate, dtype, SCORES["syn_fp"],
                        f"TCP SYN fingerprint ({os_family})",
                    )
                    print(f"[SYN-FP] {mac} os={os_family} tier=syn_fp")

    update_device(
        mac,
        ip=ip,
        vendor=observed_vendor,
        vendor_source=observed_vendor_source,
        hostname=hostname,
        model=model,
        model_score=model_score,
        model_source=model_source,
        dhcp_sig=dhcp_sig,
        vendor_class=vendor_class,
        upnp_location=upnp_location,
        candidate=candidate,
        seen_on_span=True,
        seen_in_discovery=False,
        mark_current=False,
    )
    # Optional enrichment may be triggered by traffic for any local device; this
    # does not change subnet discovery or Assas-Test association state.
    schedule_ssdp_probe(mac, ip)


INFRASTRUCTURE_TYPES = {"Router", "Access Point", "Managed Switch", "Network Device"}


def inventory_role(dtype, hostname=None, model=None):
    """Presentation role only; it never changes classification evidence."""
    if dtype in INFRASTRUCTURE_TYPES:
        return "Infrastructure"
    if dtype and dtype != "Generic / Unknown":
        return "Endpoint"
    text = " ".join(x for x in (hostname, model) if x).lower()
    if any(token in text for token in ("tl-sg105e", "tl-wr802n", "router", "gateway")):
        return "Infrastructure"
    return "Unknown"


def display_vendor(mac, vendor, vendor_source=None):
    """Presentation-only vendor text; never affects stored evidence.

    Order matters:
    1. An explicit "inferred:" source wins first -- it also covers inferred
       vendors on *real*-MAC OUI-misses, and checking the randomized bit
       first would make "(inferred)" unreachable.
    2. Any vendor on a locally-administered MAC is shown "(inferred)" too:
       get_vendor() never returns an OUI vendor for a randomized MAC, so
       such a value can only be inference or a device self-report (incl.
       legacy rows stored before the vendor_source column existed) -- never
       OUI ground-truth, so it must not read as if it were.
    3. No vendor at all on a randomized MAC -> the private-MAC placeholder.
    4. Otherwise a genuine OUI vendor on a real MAC, shown as-is.
    """
    if vendor_source and vendor_source.startswith("inferred"):
        return f"{vendor} (inferred)"
    if vendor and is_locally_administered_mac(mac):
        return f"{vendor} (inferred)"
    if not vendor and is_locally_administered_mac(mac):
        return "Private MAC (randomized)"
    return vendor or "-"


def display_device_type(dtype, mac, hostname, vendor, model):
    """Presentation-only device-type text for --show.

    A device that is unknown *because* it is a randomized MAC with no
    identifying traffic observed yet reads "Unknown (private MAC)" instead
    of a bare "Generic / Unknown", so the table is honest about why it is
    unclassified. Only fires when there is genuinely no evidence at all
    (no type, hostname, vendor, or model) and the MAC is private; a
    private MAC with some evidence, or a real-MAC unknown, reads normally.
    "Unknown (private MAC)" is 21 chars -- fits the existing TYPE column.
    """
    if dtype and dtype != "Generic / Unknown":
        return dtype
    if is_locally_administered_mac(mac) and not hostname and not vendor and not model:
        return "Unknown (private MAC)"
    return "Generic / Unknown"


def _ip_sort_value(value):
    try:
        return (0, int(ipaddress.ip_address(value)))
    except (ValueError, TypeError):
        return (1, str(value or ""))


def show_inventory(show_all=False, show_history=False):
    with db_lock:
        conn = connect_db()

        if show_all:
            where = ""
        elif show_history:
            where = (
                "WHERE COALESCE(discovered_current,0)=0 "
                "AND COALESCE(ap_associated,0)=0"
            )
        else:
            # Formal device inventory: devices currently found on the subnet.
            # An associated AP client is also included if it was idle during ARP.
            where = (
                "WHERE COALESCE(discovered_current,0)=1 "
                "OR COALESCE(ap_associated,0)=1"
            )

        rows = conn.execute(f"""
            SELECT status, ip, mac, hostname, device_type,
                   CASE WHEN COALESCE(model_score,0)>0 THEN model ELSE NULL END,
                   vendor, vendor_source, class_source, COALESCE(class_score,0), model_source,
                   COALESCE(discovered_current,0), last_discovery_seen,
                   COALESCE(traffic_seen,0), COALESCE(session_seen,0), last_traffic_seen,
                   COALESCE(is_ap_client,0), COALESCE(ap_associated,0),
                   last_ap_seen, membership_source, last_span_seen
            FROM devices
            {where}
        """).fetchall()

        current_subnet = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE COALESCE(discovered_current,0)=1"
        ).fetchone()[0]
        traffic_runtime = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE COALESCE(session_seen,0)=1"
        ).fetchone()[0]
        traffic_inventory = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE COALESCE(session_seen,0)=1 "
            "AND (COALESCE(discovered_current,0)=1 OR COALESCE(ap_associated,0)=1)"
        ).fetchone()[0]
        traffic_only_hidden = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE COALESCE(session_seen,0)=1 "
            "AND COALESCE(discovered_current,0)=0 AND COALESCE(ap_associated,0)=0"
        ).fetchone()[0]
        ap_current = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE COALESCE(ap_associated,0)=1"
        ).fetchone()[0]
        historical = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE COALESCE(discovered_current,0)=0 "
            "AND COALESCE(ap_associated,0)=0"
        ).fetchone()[0]
        conn.close()

    rows = sorted(rows, key=lambda row: (_ip_sort_value(row[1]), row[2] or ""))

    print()
    print(
        f"{'STATUS':<10}{'IP':<17}{'MAC':<19}{'NAME':<20}{'ROLE':<16}"
        f"{'TYPE':<24}{'MODEL':<23}{'VENDOR':<22}{'TRAFFIC':<9}{'ASSAS':<8}EVIDENCE"
    )
    print("-" * 188)

    roles = {"Infrastructure": 0, "Endpoint": 0, "Unknown": 0}
    classified = 0
    unknown = 0

    for (
        status, ip, mac, hostname, dtype, model, vendor, vendor_source, source, class_score, model_source,
        discovered_current, last_discovery_seen,
        traffic_seen, session_seen, last_traffic_seen,
        is_ap_client, ap_associated, last_ap_seen, membership_source, last_span_seen,
    ) in rows:
        display_status = presence_status(discovered_current, ap_associated, last_span_seen)

        if session_seen:
            traffic_label = "yes"
        elif traffic_seen:
            traffic_label = "past"
        else:
            traffic_label = "-"

        if ap_associated:
            ap_label = "yes"
        elif is_ap_client:
            ap_label = "past"
        else:
            ap_label = "-"

        role = inventory_role(dtype, hostname, model)
        roles[role] = roles.get(role, 0) + 1
        if dtype and dtype != "Generic / Unknown":
            classified += 1
        else:
            unknown += 1

        print(
            f"{display_status:<10}"
            f"{(ip or '-'):<17}"
            f"{(mac or '-'):<19}"
            f"{(hostname or '-')[:18]:<20}"
            f"{role[:14]:<16}"
            f"{display_device_type(dtype, mac, hostname, vendor, model)[:22]:<24}"
            f"{(model or '-')[:21]:<23}"
            f"{display_vendor(mac, vendor, vendor_source)[:20]:<22}"
            f"{traffic_label:<9}"
            f"{ap_label:<8}"
            f"{source or '-'}"
        )

    print("-" * 188)

    if show_all:
        print(
            f"{len(rows)} total known records; {current_subnet} currently discovered on subnet; "
            f"{traffic_runtime} traffic-seen this runtime; {ap_current} associated to {AP_SSID}; "
            f"{classified} classified; {unknown} unknown"
        )
    elif show_history:
        print(
            f"{len(rows)} historical/offline record(s); "
            f"{current_subnet} current subnet device(s) hidden"
        )
    else:
        print(
            f"{len(rows)} current inventory device(s): {current_subnet} discovered on subnet; "
            f"{traffic_inventory} seen on SPAN this runtime; {ap_current} associated to {AP_SSID}; "
            f"{roles.get('Endpoint',0)} endpoint(s), {roles.get('Infrastructure',0)} infrastructure, "
            f"{roles.get('Unknown',0)} unknown role; {classified} classified "
            f"({traffic_only_hidden} traffic-only record(s); {historical} historical hidden)"
        )
    print()

def parse_args():
    parser = argparse.ArgumentParser(
        description="ASSAS resilient device discovery and passive fingerprinting"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--show",
        action="store_true",
        help="show the current subnet device inventory with traffic/AP state",
    )
    group.add_argument(
        "--show-history",
        action="store_true",
        help="show historical/offline inventory records",
    )
    group.add_argument(
        "--show-all",
        action="store_true",
        help="show all current and historical device records",
    )
    group.add_argument(
        "--ap-test",
        action="store_true",
        help="test the TL-WR802N wireless-station membership provider",
    )
    return parser.parse_args()


# class_source values for mDNS-query hints that were removed from
# MDNS_QUERY_HINTS (they identify the query TARGET, not the querier: iTunes for
# Windows sends _apple-mobdev2; casting apps send _airplay/_raop). Any device
# still classified via one of these is stale evidence to be cleared.
_REMOVED_MDNS_QUERY_SOURCES = (
    "mDNS query (_apple-mobdev2._tcp)",
    "mDNS query (_airplay._tcp)",
    "mDNS query (_raop._tcp)",
)


def cleanup_stale_mdns_query_classifications(verbose=True):
    """Reset device_type/class_score/class_source for rows whose classification
    came from a now-removed mDNS-query hint.

    rescore_stored_evidence() only ever upgrades, so a device classified via a
    hint we have since deleted would otherwise keep that stale type forever.
    This one-shot pass (called before the rescore) clears exactly those rows
    back to unclassified so the rescore can re-derive them from remaining
    evidence. Idempotent: once cleared, no row matches the removed sources.
    Returns the number of rows reset.
    """
    with db_lock:
        conn = connect_db()
        placeholders = ",".join("?" * len(_REMOVED_MDNS_QUERY_SOURCES))
        cur = conn.execute(
            f"UPDATE devices SET device_type=NULL, class_score=0, class_source=NULL "
            f"WHERE class_source IN ({placeholders})",
            _REMOVED_MDNS_QUERY_SOURCES,
        )
        n = cur.rowcount
        conn.commit()
        conn.close()
    if verbose and n:
        print(
            f"[*] Cleared {n} device(s) classified via removed mDNS-query hints "
            "(_apple-mobdev2/_airplay/_raop query -> not querier identity)"
        )
    return n


def migrate_classification_rules():
    """Discard obsolete inferred identity, retaining inventory and raw evidence.

    Only reproducible classifications and retired DNS evidence are reset.
    Live service/port/model-independent evidence and conflict barriers survive.
    Re-running is safe; rescore rebuilds using the current rules.
    """
    with db_lock:
        conn = connect_db()
        try:
            with conn:
                rows = conn.execute("SELECT mac, class_source FROM devices").fetchall()
                for mac, source in rows:
                    if _is_rederivable_source(source) or (source or '').startswith('DNS query'):
                        conn.execute("UPDATE devices SET device_type=NULL, class_score=0, class_source=NULL WHERE mac=?", (mac,))
                conn.execute("UPDATE devices SET vendor=NULL, vendor_source=NULL WHERE vendor_source LIKE 'inferred: domain (%'")
        finally:
            conn.close()
    rescore_stored_evidence(verbose=False)


def rescore_stored_evidence(verbose=True):
    """Re-evaluate every device's type from its STORED evidence against the
    current hint tables, upgrading only when the recomputed score strictly
    beats the stored class_score.

    New hint-table entries (DHCP option-55 signatures, option-60 vendor-class
    hints, hostname/vendor/model needles) otherwise apply only to newly
    observed packets. This one-shot startup pass lets them also improve
    devices whose evidence was captured before the tables were updated.
    Nothing is ever downgraded -- a strictly-greater score is required, so any
    stronger existing classification (gateway, mDNS model, etc.) is preserved.
    Only device_type/class_score/class_source are touched; stored evidence
    columns (hostname/vendor/model/dhcp_signature/vendor_class) are read-only
    here.
    """
    with db_lock:
        conn = connect_db()
        rows = conn.execute(
            "SELECT mac, dhcp_signature, vendor_class, hostname, vendor, model, "
            "device_type, COALESCE(class_score, 0), model_score, model_source FROM devices"
        ).fetchall()

        changed = 0
        for (mac, dhcp_sig, vendor_class, hostname, vendor, model,
             old_type, old_score, stored_model_score, stored_model_source) in rows:
            # Model database: type a stored "Name (CODE)" by its CODE, exactly
            # as when it was observed.
            model = model_db.stored_code(model)
            evidence_score = SCORES["hostname"] if stored_model_source == SRC_HOSTNAME_MODEL_CODE else (stored_model_score or SCORES["model"])
            candidate = merge_candidate(
                None, type_from_hostname(hostname), SCORES["hostname"],
                "stored hostname",
            )
            candidate = merge_candidate(
                candidate, type_from_os_hint(hostname), SCORES["os_hint"],
                "android OS hostname",
            )
            candidate = merge_candidate(
                candidate, type_from_model(model), evidence_score,
                "device model identifier",
            )
            if type_from_model(model) is None:
                candidate = merge_candidate(
                    candidate, model_db.type_for_model(model), evidence_score,
                    SRC_MODEL_DATABASE,
                )
            if dhcp_sig:
                try:
                    sig = tuple(int(x) for x in dhcp_sig.split(","))
                    dtype = type_from_dhcp_signature(sig)
                    dhcp_score = (
                        SCORES["os_hint"] if dtype in OS_LEVEL_TYPES
                        else SCORES["dhcp"]
                    )
                    candidate = merge_candidate(
                        candidate, dtype, dhcp_score, "DHCP fingerprint",
                    )
                except (TypeError, ValueError):
                    pass
            vc_dtype, vc_needle = type_from_vendor_class(vendor_class)
            if vc_dtype:
                candidate = merge_candidate(
                    candidate, vc_dtype, SCORES["dhcp_vendor"],
                    f"DHCP vendor class ({vc_needle})",
                )
            candidate = merge_candidate(
                candidate, type_from_os_hint(vendor_class), SCORES["os_hint"],
                "android OS (DHCP vendor class)",
            )
            candidate = merge_candidate(
                candidate, type_from_huawei_vendor_class(vendor_class),
                SCORES["dhcp_vendor"], "Huawei DHCP vendor class",
            )
            candidate = merge_candidate(
                candidate, type_from_vendor(vendor), SCORES["vendor"], "MAC vendor",
            )

            if candidate and candidate[1] > old_score:
                new_type, new_score, new_source = candidate
                conn.execute(
                    "UPDATE devices SET device_type=?, class_score=?, "
                    "class_source=? WHERE mac=?",
                    (new_type, new_score, new_source, mac),
                )
                changed += 1
                if verbose:
                    print(
                        f"[RESCORE] {mac}  "
                        f"{old_type or 'Generic / Unknown'} (score {old_score}) "
                        f"-> {new_type} ({new_source}, score {new_score})"
                    )
        conn.commit()
        conn.close()

    if verbose:
        print(
            f"[*] Re-scored stored evidence: {changed} device(s) reclassified "
            "against current hint tables"
        )
    return changed


# class_source values that were derived from a PERSISTED evidence column
# (hostname / model / vendor / vendor_class / dhcp_signature), i.e. ones the
# current rules can reproduce from the stored row. Everything else is a
# live-only source (mDNS/SSDP/UPnP/ONVIF advertisements, DNS/mDNS queries, SYN
# fingerprint, LLDP, STP, default gateway, nmap probe, deployment overrides) and
# must never be downgraded by a stored-evidence recompute.
_REDERIVABLE_CLASS_SOURCES = frozenset({
    "hostname", "stored hostname", "DHCP hostname",
    "mDNS A-record hostname", "mDNS service-instance name", "mDNS friendly name",
    "SSDP friendly name", "WS-Discovery friendly name",
    "NBNS name", "LLMNR name",
    "android OS hostname", "android OS (DHCP vendor class)",
    "Huawei DHCP vendor class", "DHCP fingerprint",
    "device model identifier", "WS-Discovery model identifier",
    SRC_MODEL_DATABASE,
    SRC_HOSTNAME_MODEL_CODE,
    "MAC vendor",
})


# Sources whose verdict came from the device model alone.
_MODEL_CLASS_SOURCES = frozenset({
    "device model identifier", SRC_MODEL_DATABASE,
    SRC_HOSTNAME_MODEL_CODE,
})


def _is_rederivable_source(source):
    """True if a stored class_source came from a persisted evidence column, so
    the current rules can reproduce it. The unicast-probe name path appends
    " (probe)" to a name source, and the vendor-class source carries a
    "(needle)" suffix -- both are normalised before the lookup."""
    if not source:
        return False
    normalized = source
    if normalized.endswith(" (probe)"):
        normalized = normalized[:-len(" (probe)")]
    if normalized in _REDERIVABLE_CLASS_SOURCES:
        return True
    if normalized.startswith("DHCP vendor class ("):
        return True
    return False


def reevaluate_stale_classifications(verbose=True):
    """Correct stale verdicts the upgrade-only rescore_stored_evidence() cannot.

    Companion pass run once at startup, right after rescore_stored_evidence()
    (which is left exactly as its author wrote it). rescore only ever RAISES the
    score, so a row whose stored evidence now maps to a DIFFERENT type at an
    equal-or-lower score stays stuck (e.g. a Huawei tablet left "Mobile
    (Android)" by the old "android"-as-phone rule). This pass fixes exactly that
    case, under four independent guards so it can only touch the Android-family
    leftovers of the old rules:

      1. the recompute from stored columns must yield a type (never clears one);
      2. the recomputed type must differ from the stored type;
      3. the recomputed score must be <= the stored score (a strictly-higher
         score is an upgrade, already applied by rescore which runs first);
      4. BOTH the stored and recomputed types must be in ANDROID_FAMILY_TYPES
         (no cross-family change -- a TV/Router/Apple/camera is never touched);
      5. the stored class_source must be re-derivable from a persisted column
         (so a live-only Android verdict -- e.g. from a DNS query -- is never
         downgraded on the strength of a generic stored hostname).

    update_device() is intentionally NOT changed: new devices are already
    classified by the current rules, so only the pre-existing stored rows need
    this one-time correction.
    """
    with db_lock:
        conn = connect_db()
        rows = conn.execute(
            "SELECT mac, dhcp_signature, vendor_class, hostname, vendor, model, "
            "device_type, COALESCE(class_score, 0), class_source, model_score, model_source FROM devices"
        ).fetchall()

        changed = 0
        for (mac, dhcp_sig, vendor_class, hostname, vendor, model,
             old_type, old_score, old_source, stored_model_score, stored_model_source) in rows:
            # Recompute from stored evidence with the current rules. This mirrors
            # rescore_stored_evidence()'s recompute on purpose -- duplicated so
            # that function stays untouched (the accepted second-pass cost).
            # Model database: type a stored "Name (CODE)" by its CODE, exactly
            # as when it was observed.
            model = model_db.stored_code(model)
            evidence_score = SCORES["hostname"] if stored_model_source == SRC_HOSTNAME_MODEL_CODE else (stored_model_score or SCORES["model"])
            candidate = merge_candidate(
                None, type_from_hostname(hostname), SCORES["hostname"],
                "stored hostname",
            )
            candidate = merge_candidate(
                candidate, type_from_os_hint(hostname), SCORES["os_hint"],
                "android OS hostname",
            )
            candidate = merge_candidate(
                candidate, type_from_model(model), evidence_score,
                "device model identifier",
            )
            if type_from_model(model) is None:
                candidate = merge_candidate(
                    candidate, model_db.type_for_model(model), evidence_score,
                    SRC_MODEL_DATABASE,
                )
            if dhcp_sig:
                try:
                    sig = tuple(int(x) for x in dhcp_sig.split(","))
                    dtype = type_from_dhcp_signature(sig)
                    dhcp_score = (
                        SCORES["os_hint"] if dtype in OS_LEVEL_TYPES
                        else SCORES["dhcp"]
                    )
                    candidate = merge_candidate(
                        candidate, dtype, dhcp_score, "DHCP fingerprint",
                    )
                except (TypeError, ValueError):
                    pass
            vc_dtype, vc_needle = type_from_vendor_class(vendor_class)
            if vc_dtype:
                candidate = merge_candidate(
                    candidate, vc_dtype, SCORES["dhcp_vendor"],
                    f"DHCP vendor class ({vc_needle})",
                )
            candidate = merge_candidate(
                candidate, type_from_os_hint(vendor_class), SCORES["os_hint"],
                "android OS (DHCP vendor class)",
            )
            candidate = merge_candidate(
                candidate, type_from_huawei_vendor_class(vendor_class),
                SCORES["dhcp_vendor"], "Huawei DHCP vendor class",
            )
            candidate = merge_candidate(
                candidate, type_from_vendor(vendor), SCORES["vendor"], "MAC vendor",
            )

            if (candidate is None and model and old_type in ANDROID_FAMILY_TYPES
                    and old_source in _MODEL_CLASS_SOURCES
                    and type_from_model(model) is None
                    and model_db.type_for_model(model) is None):
                # The form factor rested on the model alone, and the current
                # rules no longer type it (e.g. a Galaxy Camera): keep only the
                # OS-level verdict instead of a phone/tablet it cannot support.
                candidate = ("Android Device", SCORES["os_hint"],
                             SRC_MODEL_DATABASE)
            if candidate is None:
                continue                                    # guard 1
            new_type, new_score, new_source = candidate
            if new_type == old_type:
                continue                                    # guard 2
            if new_score > old_score:
                continue                                    # guard 3 (rescore's job)
            if (old_type not in ANDROID_FAMILY_TYPES
                    or new_type not in ANDROID_FAMILY_TYPES):
                continue                                    # guard 4
            if not _is_rederivable_source(old_source):
                continue                                    # guard 5

            conn.execute(
                "UPDATE devices SET device_type=?, class_score=?, "
                "class_source=? WHERE mac=?",
                (new_type, new_score, new_source, mac),
            )
            changed += 1
            if verbose:
                print(
                    f"[RECLASSIFY] {mac}  "
                    f"{old_type} (score {old_score}) "
                    f"-> {new_type} ({new_source}, score {new_score})  "
                    "[stale Android-family evidence]"
                )
        conn.commit()
        conn.close()

    if verbose:
        print(
            f"[*] Re-evaluated stale classifications: {changed} device(s) "
            "corrected against current Android-family rules"
        )
    return changed


def main():
    args = parse_args()
    init_db()

    if args.show:
        show_inventory(show_all=False, show_history=False)
        return
    if args.show_history:
        show_inventory(show_all=False, show_history=True)
        return
    if args.show_all:
        show_inventory(show_all=True, show_history=False)
        return
    if args.ap_test:
        raise SystemExit(test_ap_membership())

    load_oui()
    load_gateway()
    load_network_context()
    load_ipv6_context()
    purge_self_records()
    cleanup_stale_mdns_query_classifications()
    migrate_classification_rules()
    rescore_stored_evidence()
    reevaluate_stale_classifications()

    # DB is authoritative from here on: apply the persisted active_probes value
    # over the env-seeded defaults before the banners/gates below read them.
    reload_runtime_settings()

    if ENABLE_UPNP_ENRICHMENT:
        print(
            "[*] Optional local UPnP metadata enrichment: ENABLED "
            "(local model/manufacturer lookup)"
        )
    else:
        print(
            "[*] Optional local UPnP metadata enrichment: disabled "
            "(set ASSAS_UPNP_ENRICH=1 to enable)"
        )

    if ENABLE_ACTIVE_PROBE:
        print(
            f"[*] Optional active nmap port probe: ENABLED "
            f"(fires once per unclassified device, {ACTIVE_PROBE_DELAY_SECONDS}s after first seen)"
        )
    else:
        print(
            "[*] Optional active nmap port probe: disabled "
            "(set ASSAS_ACTIVE_PROBE=1 to enable)"
        )

    if AP_PASSWORD:
        print(f"[*] Optional AP association polling: {AP_URL} / SSID {AP_SSID}")
    elif MANUAL_AP_CLIENTS:
        print(
            f"[*] Optional AP association: manual ASSAS_AP_CLIENTS fallback "
            f"({len(MANUAL_AP_CLIENTS)} MAC(s))"
        )
    else:
        print(
            "[*] AP association provider not configured; inventory still works from subnet discovery"
        )

    reset_session_state()

    if DISCOVERY_INTERFACE == CAPTURE_INTERFACE:
        print(
            f"[!] WARNING: discovery and SPAN capture both resolve to "
            f"{CAPTURE_INTERFACE}. Verify the physical interface mapping."
        )

    if SKIP_INITIAL_DISCOVERY:
        print("[*] Initial subnet ARP scan skipped (ASSAS_SKIP_INITIAL_DISCOVERY=1)")
    else:
        initial_discovery()
    ap_provider_configured = bool(AP_PASSWORD or MANUAL_AP_CLIENTS)
    if ap_provider_configured:
        refresh_ap_membership(verbose=True)
    warm_start_upnp_enrichment()
    fast_start_upnp_enrichment()
    show_inventory(show_all=False, show_history=False)

    threading.Thread(target=housekeeping, daemon=True).start()
    if DISCOVERY_REFRESH_SECONDS > 0:
        threading.Thread(target=discovery_refresh_loop, daemon=True).start()
        print(
            f"[*] Subnet reconciliation every {DISCOVERY_REFRESH_SECONDS}s; "
            f"presence ages out after {DISCOVERY_STALE_SECONDS}s without confirmation"
        )
    if DISCOVERY_INTERFACE and DISCOVERY_INTERFACE != CAPTURE_INTERFACE:
        threading.Thread(target=discovery_arp_observer_loop, daemon=True).start()
        print(f"[*] Passive ARP join observer on {DISCOVERY_INTERFACE}")
    if ap_provider_configured:
        threading.Thread(target=ap_membership_loop, daemon=True).start()

    udp_clause = (
        "(udp and (port 53 or port 67 or port 68 or port 5353 or port 1900 "
        "or port 3702 or port 137 or port 5355))"
    )
    # SYN+ACK from anyone -> open-port hints (unchanged). Pure SYN only from a
    # source IN the local discovery subnet -> OS fingerprint of local devices.
    # Restricting pure SYN to the local subnet bounds CPU: the daemon never
    # dissects the flood of inbound/outbound internet SYNs on the mirror, only
    # the comparatively few SYNs originated by local hosts. If the subnet is
    # unknown, the pure-SYN clause is omitted (SYN+ACK only), since without it
    # the local-only guarantee cannot be enforced.
    tcp_clauses = ["(tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack))"]
    if monitored_networks:
        src_nets = " or ".join(f"src net {n}" for n in monitored_networks)
        tcp_clauses.append(
            f"(tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and ({src_nets}))"
        )
    bpf = (
        "arp or stp or ether proto 0x88cc or "
        + udp_clause + " or "
        + " or ".join(tcp_clauses)
    )

    # Full IP capture is required for flow counters, not just fingerprint ports.
    bpf = "arp or ip or ip6 or stp or ether proto 0x88cc"
    from flows import FlowStore
    flow_store = FlowStore(DB_PATH)
    flow_stop = threading.Event()

    def flush_flows():
        while not flow_stop.wait(5):
            try:
                flow_store.flush()
            except sqlite3.Error as exc:
                print(f"[!] Flow persistence failed: {exc}")

    def process_capture(packet):
        flow_store.add(packet)
        handle(packet)  # New source devices still enter the existing inventory.

    flow_thread = threading.Thread(target=flush_flows, daemon=True)
    flow_thread.start()

    print(f"[*] Passive fingerprinting on {CAPTURE_INTERFACE}")
    print(f"[*] BPF: {bpf}")
    print(
        "[*] State separation: ARP/subnet discovery builds and refreshes inventory; "
        "SPAN marks traffic visibility; AP statistics optionally marks Assas-Test association."
    )

    try:
        sniff(
            iface=CAPTURE_INTERFACE,
            filter=bpf,
            prn=process_capture,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user")
        show_inventory(show_all=False, show_history=False)
    except PermissionError:
        print("[!] Packet capture requires root/capture privileges")
    except OSError as exc:
        print(f"[!] Could not capture on {CAPTURE_INTERFACE}: {exc}")
    finally:
        flow_stop.set()
        flow_thread.join()
        flow_store.flush()


if __name__ == "__main__":
    main()
