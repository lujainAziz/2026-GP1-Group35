"""Interpret the installed Nmap service database through its XML interface.

No third-party fingerprint database is copied into ASSAS. Nmap's package owns
its data and updates. Service/OS names alone never establish hardware type.
"""
import ipaddress
import re
import xml.etree.ElementTree as ET

from classification import SCORES, PORT_HINTS, merge_candidate


# Map only explicit, recognized device classes into the existing UI taxonomy.
# A webcam is not necessarily a security camera; general-purpose Linux and
# Windows services do not establish a computer, phone or tablet form factor.
DEVICE_TYPES = {
    "printer": "Printer",
    "router": "Router",
    "broadband router": "Router",
    "wap": "Access Point",
    "switch": "Managed Switch",
    "storage-misc": "NAS / Server",
    "media device": "Smart TV / Media Device",
    "game console": "Game Console",
    "webcam": "Video Surveillance Device",
    "bridge": "Network Device",
    "firewall": "Network Device",
    "hub": "Network Device",
    "load balancer": "Network Device",
    "print server": "Network Device",
    "power-device": "IoT Device",
}


def parse_nmap_identity(xml, target_ip):
    """Return (candidate, open TCP ports) for exactly the requested address.

    Confidence applies to Nmap's service identification, not a probability of
    device identity. Require a probed match (not its port-name lookup table).
    Keep only the normalized type and port numbers, never arbitrary banners.
    """
    if not isinstance(xml, str) or len(xml) > 2_000_000:
        raise ValueError("invalid or oversized Nmap output")
    # Nmap emits a harmless bare DOCTYPE. Reject external/internal DTDs.
    xml = re.sub(r"<!DOCTYPE\s+nmaprun\s*>", "", xml)
    if "<!ENTITY" in xml.upper() or "<!DOCTYPE" in xml.upper():
        raise ValueError("XML declarations are not supported")
    try:
        target = ipaddress.ip_address(target_ip)
        root = ET.fromstring(xml)
    except (ValueError, ET.ParseError) as exc:
        raise ValueError("invalid Nmap XML or target") from exc
    if root.tag != "nmaprun":
        raise ValueError("unexpected Nmap root")
    candidate = None
    ports = set()
    for host in root.findall("host"):
        addresses = set()
        for address in host.findall("address"):
            if address.get("addrtype") not in {"ipv4", "ipv6"}:
                continue
            try:
                addresses.add(ipaddress.ip_address(address.get("addr", "")))
            except ValueError:
                continue
        if target not in addresses:
            continue
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if port.get("protocol") != "tcp" or state is None or state.get("state") != "open":
                continue
            try:
                number = int(port.get("portid", ""))
            except ValueError:
                continue
            if not 1 <= number <= 65535:
                continue
            ports.add(number)
            service = port.find("service")
            if service is None or service.get("method") != "probed":
                continue
            try:
                confidence = int(service.get("conf", "0"))
            except ValueError:
                continue
            if not 8 <= confidence <= 10:
                continue
            dtype = DEVICE_TYPES.get(service.get("devicetype", "").lower())
            candidate = merge_candidate(candidate, dtype, SCORES["service"],
                                        "nmap service fingerprint")
    # Resolve all port hints together: ordering must not select a winner.
    port_label = "+".join(str(p) for p in sorted(ports) if p in PORT_HINTS or p == 8000)
    for port in sorted(ports):
        candidate = merge_candidate(candidate, PORT_HINTS.get(port), SCORES["port"],
                                    f"nmap active probe ports {port_label}")
    return candidate, sorted(ports)
