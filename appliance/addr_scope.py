"""LAN-scoped address ranges, shared by discovery and the alert linker.

An address is LAN-scoped when, by its range alone, it can only belong to a
device on a local network: private IPv4 (RFC 1918), shared/CGNAT space
(100.64.0.0/10), IPv4 and IPv6 link-local, and IPv6 unique-local (ULA).

The ranges are listed explicitly on purpose. Python's ipaddress `is_private` /
`is_global` also treat the documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) as non-global; those stand in
for internet addresses in tests and docs, so they must NOT count as LAN here.

Anything else (public IPv4, global IPv6) can be an internet server's address
seen behind the router's MAC, so it is trusted only with ownership evidence.
"""
import ipaddress

_LAN_V4 = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",   # link-local
    "100.64.0.0/10",    # shared address space (CGNAT)
))
_LAN_V6 = tuple(ipaddress.ip_network(n) for n in (
    "fe80::/10",        # link-local
    "fc00::/7",         # unique local (ULA)
))


def is_lan_scoped(ip) -> bool:
    """True only for an address whose range is local by definition."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return False
    nets = _LAN_V4 if addr.version == 4 else _LAN_V6
    return any(addr in n for n in nets)
