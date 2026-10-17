"""Read the outer network flow without treating quoted packets as new traffic."""
from scapy.all import IP, IPv6, TCP, UDP
from scapy.layers.inet6 import (
    IPv6ExtHdrDestOpt, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop, IPv6ExtHdrRouting,
)


def network_transport(packet):
    """Return outer IP layer, direct TCP/UDP layer (or None), and IP protocol."""
    layer = packet
    while layer and not isinstance(layer, (IP, IPv6)):
        layer = layer.payload
    if not layer:
        return None, None, None
    protocol = int(layer.proto if isinstance(layer, IP) else layer.nh)
    payload = layer.payload
    if isinstance(layer, IP) and layer.frag:
        return layer, None, protocol
    if isinstance(layer, IPv6):
        while isinstance(payload, (IPv6ExtHdrDestOpt, IPv6ExtHdrFragment,
                                   IPv6ExtHdrHopByHop, IPv6ExtHdrRouting)):
            protocol = int(payload.nh)
            if isinstance(payload, IPv6ExtHdrFragment) and payload.offset:
                return layer, None, protocol
            payload = payload.payload
    transport = payload if (
        (protocol == 6 and isinstance(payload, TCP)) or
        (protocol == 17 and isinstance(payload, UDP))
    ) else None
    return layer, transport, protocol
