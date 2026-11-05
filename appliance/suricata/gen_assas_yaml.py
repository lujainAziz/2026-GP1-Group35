#!/usr/bin/env python3
"""Generate appliance/suricata/assas.yaml from the stock Debian suricata.yaml.

Surgical, assertion-guarded edits only (fails fast if the stock layout shifts):
  1. af-packet first interface eth0 -> eth1
  2. eve-log types reduced to alert (no payload/packet/tagged) + stats
  3. outputs.fast enabled yes -> no
  4. global stats interval 8 -> 30
  5. HOME_NET: add local IPv6 ranges (fc00::/7 ULA, fe80::/10 link-local)
  6. eve-log ethernet: yes — log the Ethernet header (src/dest MAC) in events,
     so address-less decoder events (e.g. IPv6 truncated packet) can be
     attributed to a known device by MAC.
Everything else is left exactly as Debian ships it.
"""
import sys

STOCK = "/etc/suricata/suricata.yaml"
import os
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assas.yaml")

with open(STOCK) as f:
    lines = f.read().split("\n")  # 0-indexed; file line N == lines[N-1]


def expect(n, text):
    got = lines[n - 1]
    if got != text:
        sys.exit(f"ASSERT FAIL at line {n}: expected {text!r} got {got!r}")


# --- anchor checks ---------------------------------------------------------
expect(18, '    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"')
expect(104, "      #ethernet: no  # log ethernet header in events when available")
expect(64, "stats:")
expect(68, "  interval: 8")
expect(84, "  - fast:")
expect(85, "      enabled: yes")
expect(91, "  - eve-log:")
expect(158, "      types:")
expect(159, "        - alert:")
expect(321, "        - flow")
expect(340, "  # a line based log of HTTP requests (no alerts)")
expect(621, "af-packet:")
expect(622, "  - interface: eth0")

# --- edits (apply high line numbers first so earlier indices stay valid) ---
# 4. global stats interval 8 -> 30
lines[68 - 1] = "  interval: 30"
# 6. eve-log ethernet header logging on (MAC attribution for address-less events)
lines[104 - 1] = "      ethernet: yes  # ASSAS: log src/dest MAC in events (device attribution)"
# 3. fast enabled yes -> no
lines[85 - 1] = "      enabled: no"

# 2. replace eve-log types block (lines 158..339 inclusive -> minimal block).
#    Line 339 is blank, line 340 begins the http-log comment (kept).
minimal_types = [
    "      types:",
    "        # ASSAS Sprint 2: signature alerts only, no payload/packet capture.",
    "        - alert:",
    "            tagged-packets: no",
    "            payload: no",
    "            payload-printable: no",
    "            packet: no",
    "            http-body: no",
    "            metadata: no",
    "        # Engine stats for packet-drop monitoring (not ingested as alerts).",
    "        - stats:",
    "            totals: yes",
    "            threads: no",
    "            deltas: no",
    "",
]
lines[158 - 1:339] = minimal_types  # replace 158..339 (slice end exclusive = 339 -> idx 339)

# 1. af-packet first interface eth0 -> eth1 (line number unchanged by the
#    replacement above because 622 > 339; recompute by re-finding to be safe).
# After the slice edit the af-packet line moved; find it fresh.
in_afpacket = False
done = False
for i, ln in enumerate(lines):
    if ln == "af-packet:":
        in_afpacket = True
        continue
    if in_afpacket and ln == "  - interface: eth0":
        lines[i] = "  - interface: eth1"
        done = True
        break
    if in_afpacket and ln.startswith("pcap:"):
        break
if not done:
    sys.exit("ASSERT FAIL: af-packet eth0 interface not found")

# 5. HOME_NET: add the standard local IPv6 ranges. The ISP-delegated global
#    IPv6 prefix is dynamic, so it is deferred (documented, not hardcoded).
#    Applied after the slice/af-packet edits (both at lines > 18), so line 18 is
#    still the stock HOME_NET line; done before the header insert at line 2.
assert lines[18 - 1] == '    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"', \
    "HOME_NET line moved before the edit"
lines[18 - 1:18] = [
    "    # ASSAS: IPv4 RFC1918 + local IPv6 (fc00::/7 ULA, fe80::/10 link-local).",
    "    # The global IPv6 prefix is ISP-delegated/dynamic -> add it here only",
    "    # after the operator confirms a stable monitored-LAN prefix.",
    '    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,fc00::/7,fe80::/10]"',
]

# Header comments must follow the "%YAML 1.1 / ---" directive (which must be
# line 1), so inject them right after the "---" document-start marker.
expect(1, "%YAML 1.1")
expect(2, "---")
header = [
    "",
    "# ASSAS Suricata IDS config (Sprint 2, PBI-13).",
    "# Generated from Debian suricata 7.0.10 stock /etc/suricata/suricata.yaml by",
    "# appliance/suricata/gen_assas_yaml.py. IDS/af-packet only on eth1 (never inline/IPS).",
    "# eve.json carries alert + stats events only; no payload/packet capture.",
]
lines[2:2] = header  # insert after line 2 ("---")

with open(OUT, "w") as f:
    f.write("\n".join(lines))

print(f"wrote {OUT}: {len(lines)} lines")
