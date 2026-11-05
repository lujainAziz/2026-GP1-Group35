# Capture-Path Check & MAC-Attribution Feasibility (read-only, 2026-11-05)

Scope: the recurring `SURICATA IPv6 truncated packet` alerts (sid 2200013, no IP
fields in the events). No rules were disabled or rate-limited; no configuration
was changed. All checks are read-only; the Suricata test ran offline
(`suricata -r` on a crafted pcap in a scratch directory) and never touched the
running service or its logs.

## 1. MAC extraction — FEASIBLE on the installed version (proven offline)

Suricata 7.0.10's eve-log supports `ethernet: yes` ("log ethernet header in
events when available"; present but disabled in the deployed config). An
offline run on crafted truncated-IPv6 frames reproduced the exact production
event and carried the MACs:

```
sid=2200013 SURICATA IPv6 truncated packet
   ether = {"src_mac": "e6:42:65:03:0d:8f", "dest_mac": "fc:1b:d1:30:cb:6c"}
   src_ip present: False
sid=2200013 SURICATA IPv6 truncated packet
   ether = {"src_mac": "fc:1b:d1:30:cb:6c", "dest_mac": "e6:42:65:03:0d:8f"}
   src_ip present: False
```

Device-vs-router distinction is handled by direction: the Ethernet header of a
frame truncated at the IPv6 layer is intact, and the proposed linking policy
mirrors the IP rule — exclude the gateway MAC(s), multicast/broadcast and the
appliance itself as candidates; exactly one remaining inventory device links
the alert (source side preferred when both sides are devices); otherwise NULL.

## 2. Truncation cause — mirror/offload findings (GSO hypothesis now DISFAVORED)

Read-only facts from the capture path:
- `eth1` MTU 1500; capture-side coalescing is OFF (`generic-receive-offload:
  off`, `large-receive-offload: off [fixed]`, `rx-gro-hw: off [fixed]`).
- NIC statistics: RX errors 0; dropped 38 of 95.3 M (negligible).
- Suricata capture: `kernel_drops = 0`, `errors = 0`.
- Decoder: **`max_pkt_size = 1514`** — no frame larger than standard Ethernet
  has ever reached the engine; `decoder.event.ipv6.trunc_pkt = 78` in the
  current stats window (matching the alert volume), plus `zero_len_padn = 83`
  (anomalous IPv6 padding) and `invalid = 78`.

Interpretation (calibrated): the oversized-GSO-frame hypothesis is **not
supported** — nothing coalesces on the capture side and no over-sized frame was
ever observed. The truncated events are ≤ 1514-byte frames whose IPv6
payload-length field claims more data than the frame carries. Two candidate
causes remain, indistinguishable without the sender's identity:
(a) one host periodically emits malformed/padded IPv6 frames (the steady
~1–2/min rate and the `zero_len_padn` counter are consistent with this);
(b) the switch truncates occasional larger frames at the mirror egress.
**The decisive next step is the MAC logging above** — the first logged
`ether.src_mac` names the sender and settles the cause.

## 3. Proposed next step (awaiting approval; nothing applied)
1. Enable `ethernet: yes` in the eve-log section via the config generator;
   validate with `suricata -T`; restart `assas-suricata`.
2. Extend the ingester to read `ether` for events without IP addresses and link
   by the policy above (gateway/multicast/self excluded; single device match
   only), with tests mirroring the offline pcap cases.
3. Re-examine: the sender MAC of the truncated frames determines the cause and
   whether a rule decision (threshold/disable) is justified — not before.

## 4. Live result after deployment (2026-11-05 00:40:14Z, read-only checks)

First production sid-2200013 event after the restart (03:41:38 +03):
```
ether = {"src_mac": "b8:fb:b3:cb:b3:56", "dest_mac": "33:33:00:00:00:00"}   (no IP fields)
```
- **Exclusions applied:** the destination (IPv6 multicast `33:33:…`) was not a
  candidate; the live resolver excludes the gateway MACs
  `fc:1b:d1:30:cb:6c` (IPv4 default route) **and `c0:e0:18:ec:5d:69` — the
  IPv6 default route's next-hop (`fe80::1`), a different MAC that the previous
  inventory-IPv4-only logic would have missed** — plus the appliance's three
  interface MACs.
- **Selection:** the source MAC is a known inventory device →
  `b8:fb:b3:cb:b3:56` (TP-Link TL-WR802N 4.0).
- **SQLite / counters:** new device-keyed row `id=1322, occurrence_count=1`
  (exactly one event since the restart — no inflation); the historical
  NULL-keyed row `id=1297` is untouched (`occ=79`, last event 03:39:32, before
  the deployment).
- **API:** `device_mac=b8:fb:b3:cb:b3:56`,
  `device_name="TP-Link TL-WR802N 4.0"`, `state=new`.
- **Pending:** the owner's in-app navigation test from this alert to the
  device's details.

**Calibrated interpretation:** the frames' sender is the TP-Link access point —
a concrete lead for the truncation cause (periodic IPv6 multicast emissions
from the AP), **not** proof that the AP crafts malformed packets: the frame
could be truncated anywhere on the mirror path. Determining the actual cause
still requires examining a captured sample and the mirror configuration. The
rule and its rate remain unchanged.


## 5. Sample-capture plan for the truncation cause (approved tooling: tcpdump; HELD until run)

Limited, bounded capture of the suspect frames on the mirror interface — at most
20 frames or 5 minutes, full snaplen, filtered to IPv6 frames from the AP's MAC.
The pcap is stored OUTSIDE the repository (`/home/assas/sprint2-backups/`,
consistent with the no-network-data-in-git policy); only derived facts are
documented. The rule and its rate stay unchanged until the cause is known.

```bash
set -euo pipefail
OUT="/home/assas/sprint2-backups/trunc-sample-$(date -u +%Y%m%dT%H%M%SZ).pcap"
sudo timeout 300 tcpdump -i eth1 -s 0 -c 20 -w "$OUT" \
  'ether proto 0x86dd and ether src b8:fb:b3:cb:b3:56'
sudo chmod 644 "$OUT"
echo "SAMPLE_CAPTURED $OUT"
```

Analysis (read-only, after capture): for each frame — captured length vs the
IPv6 header's payload-length field, destination, ethertype and a safe header
hexdump. If payload-length consistently exceeds the on-wire frame length, the
frames arrive malformed/truncated before the mirror egress limit is reached;
matching lengths with intact payloads would instead point at the capture path.
Only after that evidence: the STREAM/decoder rule-group proposal
(threshold/disable with stated detection impact) is re-presented for decision.
