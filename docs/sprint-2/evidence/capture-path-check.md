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
   ether = {"src_mac": "02:00:00:00:00:02", "dest_mac": "02:00:00:00:00:03"}
   src_ip present: False
sid=2200013 SURICATA IPv6 truncated packet
   ether = {"src_mac": "02:00:00:00:00:03", "dest_mac": "02:00:00:00:00:02"}
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
ether = {"src_mac": "02:00:00:00:00:01", "dest_mac": "33:33:00:00:00:00"}   (no IP fields)
```
- **Exclusions applied:** the destination (IPv6 multicast `33:33:…`) was not a
  candidate; the live resolver excludes the gateway MACs
  `02:00:00:00:00:03` (IPv4 default route) **and `02:00:00:00:00:04` — the
  IPv6 default route's next-hop (`fe80::1`), a different MAC that the previous
  inventory-IPv4-only logic would have missed** — plus the appliance's three
  interface MACs.
- **Selection:** the source MAC is a known inventory device →
  `02:00:00:00:00:01` (TP-Link TL-WR802N 4.0).
- **SQLite / counters:** new device-keyed row `id=1322, occurrence_count=1`
  (exactly one event since the restart — no inflation); the historical
  NULL-keyed row `id=1297` is untouched (`occ=79`, last event 03:39:32, before
  the deployment).
- **API:** `device_mac=02:00:00:00:00:01`,
  `device_name="TP-Link TL-WR802N 4.0"`, `state=new`.
- **Pending:** the owner's in-app navigation test from this alert to the
  device's details.

**Calibrated interpretation:** the frames' sender is the TP-Link access point —
a concrete lead for the truncation cause (periodic IPv6 multicast emissions
from the AP), **not** proof that the AP crafts malformed packets: the frame
could be truncated anywhere on the mirror path. Determining the actual cause
still requires examining a captured sample and the mirror configuration. The
rule and its rate remain unchanged.


## 5. Sample-capture plan for the truncation cause (HELD until run)

Bounded capture on the mirror interface: at most 20 frames or 5 minutes, full
snaplen, filtered to IPv6 frames from the AP's MAC toward the multicast
destination observed in the attributed event. The pcap stays OUTSIDE the
repository (`/home/assas/sprint2-backups/`) with restricted permissions (0600)
— it may carry private network data. The rule and its rate stay unchanged until
the cause is decided.

```bash
set -euo pipefail
OUT="/home/assas/sprint2-backups/trunc-sample-$(date -u +%Y%m%dT%H%M%SZ).pcap"
rc=0
sudo timeout 300 tcpdump -i eth1 -s 0 -c 20 -w "$OUT" \
  'ether proto 0x86dd and ether src 02:00:00:00:00:01' || rc=$?
if [ "$rc" -eq 124 ]; then
  echo "WINDOW_ELAPSED: 5-minute cap reached; captured whatever arrived"
elif [ "$rc" -ne 0 ]; then
  echo "TCPDUMP_FAILED rc=$rc"; exit "$rc"
fi
sudo chown assas:assas "$OUT" && sudo chmod 600 "$OUT"
echo "SAMPLE_FILE $OUT ($(stat -c%s "$OUT") bytes)"
```
(The expected 5-minute timeout — exit 124 — is handled explicitly and is not a
tcpdump failure; without this, `set -e` would abort before reporting the file.)

Analysis (read-only, after capture):
- For each frame: on-wire captured length vs the IPv6 header's payload-length
  field, destination, and a safe header hexdump.
- **Correlation requirement:** the sample is matched against concurrent
  sid-2200013 eve events by timestamp. The first 20 IPv6 frames may all be
  healthy; if no captured frame corresponds to a truncation event, the sample is
  recorded as **inconclusive** (longer window / refined filter proposed), not as
  evidence of absence.
- **Scope of what this sample can prove:** an eth1 capture shows only what
  reaches the Pi. A short-on-wire frame here does NOT establish that the source
  emitted it short — it may have been truncated anywhere on the mirror path.
  Settling the origin requires a comparison capture taken BEFORE the mirror
  (e.g. on the AP's own segment) or switch mirror-configuration evidence; this
  sample narrows the hypotheses and characterises the frames, no more.
Only after that evidence is the STREAM/decoder rule-group proposal
(threshold/disable with stated detection impact) re-presented for decision.


## 6. Sample analysis — RESULTS (capture of 2026-11-05 05:17–05:22 +03)

Three frames captured (file outside the repo, 0600). All three are byte-for-byte
identical, ~125 s apart, and **each matches a sid-2200013 eve event to the
second with the same source MAC** — the sample IS the alerting traffic, not
bystander frames.

Per frame (full snaplen; nothing cut by tcpdump):
- On-wire length **86 bytes**, `src=::` (unspecified), `dst=ff02::1`
  (all-nodes multicast), Hop-by-Hop + ICMPv6 structure (MLD-like),
- IPv6 header **payload-length field = 8192 (0x2000)** → claimed frame 8246 B
  vs 86 B actually on the wire → Suricata's `ipv6.trunc_pkt`.

**Calibrated interpretation.** What the sample ESTABLISHES: three byte-identical
86-byte frames reached eth1, each carrying an IPv6 payload-length field (8192)
far larger than the bytes present, and each matches a sid-2200013 event to the
second — the alert fires on a genuinely length-inconsistent frame, not a
Suricata artefact. What it does NOT establish: **where** the inconsistency
originates. The mirror-truncation explanation looks **less likely** (a switch
truncating a jumbo frame would cut near its ~1514 B egress MTU, not at a
consistent 86 B ending exactly on the ICMPv6 boundary, and the engine has never
recorded any frame above 1514 B), and a source emitting malformed MLD-like
multicasts is one consistent explanation — **but neither is proven; "AP firmware
defect" is a hypothesis, not a confirmed cause.** Deciding the origin requires a
capture taken BEFORE the mirror (on the AP's own segment) or switch
mirror-configuration evidence, neither performed. The rule and its rate remain
**unchanged**; sid 2200013 is NOT reclassified as known-cause noise. Any
threshold/disable decision stays with the team and should wait for pre-mirror
evidence — this analysis only characterises the frames and narrows the
hypotheses.
