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
