# Capture-load check (completed 2026-11-09)

This complements `capture-path-check.md`, which investigated sid 2200013; both
found `capture.kernel_drops = 0`.

Purpose: decide whether SURICATA STREAM events come from packet loss on the
capture path (mirror/offload) or from the monitored traffic itself. This check
was the prerequisite for the STREAM/decoder decision deferred on 2026-11-05.

## Setup
- One phone on the Assas-Test network played a 1080p video for about 11 minutes
  (about 20:36 to 20:47, +03).
- This was a normal home-usage load, **not** a maximum stress test.

## Results

### Suricata counters during the test
- `capture.kernel_packets`: 171,761 at 20:36 -> 419,989 at 20:47, i.e.
  **about 248,000 packets** processed during the test.
- `capture.kernel_drops` = **0**.
- `tcp.reassembly_gap` = **0**.

Note: `stats.log` omits counters whose value is zero because `null-values` is
not enabled in the stats output. Both zero values above are therefore read
from the counters being absent from `stats.log`, not from an explicit `0`.

### eth1 interface counters (`ip -s link`)
- Snapshot at about 20:30 (+03), **before** the load test: **148,716 packets
  received, 32 dropped (about 0.02%)**.

These numbers are not directly comparable with the Suricata counters above:
they cover a different time window (a snapshot before the test, not the
increase during it) and they are different counters. The eth1 counter counts
packets the Linux kernel dropped on that interface for any reason, while
`capture.kernel_drops` counts packets Suricata's capture socket missed. The
cause of the 32 interface drops was not investigated.

## Conclusion
Under this load Suricata's capture socket missed no packets and no TCP
reassembly gaps occurred, so the STREAM events are **not caused by capture
loss**. On this basis the team decided on 2026-11-09 to disable the
`stream-events.rules` group together with the other noise rules (Round 2 in
`appliance/suricata/disable.conf`).
