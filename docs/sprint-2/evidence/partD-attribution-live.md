# Address-Evidence Attribution — Live Verification (2026-11-05)

Deployed `sprint-2 @ 7144b31` at 02:47 (+03); `assas-discovery`, `assas-alerts`
and `assas-api` restarted and `active`; `/healthz` ok. All checks below are
read-only queries against the production database and API.

## Evidence collection (within ~90 s of deployment)
`device_addresses`: 17 rows — 14 IPv4 (`source=arp`), 2 link-local and 1 global
IPv6 (`source=span`, locality-guarded). The recorded global IPv6 is the
**privacy address behind the previously-unlinked alert cluster**
(`2001:0db8:c83e:5700:78f5:8a3d:cbf4:b5fe` → `02:5a:01:00:0e:8f`).
Gateway-MAC rows with `source=ndp`: **0** (Proxy-NDP exclusion holding).

## Discovery-lag repair (relink of recent unlinked alerts)
The four IPv6 alerts from the 01:27–01:30 cluster (ids 1298, 1300, 1301, 1304),
stored unlinked before the feature existed, are now **linked to
`02:5a:01:00:0e:8f`**: the late evidence (first_seen 02:47) covers their event
times via the pre-slack bound (01:27 ≥ 02:47 − 2 h). Integrity preserved —
id 1304 after relink: `occurrence_count = 1`, `state = New` (only `device_mac`
was written).

## Current linking state
- **Linked: 23 rows (occ 115). Unlinked: 1 row (occ 54)** — the remaining NULL
  is `SURICATA IPv6 truncated packet` with **no addresses in the event itself**;
  no evidence can exist for it. This is the honest limit: linking is
  evidence-based, and address-less decoder events stay unlinked by design.
- **Post-deploy alerts link at insert time** (ids ≥ 1306: IPv4 and IPv6 events
  all carried `device_mac` on arrival).
- **Deduplication now groups by device** for the attributed events (e.g. one
  row with `occurrence_count = 10` for repeated STUN events on the same rule
  and device) instead of splitting per external server.

## Display-name unification (API)
A linked alert of `02:5a:01:00:0e:8f` is served with
`device_name = "emulator (sdk_gphone64_x86_64)"` (inventory model; the opaque
UUID hostname is skipped) — matching the device-details screen.

## Pending (owner)
Visual confirmation in the app that an IPv6-linked alert's device pill opens
the correct device details. Data prerequisite verified: the MAC exists in the
device inventory (online), so the pill is tappable.
