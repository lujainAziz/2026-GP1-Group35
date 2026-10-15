# Sprint 0/1 local repairs — 2026-10-15

Branch: test/mobile-theme. Changes remain local and uncommitted; no push.

## Implemented

- Unpair retains the local session on network/server failure. HTTP 401 means the
  credential is already invalid. The backend now returns failure if deletion fails.
- Protected settings and device actions notify the common session-expired handler.
- Settings retry every five seconds, expose a retry, and read changes made elsewhere.
- Initial connection status is Connecting, not Connected. Session text no longer
  claims transport security. Detail failures expose Retry; null summary values no
  longer resurrect stale detail fields.
- All optional identification probe gates, including SSDP/UPnP, follow active_probes.
  New databases default off; existing saved choices are preserved.
- Recent observed devices map to Online. A last-seen age over 120 seconds maps to
  Offline without changing monitored. Legacy records without a timestamp retain
  their stored presence. No idle-based removal of monitoring was introduced.
- The API returns timezone-qualified first/last-seen and pairing expiry values.
- API and pairing responses include a persistent appliance_id. New pairings store
  this ID with the token. Discovery verifies it before choosing a destination.
  Failed transport operations cause rediscovery on the next request; writes are
  not automatically replayed. IDs prevent accidental cross-appliance selection;
  they are not cryptographic server authentication and do not replace TLS.
- iOS camera usage description added. Actual iOS build/camera validation remains.
- flows.py accumulates directional IPv4/IPv6 protocol/port metadata in 60-second
  windows, with packet counts, captured IP byte counts, first/last timestamps.
  Unavailable ports are -1. No payload is stored. Capture now includes all IP
  packets and still forwards each packet to the existing inventory handler.
  Up to 10,000 tuples are buffered, flushed on capacity or every five seconds.
  Persisted counters are additive across flushes; no ML feature extraction is implied.
- A capture heartbeat is persisted even on idle networks. Health uses it when
  available, falling back to legacy device timestamps for old deployments.

## Validation

- Mobile and display Flutter analysis passed.
- Mobile widget/unit tests passed, including failed-unpair credential retention,
  settings recovery, and common 401 handling.
- Display layout/new-phone banner test passed.
- Real HTTP Flutter contract against an isolated fresh FastAPI fixture passed,
  including identity matching and rediscovery after a failed destination.
- Backend API, discovery, classification, integration and generated-PCAP tests run.
  The PCAP test uses synthetic packets; it is not a physical switch capture.

## Deployment and hardware acceptance

Deploy api.py, discovery.py and flows.py together with the updated apps. Back up
production SQLite before deployment. New tables are additive. Existing sessions
without an appliance ID need a successful new pairing to gain ID binding.

Still requires real hardware: switch/AP mirroring, identification probes on actual
clients, multi-appliance DNS-SD and changing DHCP addresses, Android/iOS camera,
restart persistence, traffic loss/load and disk growth measurements. The current
mobile/browser preview remains DEMO. No Pi deployment was performed.

Remote access/notifications remain Sprint 5. Monitoring coverage is not inferred
from silence. Source/reason-of-classification UI additions were deliberately not
included because the accepted Sprint 1 requirements do not request them.

## Discovery/classification follow-up — 2026-10-16

- Presence recording no longer depends on successful TCP SYN classification or
  fingerprint rate limits. Foreign IP evidence is rejected before classification
  when the monitored subnet context identifies it as outside the local network.
- Passive IPv6 addresses are recorded, and local IPv6 subnets are learned from
  the discovery interface. Active unicast probe transports remain IPv4-only.
- Delayed probes validate the persisted active_probes switch and current MAC/IP
  binding before sending. Responses are discarded if the target binding changed.
  Already transmitted packets cannot be recalled.
- Port/mDNS/NBNS/SSDP/UPnP scheduling has an in-flight gate, a 60-second retry
  cooldown, and at most three attempts per worker/MAC/IP per service runtime.
  Further observations trigger retries; there is no busy retry loop.
- Hostname classification weight is now 70, below service evidence (85) and model
  evidence (95). Existing hostname-only scores are normalized when updated so
  stronger new evidence can correct an old verdict.
- Vendor updates compare evidence strength instead of keeping the first guess
  forever; stronger UPnP/manufacturer/model evidence can replace weaker inferred
  sources, while weaker guesses cannot replace stronger records.

Validation: 346 backend tests passed, including nine new safety regressions.
No physical network identification accuracy claim is made. Validate on the Pi
with actual devices, DHCP address changes and enabled/disabled optional probes.
No changes were pushed to GitHub.
