# Sprint 2 — Testing

Instructions and **recorded** results. Status: ☐ Planned · ◐ In progress · ☑ Done. No result is
recorded without evidence (command + output path). Raw logs: `docs/sprint-2/evidence/`.

Rules version used for all tests: ET Open downloaded 2026-11-02 (53,305 signatures loaded, 0
failed — see `README.md`). Record the rules date/version with every test run below.

---

## Suricata Configuration  ☑ Done & tested (2026-11-02)
| Test | How | Result | Evidence |
|---|---|---|---|
| Config + rules load | `sudo suricata -T -c /etc/suricata/assas.yaml -v` | ☑ exit 0, IDS mode, 53305 rules, 0 failed | `evidence/partA-suricata-T.log` |
| Service runs on eth1 | `systemctl show assas-suricata.service` | ☑ `ActiveState=active`, `SubState=running`, `ExecMainStatus=0`, enabled | `evidence/partA-service-state.txt` |
| Rotation timer active | `systemctl is-active assas-suricata-rotate.timer` | ☑ enabled + active | `evidence/partA-service-state.txt` |
| eve.json types = alert+stats only | `python3` event-type count over `eve.json` | ☑ only `alert` + `stats` (no packet/flow/etc.) | `evidence/partA-eve-event-types.txt` |
| logrotate excludes eve.json | `sudo logrotate -d /etc/logrotate.d/suricata` | ☑ manages only `stats.log`/`suricata.log`; eve.json absent | `evidence/partA-logrotate-patterns.txt` |
| **Real rotation** (not just `-d`) | `sudo appliance/suricata/rotate-eve.sh --force` | ☑ `eve.json` (inode 909884)→renamed `eve.json-20261102-124031` (554696 B, **preserved**); fresh `eve.json` **new inode 909942** created; grew to 16089 B after stats interval (**logging resumed**); service still `active` | `evidence/partA-rotation-test.txt` |
| Rotation never deletes/compresses | inspect eve files after rotation | ☑ rotated file kept, uncompressed | `evidence/partA-rotation-test.txt` |
| No overlap / no collision | shared `flock` serialises timer vs. manual; names `.N`-suffixed | ☑ by design (script `sh -n` OK) | `appliance/suricata/rotate-eve.sh` |

**Note (for Threat Alert Ingestion):** for ~1–3 s after rotation, before Suricata processes `SIGHUP`, `eve.json`
does not exist (seen in the test: "cannot statx … No such file"). The ingester must tolerate a
transient missing/!-existent `eve.json` (retry, don't error).

## Threat Alert Ingestion (`appliance/test_alerts.py`)  ☑ unit-tested (22) + live-verified
Run: `cd appliance && ../.venv/bin/python -m pytest test_alerts.py -q` → **22 passed in 0.11s**
(full suite `pytest -q` → **497 passed**, no Sprint-1 regressions). Offline, deterministic: eve
events are synthesised as JSON lines so file identity/rotation/offsets are controllable (no Suricata
binary needed in CI). Covered:
- severity map 1→Critical, 2→High, 3→Medium, ≥4/0/unknown→Low.
- `local_naive_iso` tz→local-naive-seconds; `parse_alert_event` with and without addresses
  (decoder-event alerts → NULL addresses/ports); `split_complete_lines` leaves a partial line.
- device linking: src-only, dst-only, both (→source), neither, None.
- dedup: same rule+device within window merges (`occurrence_count`++, `last_event_time` bumped,
  `event_time` kept); outside window → new row; NULL-device grouped by rule+src+dst (unknown hosts
  not merged).
- resume: offset persisted in the same txn; re-run and **restart on a fresh DB connection** →
  no double-ingest; partial trailing line waits for completion.
- **multi-rotation restart recovery**: two `eve.json-<ts>` + live file at startup → every event
  ingested exactly once, in order; second pass adds nothing.
- **reaper preserves unread files** (unconsumed rotated file survives `reap`), deletes consumed,
  and keeps the most recent `keep` consumed; live file never reaped.
- truncation (size < stored offset) is logged (`TRUNCATION/GAP`) and re-read; missing eve.json
  (post-rotation window) tolerated.
- **Live end-to-end** (2026-11-02, `assas-alerts.service` reading the real eve.json →
  `evidence/partB-service-state.txt`, `evidence/partBC-live.txt`): service `active (running)`;
  a real Suricata alert was ingested and served; **dedup confirmed live** — 24 firings of one
  signature merged into a single alert with `occurrence_count=24`, `state=New`; severity 3 → Medium;
  the address-less decoder alert correctly linked to **no** device (`device_mac` NULL). No raw
  addresses are committed (aggregates + signature names only).

## Alert API (`test_api.py`, `test_frontend_contract.py`)  ☑ Done & tested + live-verified
Run: `cd appliance && ../.venv/bin/python -m pytest test_api.py test_frontend_contract.py -q` →
**139 passed** (full suite **503 passed**, no regressions). Covered:
- `AlertEndpointTests` (direct-call): `GET /alerts` ordered by `last_event_time` desc; device-name
  precedence (user_name→hostname→model→"Unknown device"); unlinked alert → `device_mac` null,
  "Unknown device"; `GET /alerts/{id}` + 404; `GET /devices/{mac}/alerts` filters and normalises the
  MAC; **missing `alerts` table → `[]`**.
- `AlertContractTests` (end-to-end via `TestClient`, incl. pairing): `GET /alerts` is **401 without a
  paired token**; with a token the JSON matches the `SecurityAlert` contract with **exact casing** —
  `kind="threat"`, `state="new"`, `severity="critical"`, plus `device_name`, `time`(=last_event_time),
  `first_event_time`, `occurrence_count`, `rule_id`, `source_ip`/`destination_ip`, ports, and
  `explanation`/`anomaly_score` = `null`; `/alerts/{id}` and `/devices/{mac}/alerts` return the row;
  unknown id → 404.
- **Live** (2026-11-02, `evidence/partBC-live.txt`): after restarting `assas-api` to load the new
  routes, the local API served the ingested alert with `kind=threat`, `state=new`, newest-first
  ordering, and `GET /alerts/{id}` resolving the row. (`GET /devices/{mac}/alerts` not exercised
  live — the only live alert is address-less so it links to no device — but it is unit-tested.)
  Operational note: deploying API changes requires `systemctl restart assas-api`.

## Mobile Alert Screens (`app/mobile`)  ☑ analyzed & unit-tested; visual review outstanding
Run (Flutter SDK at `~/flutter`): `flutter analyze` (mobile) → **No issues found**;
`flutter test` → **63 passed, 1 skipped** (incl. new `test/alerts_test.dart` **7 passed**);
display `flutter analyze` → **No issues found**.
- `test/alerts_test.dart`: `SecurityAlert.fromApi` parses the full contract + Sprint-2 fields
  (occurrence_count, rule_id, ports, first/last event time) with safe defaults and casing; copyWith
  preserves them; **Sprint-2 gating** locked (`alerts` true; `alertsHome`, `alertSeverityBadges`,
  `alertDisplay`, `alertExplanations`, `alertManagement`, `risk` all false); **device-list badges
  stay hidden** (`Signals.all` yields no severity while the gate is off, even with alerts present).
- Regression: `dashboard_layout_test` still asserts Home "Open alerts → SOON" (kept hidden via
  `alertsHome`); `session_ended_test` unaffected (401 short-circuits before the alerts fetch);
  `polling_lifecycle_test` wait widened past the demo `getAlerts` delay (now in the refresh path),
  assertions unchanged.
- **Known environment issue** (not a regression): `display_layout_test` fails only on writing
  `assas-display-preview.png` (Permission denied) in this session; unrelated to the alert flag.
- **Outstanding:** visual review of the Alerts tab, Alert detail, and Device-details alerts section;
  screenshots → `evidence/ui/` are captured on a dev machine (the Pi session is headless). See
  `evidence/ui/README.md`.

## Evaluation — resources  ☑ 2-hour live-traffic baseline complete (detection replay outstanding)
Run `appliance/tools/resource_sampler.py 7200 10`, 2026-11-02 13:37–15:37 UTC. Verified:
**7200 s / 720 samples**, inter-sample interval 10.0–11.0 s (**no gap >15 s**), all five services
`active` with **NRestarts=0** and continuous through the window (no restarts). Results:
**CPU avg 29.5% / max 39.9% → PASS (≤75%)**; **Suricata drop rate 0.0%** (0/163,368) → PASS;
traffic rx avg ~12 kbps (light); **total-device memory avg 4.90 GB / max 6.01 GB → target <4 GB NOT
MET under this baseline** because the Claude Code dev agent (~2.4 GB) was co-resident and is included
as required (not excluded). Appliance-only RSS ~1.49 GB (context). Memory is **not validly judged**
until a run without the dev agent; procedure + commands in `EVALUATION.md §4`. Evidence:
`evidence/resources/resource-2h.csv`, `resource-2h-summary.json`, `appliance-footprint.txt`.

## Summary of successes / failures / issues
Recorded as tests run (what passed, what failed and why, how resolved, remaining limitations).
Currently: Suricata Configuration, Threat Alert Ingestion, Alert API, and Mobile Alert Screens are
tested (see each section above); the 2-hour resource baseline is complete (CPU + drop-rate pass,
memory pending a dev-agent-free run); the Evaluation **detection replay** and the **mobile visual
review** remain outstanding.


---

## Robustness and revision testing (post-review hardening, 2026-11-04/05)

**Ingester (`appliance/test_alerts.py`):** file identity is taken from the open
descriptor (`os.fstat`), closing the rotation race between path lookup and open;
the reaper deletes a rotated file only when it has not grown past the read
offset, has been quiescent for a grace period, and no process still holds it
open (verified with a concurrent-open-writer test); structurally invalid eve
records (null/list/scalar lines, non-object `alert`) are skipped with the
offset still advancing; out-of-order events within the dedup window keep the
chronological first/last span; an IP claimed by more than one inventory row is
never linked (ambiguity → `device_mac` NULL).

**Alert API (`appliance/test_frontend_contract.py`):** `GET /alerts/open_count`
equals the database aggregate (verified against >200 and >2000 inserted rows);
`LIMIT/OFFSET` pagination returns disjoint, complete pages; the state-change
endpoint applies transitions as a single guarded UPDATE — concurrent
Review/Resolve requests from two clients cannot revert a Resolved alert
(threaded test). The state-management UI is gated off; the endpoints and their
tests remain part of the codebase.

**Mobile (`app/mobile/test/`):** overflow-free rendering across the full
supported font range (app text-size zoom {1.0, 1.2} × system scale
{0.85, 1.0, 1.3} × widths {320, 400}) for the alerts, devices, settings,
pairing and splash screens; live text-size switching (all four sizes, forward
and back, without rebuilding the screen) does not overflow mid-animation;
device-filter labels stay fully visible while the font size changes with the
menu open; the alerts list loads older alerts on demand instead of a silent
cap; opaque machine-identifier names display as "Unknown device" on all alert
surfaces while rename and MAC are unaffected.

**Suite totals after the revision:** appliance **519 passed** (108 subtests);
mobile **76 passed**, `flutter analyze` clean (mobile and display).

## Operational verifications (2026-11-05)

- **Rule-scope tuning:** enabled rules 53,305 → 53,293; the enabled-SID diff
  equals exactly the 12 approved normal-usage SIDs; `suricata -T` passed;
  post-apply monitoring shows zero new events from the disabled SIDs while
  other detection continues (`README.md` §Rule-scope tuning,
  `evidence/rule-tuning/`).
- **Alert-log reset:** 645 rows deleted after a validated WAL-aware backup;
  read checkpoints preserved — no historical re-ingestion (0 rows immediately
  after restart; only newer events enter). Devices, trust, pairing and rules
  untouched (`evidence/alert-log-reset.md`).

## Address-evidence attribution tests (2026-11-05)

`appliance/test_discovery.py`: NDP neighbor parsing keeps REACHABLE/STALE/DELAY
and discards INCOMPLETE/FAILED (unproven); an external address is never
recorded as evidence even when carried by the router's MAC (IPv4 and IPv6);
local IPv4/ULA/link-local and monitored-prefix global IPv6 are recorded with
first_seen kept and last_seen bumped; an authoritative source (ndp/arp/dhcp)
upgrades a traffic-derived row, never the reverse; the global-IPv6 fan-out cap
blocks new addresses while still updating known ones; address normalization
(exploded IPv6 / dotted IPv4).

`appliance/test_alerts.py`: a device with one IPv4 and multiple (rotating)
IPv6 addresses links through the evidence set, including the rotated-out
address for events inside its own window; evidence-window boundaries hold on
both sides (first − 1 h 59 m links, first − 2 h 01 m does not; last + 23 h 59 m
links, last + 24 h 01 m does not); an ownership conflict (two MACs, one
address) never links; the compressed-vs-exploded IPv6 form difference between
the inventory columns and eve.json no longer breaks matching; `relink_recent`
links a recent unlinked alert after late evidence while leaving
occurrence_count, state and event times untouched, never rewrites alerts
outside its bounded window, and is idempotent; a database without the
`device_addresses` table behaves exactly as before.

`appliance/test_api.py`: the alert device name follows the device-details
precedence (user name → human hostname with opaque machine identifiers
skipped → model → "Unknown device"), from inventory data only.

Review hardening (same date): the evidence table is authoritative — a stale
address still present in the single-value columns cannot link an event outside
its ownership window (tested with the expired address kept in
`last_ipv6_global`); the fan-out cap counts recent addresses only (historical
rotated-out addresses are kept and never block a device's new addresses);
NS/NA messages are validated (link-layer option present and equal to the frame
source; DAD, multicast targets and mismatching options rejected — tested
through the real packet handler with crafted scapy packets, including the
gateway-MAC Proxy-NDP exclusion); locality is strict (RFC 1918/ULA alone are
not accepted; monitored subnets plus RA-learned on-link prefixes from a
link-local source define the context).

Suites after the change: appliance **538 passed** (108 subtests), mobile
**76 passed**, `flutter analyze` clean. Live verification of the attribution
is recorded separately once performed on the appliance.
