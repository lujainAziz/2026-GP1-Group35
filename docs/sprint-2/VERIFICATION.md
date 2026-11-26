# Sprint 2 — Final Verification

> **Superseded in Release 1.** Some Threat Alert behaviour described here has
> changed: the Reviewed state is removed (New → Resolved only); severities are
> High / Medium / Low (priority 1 → High, 2 → Medium, 3 or more or missing → Low;
> no Critical); the fallback title is "Network activity detected" and names the
> original rule; the app shows the detection count and first/last detection
> times; the test rules are SIDs 1000001-1000003 (1000004 retired); "Network
> Risk" is renamed "Network Alert Level" (Sprint 4). This document records
> Sprint 2 as delivered. Current behaviour: `docs/database-schema.md`,
> `docs/API_CONTRACT.md`, `docs/sprint-2/threat-alert-titles.md`.

**Sprint status: implementation and automated tests are complete; the clean
resource run is done (CPU pass; memory target NOT met — see #8/R); the
drop-measurement re-run (corrected tool, pending an agent-free window) and the
owner's visual sign-off are still pending — Sprint 2 is NOT fully closed.**

Practical verification of each acceptance requirement. **Automated** = test suite; **Live** =
observed on the running appliance. Synthetic/unit tests are **not** a substitute for the dataset
detection evaluation, which was completed offline on 23-24 November 2026 (row D). No test data was written into
production logs; live evidence is redacted of addresses/MACs. Commit links:
`github.com/lujainAziz/2026-GP1-Group35/commit/<hash>`.

Legend: ✅ pass · ❌ fail · ☐ not tested.

| # | Requirement | Verdict | Method | Actual result | Evidence | Commit |
|---|---|---|---|---|---|---|
| 1 | Five services up; no faults/restarts during the test | ✅ | Live | All five `active`/`enabled`, **NRestarts=0**, active-since predates the 13:37–15:37 UTC window → continuous; journal 0 stop/fail events | `evidence/resources/` (§4), service check | `2bea922` |
| 2 | Full path: traffic on `eth1` → Suricata event → SQLite alert → API → app | ✅ to API (Live) · ☐ app | Chain demonstrated live (eth1→Suricata→SQLite→API). After the #5 fix + cleanup the ingester is healthy and caught up (331 rows, no crash loop). App leg pending visual review (#7) | `evidence/final-live-verify.txt`, `evidence/partB-cleanup-verify.txt` | `6d15b7d`,`810c3ab`,`10b78e7` |
| 3 | Dedup: `occurrence_count`↑, keep first & last event time, don't merge unrelated hosts | ✅ (Automated + Live; data corrected) | Live + Automated | Dedup logic verified (occ `first<last`; NULL-device rules kept separate). The #5 re-read defect had inflated the live data; **after fix + cleanup, `SUM(occurrence)=2843 == 2843` source events (diff 0)** — counts now match source exactly | `evidence/partB-cleanup-verify.txt`, `evidence/final-live-verify.txt`; `appliance/test_alerts.py` | `6d15b7d`,`10b78e7` |
| 4 | Link alert to the right device; `device_mac` NULL when no match | ✅ (upgraded) | Live + Automated | Original rules verified, then attribution upgraded (2026-11-05): multi-address evidence (`device_addresses` from ARP/DHCP/validated NDP/guarded traffic) with event-time windows; MAC-based linking for address-less events (gateway/multicast/appliance excluded; both default routes' gateway MACs resolved via neighbor tables). Live: 23 of 24 rows linked post-deploy; the four privacy-IPv6 alerts relinked with counters untouched; the first MAC-attributed event linked to the TP-Link AP with the IPv6 gateway's distinct MAC excluded; the only NULL is the address-less history row. Automated: 30+ linking tests incl. window boundaries, conflicts, router exclusion | `evidence/partD-attribution-live.md`, `evidence/capture-path-check.md`; `test_alerts.py`, `test_discovery.py` | `227bce8`,`7144b31`,`df5d2a4`,`30b7710` |
| 5 | Resume after reader stop; multiple rotations; no loss/dup; keep unread files | ✅ Fixed + verified (Automated + Live) | Automated + Live | A reboot-induced `offset>size` had made the old handler **re-read from 0 → duplicate** (68→651, occ→1496) and an unhandled `UnicodeDecodeError` crash-looped it. **Fixed (`10b78e7`)**: gap→resume at EOF (no re-read, documented data loss), decode errors skipped. **Deployed + cleaned 2026-11-03**; independent verification: 331 rows, `SUM(occurrence)=2843 == 2843` source events (diff 0), caught up, no crash. **Restart-safety re-check:** a restart left rows/`SUM(occurrence)`/offset **identical** (337/2854/29899717 before==after) → resumed from checkpoint, no re-ingestion. Pre-reset: 0 DB-only alerts; backup preserves prior state. | `evidence/partB-defect-duplication.md`, `evidence/partB-cleanup-verify.txt`, `evidence/partB-restart-safety.txt`; `appliance/test_alerts.py` | `10b78e7` |
| 6 | Three endpoints: reject unauthenticated; succeed with a paired session | ✅ | Live + Automated | Live from a **non-local (LAN-IP)** address: **401 without a token** and **200 with a valid paired token** on all three (`/alerts`, `/alerts/{id}`, `/devices/{mac}/alerts`); token obtained via the normal pairing flow and removed with `/unpair` afterwards (token never printed/stored). localhost→200 only exercises the local-bypass path. Automated: `AlertContractTests` — 401 without token, 200 + exact contract with a token | `evidence/partC-auth-live.txt`; `appliance/test_frontend_contract.py` | `810c3ab` |
| 7 | Alert screens + navigation; data matches the API | ◐ screenshots generated; owner sign-off pending | Automated render | Current UI state: the security alert screens are live (list, details with Last seen, per-device alerts); **alert state management is released** (`alertManagement` on) — All/Open/Resolved tabs, New/Reviewed/Resolved badges, Review/Resolve actions, live unresolved (New+Reviewed) counter; device-name unification; connection wording Online/Outdated/Offline; redesigned device filters; corrected pairing and Home texts; Active-identification load/error states. Independent per-device/by-id fetch with pagination. Whole-app overflow tests span zoom {1.0,1.2} × scale {0.85,1.0,1.3} × widths {320,400}. Screenshots: `evidence/ui/*.png`; UI behaviour summarised in `README.md` and `TESTING.md`. Not marked passed until the owner confirms the live screens and data-matches-API. | `evidence/ui/`, `test/detail_overflow_test.dart`, `test/alerts_test.dart` | `a9278cc`,`cdad1da`,`b65d25b`,`df5f387` |
| 8 | Independent 2-hour resource run **without** the dev agent (CPU/mem/traffic/drops/continuity) | ✅ CPU · ❌ memory · ☐ drops not validated | Live | Completed 2026-11-05 02:26–04:26 UTC, guard **0 PRESENT**: CPU avg **36.71 %** PASS; memory avg **4046 MB**/max 4470 → **NOT met** even agent-free (appliance ≈1.7–1.8 GB; remainder is the desktop/system stack — analysis in `EVALUATION.md §4`); drops 0/6,193,620 with clean counters but **not validated** — the sampler's PID detector missed the real process name `Suricata-Main` (tool defect, fixed + regression-tested; re-run pending decision). 720 samples, 0 gaps, five services continuous. Baseline verdict retained unchanged. | `evidence/resources/clean/`; `EVALUATION.md §4` | `(this commit)` |
| 9 | Later-sprint features stay hidden; Sprint 1 not broken | ✅ | Automated | Gating test locks the released flag state — enabled: security alert display, alert state management, and device signals from unresolved alerts (`alerts`/`alertManagement`/`alertSeverityBadges` = true); hidden: Home open-alerts summary, display count, plain-language explanations, network risk and behavioural baseline (`alertsHome`/`alertDisplay`/`alertExplanations`/`risk`/`baseline` = false). *(Release 1: `alertDisplay` is now true; the 7-inch display shows the unresolved alert count.)* Suites green: appliance **555 passed**, mobile **80 passed** | `app/mobile/test/alerts_test.dart`; suites | `87d819e`,`df5f387` |
| R | Resource targets (CPU ≤75% avg, memory <4 GB, drops) — baseline | ✅ CPU · ✅ drops · ❌ memory | Live | CPU avg **29.5%**/max 39.9% (PASS); drop rate **0.0%** (0/163,368) (PASS); total-device memory avg **4.90 GB**/max 6.01 GB → **NOT met** (dev agent co-resident; not excluded) | `evidence/resources/resource-2h-summary.json` | `2bea922` |
| D | Detection evaluation on a labelled attack dataset (IoT-23, offline) | ✅ | Offline (IoT-23) | 20 malware + 3 benign IoT-23 captures read offline by Suricata on the appliance (`suricata -r`, configuration and rules unchanged) and processed by the real alert pipeline into a separate test database; no traffic replayed, no malware executed. Alerts on the infected device in **16 of 20** malware captures: 4 Strong, 12 Indirect, 0 Weak, 4 Not detected. 14,783,458 alert events → 1,096 alerts, all associated with the infected device; no alert on any device in the benign captures (one low-severity protocol event in the Philips Hue capture was not associated with a device). Precision/recall not computed; CICIoT2023 not tested in Release 1 | Project report, Chapter 5; `appliance/tools/IOT23_OFFLINE_TEST.md` | `6bd3981` |

## Verification classes — automated vs live vs pending

**Automated (executed test suites):** appliance **555 passed** (108 subtests) —
ingester (rotation/reaper/resume/linking incl. the address-evidence and MAC
attribution rules, and the resolved-is-terminal rule), API contracts (auth,
pagination, open-count aggregate, state transitions), tooling parsers; mobile
**80 passed** — gating, overflow
across the full font range, in-place size-transition tests (Home, devices,
settings), filters, pagination, name handling; `flutter analyze` clean
(mobile + display).

**Live (performed on the appliance, documented with actual output):**
Suricata/ingestion/API chain; auth 401/200 over the LAN with a paired session;
rule tuning applied with the enabled-set diff limited to the 12 approved SIDs;
alert-log reset with preserved checkpoints; attribution deployed — relink of
the privacy-IPv6 alerts, insert-time linking, MAC attribution of the first
address-less event, both gateways excluded. Evidence: `evidence/*.md`/`.txt`.

**Pending (explicitly NOT verified yet):**
- **Owner visual review** of the running app — including the IPv6-linked alert
  → device navigation and the Home stat card at different font sizes
  (automated widget tests exist; they are not on-device verification).
- **Truncated-frame sample capture** → actual truncation cause → the
  STREAM/decoder rule-group decision (rule and rate unchanged until then).
- **Drop-measurement re-run** — PENDING, not run. The clean run completed (CPU
  pass; memory NOT met; drops recorded but NOT validated — the PID detector
  missed `Suricata-Main`). The tool is fixed and now samples the PID every
  interval, but a validated drop figure needs a fresh agent-free 2-hour window
  that is not available yet.
- **Memory Shmem breakdown** — the ≈1.4 GiB of non-tmpfs Shmem is unattributed
  from an unprivileged vantage (SysV shm 0, tmpfs ≈342 MiB, Suricata smaps and
  GEM/dma-buf root-only); any memory-reduction proposal is blocked on a
  privileged breakdown first (`EVALUATION.md` memory section). No reduction
  claimed or applied.

## Reader-restart smoke test (#5) — sudo batch (smoke test only)
This is a **smoke test** — it shows the reader comes back and keeps its alerts across a restart; it
is **not** full resume proof on its own (that is the automated `test_alerts.py` plus the read-only
checkpoint/occurrence cross-check above). It preserves data and injects no synthetic events.
Notes: query with a **high `limit` (1000)** so the 200-default pagination can't make IDs look
missing; a **manual `systemctl restart` is an intentional test action and is not necessarily counted
by `NRestarts`** (which tracks automatic, policy-driven restarts) — record it separately.
```
cd /home/assas/assas
api(){ python3 -c "import urllib.request,json;print(sorted(int(a['id']) for a in json.load(urllib.request.urlopen('http://127.0.0.1:8000/alerts?limit=1000',timeout=5))))"; }
api > /tmp/before.txt
echo "INTENTIONAL TEST ACTION: manual restart of assas-alerts at $(date -u +%FT%TZ)"
sudo systemctl restart assas-alerts.service   # manual/intentional — not an automatic NRestarts event
sleep 8
api > /tmp/after.txt
python3 - <<'PY'
b=set(eval(open('/tmp/before.txt').read())); a=set(eval(open('/tmp/after.txt').read()))
print("before:",len(b)," after:",len(a))
print("all pre-restart ids still present (no loss/renumber):", b.issubset(a))
print("ids lost (must be empty):", sorted(b-a))
print("new ids during restart window (live traffic, possible):", sorted(a-b))
PY
systemctl is-active assas-alerts.service
systemctl show -p NRestarts --value assas-alerts.service  # automatic restarts only; manual restart not counted here
```

## Mobile visual review (#7) — steps and required screenshots
Do **not** write test data into production logs/DB (see `evidence/ui/README.md`): use demo mode or an
isolated test backend. On a machine with Flutter:
```
cd app/mobile && flutter pub get && flutter run   # or: flutter run -d chrome
```
Pair using the code on the 7-inch display, then capture into `docs/sprint-2/evidence/ui/`
(**final: alert state management released — the state-management UI is live**):
1. `alerts-tab.png` — hero shows the live unresolved count (New+Reviewed); All/Open/Resolved
   tabs; list rows: title, severity, device, last event time, state badge; newest first.
2. `alert-details.png` — title, time, device pill (navigates to device details); **state badge**
   and **Review/Resolve actions** (New→Reviewed, New→Resolved, Reviewed→Resolved; Resolved
   terminal, actions gone); Signal details: alert type, severity, last seen, source/destination IP
   (first seen / rule ID / ports hidden; explanation hidden — later sprint).
3. `device-alerts.png` — the device's alerts (no "Coming soon").
4. `device-list.png` — severity flag on alerting devices (severity palette; device signals from unresolved alerts).
Also capture a Review/Resolve round-trip (New → Reviewed → Resolved) and confirm the hero count
decrements as alerts resolve. Confirm each screen's values match `GET /alerts` / `/alerts/{id}` /
`/devices/{mac}/alerts`.
