# Sprint 2 — Final Verification

Practical verification of each acceptance requirement. **Automated** = test suite; **Live** =
observed on the running appliance. Synthetic/unit tests are **not** a substitute for the dataset
detection evaluation (that item is explicitly ☐ not-tested). No test data was written into
production logs; live evidence is redacted of addresses/MACs. Commit links:
`github.com/lujainAziz/Assas/commit/<hash>`.

Legend: ✅ pass · ❌ fail · ☐ not tested.

| # | Requirement | Verdict | Method | Actual result | Evidence | Commit |
|---|---|---|---|---|---|---|
| 1 | Five services up; no faults/restarts during the test | ✅ | Live | All five `active`/`enabled`, **NRestarts=0**, active-since predates the 13:37–15:37 UTC window → continuous; journal 0 stop/fail events | `evidence/resources/` (§4), service check | `2bea922` |
| 2 | Full path: traffic on `eth1` → Suricata event → SQLite alert → API → app | ✅ to API (Live) · ☐ app | Chain demonstrated live (eth1→Suricata→SQLite→API). After the #5 fix + cleanup the ingester is healthy and caught up (331 rows, no crash loop). App leg pending visual review (#7) | `evidence/final-live-verify.txt`, `evidence/partB-cleanup-verify.txt` | `6d15b7d`,`810c3ab`,`10b78e7` |
| 3 | Dedup: `occurrence_count`↑, keep first & last event time, don't merge unrelated hosts | ✅ (Automated + Live; data corrected) | Live + Automated | Dedup logic verified (occ `first<last`; NULL-device rules kept separate). The #5 re-read defect had inflated the live data; **after fix + cleanup, `SUM(occurrence)=2843 == 2843` source events (diff 0)** — counts now match source exactly | `evidence/partB-cleanup-verify.txt`, `evidence/final-live-verify.txt`; `appliance/test_alerts.py` | `6d15b7d`,`10b78e7` |
| 4 | Link alert to the right device; `device_mac` NULL when no match | ✅ (upgraded) | Live + Automated | Original rules verified, then attribution upgraded (2026-11-05): multi-address evidence (`device_addresses` from ARP/DHCP/validated NDP/guarded traffic) with event-time windows; MAC-based linking for address-less events (gateway/multicast/appliance excluded; both default routes' gateway MACs resolved via neighbor tables). Live: 23 of 24 rows linked post-deploy; the four privacy-IPv6 alerts relinked with counters untouched; the first MAC-attributed event linked to the TP-Link AP with the IPv6 gateway's distinct MAC excluded; the only NULL is the address-less history row. Automated: 30+ linking tests incl. window boundaries, conflicts, router exclusion | `evidence/partD-attribution-live.md`, `evidence/capture-path-check.md`; `test_alerts.py`, `test_discovery.py` | `227bce8`,`7144b31`,`df5d2a4`,`30b7710` |
| 5 | Resume after reader stop; multiple rotations; no loss/dup; keep unread files | ✅ Fixed + verified (Automated + Live) | Automated + Live | A reboot-induced `offset>size` had made the old handler **re-read from 0 → duplicate** (68→651, occ→1496) and an unhandled `UnicodeDecodeError` crash-looped it. **Fixed (`10b78e7`)**: gap→resume at EOF (no re-read, documented data loss), decode errors skipped. **Deployed + cleaned 2026-11-03**; independent verification: 331 rows, `SUM(occurrence)=2843 == 2843` source events (diff 0), caught up, no crash. **Restart-safety re-check:** a restart left rows/`SUM(occurrence)`/offset **identical** (337/2854/29899717 before==after) → resumed from checkpoint, no re-ingestion. Pre-reset: 0 DB-only alerts; backup preserves prior state. | `evidence/partB-defect-duplication.md`, `evidence/partB-cleanup-verify.txt`, `evidence/partB-restart-safety.txt`; `appliance/test_alerts.py` | `10b78e7` |
| 6 | Three endpoints: reject unauthenticated; succeed with a paired session | ✅ | Live + Automated | Live from a **non-local (LAN-IP)** address: **401 without a token** and **200 with a valid paired token** on all three (`/alerts`, `/alerts/{id}`, `/devices/{mac}/alerts`); token obtained via the normal pairing flow and removed with `/unpair` afterwards (token never printed/stored). localhost→200 only exercises the local-bypass path. Automated: `AlertContractTests` — 401 without token, 200 + exact contract with a token | `evidence/partC-auth-live.txt`; `appliance/test_frontend_contract.py` | `810c3ab` |
| 7 | Alert screens + navigation; data matches the API | ◐ screenshots generated; owner sign-off pending | Automated render | Current UI state: PBI-14 screens live (list, details with Last seen, device alerts); PBI-22 surfaces hidden (`alertManagement` off) with backend endpoints and stored states retained; detail fields beyond type/severity/last seen/addresses hidden; device-name unification; connection wording Online/Outdated/Offline; redesigned device filters; corrected pairing and Home texts; Active-identification load/error states. Independent per-device/by-id fetch with pagination. Whole-app overflow tests span zoom {1.0,1.2} × scale {0.85,1.0,1.3} × widths {320,400}. Screenshots: `evidence/ui/*.png`; UI behaviour summarised in `README.md` and `TESTING.md`. Not marked passed until the owner confirms the live screens and data-matches-API. | `evidence/ui/`, `test/detail_overflow_test.dart` | `a9278cc`,`cdad1da`,`b65d25b`,`df5f387` |
| 8 | Independent 2-hour resource run **without** the dev agent (CPU/mem/traffic/drops/continuity) | ☐ | — | Not yet run (the agent is the co-resident process). Script ready: `clean_resource_run.sh` (aborts if agent present; guards throughout). **First run retained: memory target NOT met.** | `appliance/tools/clean_resource_run.sh`; `EVALUATION.md §4` | `6bd3981` |
| 9 | Later-sprint features stay hidden; Sprint 1 not broken | ✅ | Automated | Gating test locks the released flag state: `alerts`/`alertSeverityBadges` = true; `alertManagement`/`alertsHome`/`alertDisplay`/`alertExplanations`/`risk` = false. Suites green: appliance **551 passed** (108 subtests), mobile **80 passed** | `app/mobile/test/alerts_test.dart`; suites | `87d819e`,`df5f387` |
| R | Resource targets (CPU ≤75% avg, memory <4 GB, drops) — baseline | ✅ CPU · ✅ drops · ❌ memory | Live | CPU avg **29.5%**/max 39.9% (PASS); drop rate **0.0%** (0/163,368) (PASS); total-device memory avg **4.90 GB**/max 6.01 GB → **NOT met** (dev agent co-resident; not excluded) | `evidence/resources/resource-2h-summary.json` | `2bea922` |
| D | Detection evaluation on replayed attack datasets | ☐ | — | **Not tested** — datasets on hold (no download). Synthetic/unit alerts are **not** a substitute. Replay host + IoT-23 selection prepared | `EVALUATION.md §1–3` | `6bd3981` |

## Verification classes — automated vs live vs pending

**Automated (executed test suites):** appliance **551 passed** (108 subtests) —
ingester (rotation/reaper/resume/linking incl. the address-evidence and MAC
attribution rules), API contracts (auth, pagination, open-count aggregate,
state transitions), tooling parsers; mobile **80 passed** — gating, overflow
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
- **Clean 2-hour resource run** without the co-resident dev agent (memory
  target judgement).
- **Dataset detection evaluation** — plan ready in `EVALUATION.md`; downloads
  held for approval.
- **Merge `sprint-2` → main** at sprint close (owner).

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
(**final: PBI-22 deferred again — state-management UI hidden**):
1. `alerts-tab.png` — hero keeps the count design with a muted "—" (live count deferred with
   PBI-22); no tabs/state pills; list rows: title, severity, device, last event time; newest first
   (no occurrence `N×`).
2. `alert-details.png` — title, time, device pill (navigates to device details); Signal details:
   alert type, severity, last seen, source/destination IP; **no** Review/Resolve, **no** state badge
   (deferred SOON tag instead; no occurrences / first seen / rule ID / ports; explanation hidden).
3. `device-alerts.png` — the device's alerts (no "Coming soon").
4. `device-list.png` — severity flag on alerting devices (severity palette, PBI-09/10).
Confirm each screen's values match `GET /alerts` / `/alerts/{id}` / `/devices/{mac}/alerts`.
