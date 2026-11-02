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
| 2 | Full path: traffic on `eth1` → Suricata event → SQLite alert → API → app | ✅ to API (Live) · ☐ app | 68 live alerts (21 distinct signatures) from `eth1` traffic ingested to `alerts` and served by the API; **app leg pending visual review (#7)** | `evidence/final-live-verify.txt`; `evidence/partBC-live.txt` | `6d15b7d`,`810c3ab`,`25eb0f4` |
| 3 | Dedup: `occurrence_count`↑, keep first & last event time, don't merge unrelated hosts | ✅ | Live + Automated | Live: occ up to **204**, `first<last` (e.g. id=1 15:40:44→22:45:09); same-second merges keep equal times; NULL-device rules 2210045 & 2210030 each kept as **separate** alerts (distinct src/dst). Automated: `test_alerts.py` dedup + NULL-device cases | `evidence/final-live-verify.txt`; `appliance/test_alerts.py` | `6d15b7d` |
| 4 | Link alert to the right device; `device_mac` NULL when no match | ✅ | Live + Automated | Live: **56 linked**, **12 NULL** (link-local / address-less → NULL). Automated: one/both→source/neither rules in `test_alerts.py` | `evidence/final-live-verify.txt`; `appliance/test_alerts.py` | `6d15b7d` |
| 5 | Resume after reader stop; multiple rotations; no loss/dup; keep unread files | ✅ Automated · ☐ live spot-check | Automated | `test_alerts.py`: resume on fresh DB (no double-ingest), multi-rotation recovery (every event once, in order), reaper preserves unconsumed files, truncation logged. Live restart spot-check optional (sudo batch below) | `appliance/test_alerts.py`; live dedup `partBC-live.txt` | `6d15b7d` |
| 6 | Three endpoints: reject unauthenticated; succeed with a paired session | ✅ | Live (reject) + Automated (accept) | Live: localhost→200; **LAN-IP no token → 401** on `/alerts`, `/alerts/{id}`, `/devices/{mac}/alerts`. Automated: `AlertContractTests` — 401 without token, 200 + exact contract with a paired token | `evidence/final-live-verify.txt`; `appliance/test_frontend_contract.py` | `810c3ab` |
| 7 | Three alert screens + navigation; data matches the API | ☐ | — | **Pending owner visual review.** Steps + required screenshots below and in `evidence/ui/README.md`; not marked passed until confirmed | `evidence/ui/README.md` | `87d819e` |
| 8 | Independent 2-hour resource run **without** the dev agent (CPU/mem/traffic/drops/continuity) | ☐ | — | Not yet run (the agent is the co-resident process). Script ready: `clean_resource_run.sh` (aborts if agent present; guards throughout). **First run retained: memory target NOT met.** | `appliance/tools/clean_resource_run.sh`; `EVALUATION.md §4` | `6bd3981` |
| 9 | Later-sprint features stay hidden; Sprint 1 not broken | ✅ | Automated | Gating test locks `alerts=true` with `alertsHome`/`alertSeverityBadges`/`alertDisplay`/`alertExplanations`/`alertManagement`/`risk`=false; appliance **503 passed**, mobile **63 passed** (Sprint 1 suites green) | `app/mobile/test/alerts_test.dart`; suites | `87d819e` |
| R | Resource targets (CPU ≤75% avg, memory <4 GB, drops) — baseline | ✅ CPU · ✅ drops · ❌ memory | Live | CPU avg **29.5%**/max 39.9% (PASS); drop rate **0.0%** (0/163,368) (PASS); total-device memory avg **4.90 GB**/max 6.01 GB → **NOT met** (dev agent co-resident; not excluded) | `evidence/resources/resource-2h-summary.json` | `2bea922` |
| D | Detection evaluation on replayed attack datasets | ☐ | — | **Not tested** — datasets on hold (no download). Synthetic/unit alerts are **not** a substitute. Replay host + IoT-23 selection prepared | `EVALUATION.md §1–3` | `6bd3981` |

## Outstanding (blocks "Sprint 2 complete")
- **#7 visual review** of the three mobile screens (owner).
- **#8 clean 2-hour memory run** without the dev agent, to validly judge the memory target.
- **D detection evaluation** — dataset approval + mirrored-port replay.

## Optional live resume spot-check (#5) — sudo batch
Confirms the ingester resumes from its checkpoint without re-ingesting (live traffic may add new
rows; the check is that existing `alert_id`s are unchanged):
```
cd /home/assas/assas
python3 -c "import urllib.request,json;print('before ids:',sorted(int(a['id']) for a in json.load(urllib.request.urlopen('http://127.0.0.1:8000/alerts'))))" > /tmp/before.txt
sudo systemctl restart assas-alerts.service
sleep 8
python3 -c "import urllib.request,json;print('after ids :',sorted(int(a['id']) for a in json.load(urllib.request.urlopen('http://127.0.0.1:8000/alerts'))))" > /tmp/after.txt
cat /tmp/before.txt /tmp/after.txt   # existing ids must persist (no renumber/duplication)
```

## Mobile visual review (#7) — steps and required screenshots
Do **not** write test data into production logs/DB (see `evidence/ui/README.md`): use demo mode or an
isolated test backend. On a machine with Flutter:
```
cd app/mobile && flutter pub get && flutter run   # or: flutter run -d chrome
```
Pair using the code on the 7-inch display, then capture into `docs/sprint-2/evidence/ui/`:
1. `alerts-tab.png` — list: title, severity, device, last event time, occurrence `N×`, newest first.
2. `alert-details.png` — first/last seen, occurrences, src/dst address:port, rule ID; navigate to
   device details; **no** explanation block / Review·Resolve.
3. `device-alerts.png` — the device's alerts (no "Coming soon").
Confirm each screen's values match `GET /alerts` / `/alerts/{id}` / `/devices/{mac}/alerts`.
