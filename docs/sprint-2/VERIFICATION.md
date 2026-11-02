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
| 3 | Dedup: `occurrence_count`↑, keep first & last event time, don't merge unrelated hosts | ✅ | Live + Automated | Live: occ up to **204**, `first<last` (id=1); same-second merges keep equal times; NULL-device rules 2210045 & 2210030 kept as **separate** alerts (distinct src/dst); **`occurrence_count` cross-checked against source events (12/12 NULL-device exact; total 739==739)**. Automated: `test_alerts.py` dedup + NULL-device cases | `evidence/final-live-verify.txt`, `evidence/partB-resume-crosscheck.txt`; `appliance/test_alerts.py` | `6d15b7d` |
| 4 | Link alert to the right device; `device_mac` NULL when no match | ✅ | Live + Automated | Live: **56 linked**, **12 NULL** (link-local / address-less → NULL). Automated: one/both→source/neither rules in `test_alerts.py` | `evidence/final-live-verify.txt`; `appliance/test_alerts.py` | `6d15b7d` |
| 5 | Resume after reader stop; multiple rotations; no loss/dup; keep unread files | ✅ Automated + Live cross-check · ☐ restart smoke test | Automated + Live | **Automated** `test_alerts.py`: resume on fresh DB (no double-ingest), multi-rotation recovery (every event once, in order), reaper preserves unconsumed files, truncation logged. **Live cross-check (read-only):** persisted `alert_ingest_state` matches on-disk eve (rotated `offset==size_at_eof==size`, `consumed=1`; live `offset==size`, 0-byte lag); **739 alert events in eve == SUM(occurrence_count) 739** (no loss/double-count); 12/12 NULL-device alerts' `occurrence_count` == source events in `[first,last]`. **Reader-restart smoke test** (sudo, below) still to run — alert-IDs alone are not full resume proof. | `evidence/partB-resume-crosscheck.txt`; `appliance/test_alerts.py` | `6d15b7d` |
| 6 | Three endpoints: reject unauthenticated; succeed with a paired session | ✅ | Live + Automated | Live from a **non-local (LAN-IP)** address: **401 without a token** and **200 with a valid paired token** on all three (`/alerts`, `/alerts/{id}`, `/devices/{mac}/alerts`); token obtained via the normal pairing flow and removed with `/unpair` afterwards (token never printed/stored). localhost→200 only exercises the local-bypass path. Automated: `AlertContractTests` — 401 without token, 200 + exact contract with a token | `evidence/partC-auth-live.txt`; `appliance/test_frontend_contract.py` | `810c3ab` |
| 7 | Three alert screens + navigation; data matches the API | ☐ | — | **Pending owner visual review.** Steps + required screenshots below and in `evidence/ui/README.md`; not marked passed until confirmed | `evidence/ui/README.md` | `87d819e` |
| 8 | Independent 2-hour resource run **without** the dev agent (CPU/mem/traffic/drops/continuity) | ☐ | — | Not yet run (the agent is the co-resident process). Script ready: `clean_resource_run.sh` (aborts if agent present; guards throughout). **First run retained: memory target NOT met.** | `appliance/tools/clean_resource_run.sh`; `EVALUATION.md §4` | `6bd3981` |
| 9 | Later-sprint features stay hidden; Sprint 1 not broken | ✅ | Automated | Gating test locks `alerts=true` with `alertsHome`/`alertSeverityBadges`/`alertDisplay`/`alertExplanations`/`alertManagement`/`risk`=false; appliance **503 passed**, mobile **63 passed** (Sprint 1 suites green) | `app/mobile/test/alerts_test.dart`; suites | `87d819e` |
| R | Resource targets (CPU ≤75% avg, memory <4 GB, drops) — baseline | ✅ CPU · ✅ drops · ❌ memory | Live | CPU avg **29.5%**/max 39.9% (PASS); drop rate **0.0%** (0/163,368) (PASS); total-device memory avg **4.90 GB**/max 6.01 GB → **NOT met** (dev agent co-resident; not excluded) | `evidence/resources/resource-2h-summary.json` | `2bea922` |
| D | Detection evaluation on replayed attack datasets | ☐ | — | **Not tested** — datasets on hold (no download). Synthetic/unit alerts are **not** a substitute. Replay host + IoT-23 selection prepared | `EVALUATION.md §1–3` | `6bd3981` |

## Outstanding (blocks "Sprint 2 complete")
- **#7 visual review** of the three mobile screens (owner).
- **#8 clean 2-hour memory run** without the dev agent, to validly judge the memory target.
- **D detection evaluation** — dataset approval + mirrored-port replay.

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
Pair using the code on the 7-inch display, then capture into `docs/sprint-2/evidence/ui/`:
1. `alerts-tab.png` — list: title, severity, device, last event time, occurrence `N×`, newest first.
2. `alert-details.png` — first/last seen, occurrences, src/dst address:port, rule ID; navigate to
   device details; **no** explanation block / Review·Resolve.
3. `device-alerts.png` — the device's alerts (no "Coming soon").
Confirm each screen's values match `GET /alerts` / `/alerts/{id}` / `/devices/{mac}/alerts`.
