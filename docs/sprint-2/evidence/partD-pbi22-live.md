# Alert State-Management Endpoints — Live Verification (2026-11-04)

**Status.** Alert state management is **RELEASED in Sprint 2** (team
decision, 2026-11-07): `alertManagement = true`, surfacing the All/Open/Resolved
tabs, the New/Reviewed/Resolved badges, the Review/Resolve actions and the live
unresolved (New+Reviewed) counter. The endpoint results below were executed on
2026-11-04 and remain valid. The per-criterion acceptance verification for the
seven acceptance criteria is in the section at the end of this document.

**Test context.** Deployed `sprint-2 @ 16a4de2` (configuration backup
`/etc/suricata/assas.yaml.bak-20261104T160917Z`; `suricata -T` passed with the
IPv6 HOME_NET; all five services `active`; `/healthz` ok). No token value is
recorded in this document; the temporary pairing session created for the test
was removed with `/unpair` on completion. The test modified one production
alert (id 652, the oldest alert in state New at the time) from New to Reviewed
— a legitimate user action chosen deterministically. The alert log was
subsequently reset on 2026-11-05 (see `alert-log-reset.md`), so this record id
no longer exists in the live table; the results remain valid for the date
tested, and the figures below predate the rule tuning and the reset.

## Results

**Endpoint availability (read-only checks):** `GET /alerts/open_count` → 200
(422 before deployment, confirming the route was newly served);
`GET /alerts?limit&offset` → 200; `GET /alerts/{id}` → 200; `PATCH /alerts/{id}`
route present (empty body → 422); `GET /devices/{mac}/alerts` → 200.

**Open-count equals the database aggregate (not a page length):**
```
api /alerts/open_count = 569
sqlite  SELECT COUNT(*) FROM alerts
        WHERE alert_type='Threat' AND LOWER(state) IN ('new','reviewed') = 569   → MATCH
```
The figure advanced 568 → 569 between consecutive calls as a new alert was
ingested, consistent with a live system.

**Pagination returns distinct pages:**
```
/alerts?limit=5&offset=0 → [785,1220,1216,1219,1218]
/alerts?limit=5&offset=5 → [1217,1210,1215,1214,1213]   → disjoint
```

**Authentication and state change over the LAN (192.168.100.236), paired
session:**
```
no token : GET /alerts/open_count → 401 ;  PATCH /alerts/{id} → 401
token    : GET /alerts/open_count → 200
alert id=652 : state before = new → PATCH {"state":"reviewed"} → reviewed → re-read: reviewed
session unpaired on completion
```

## State persistence across restarts — PASS (2026-11-04)

```
BEFORE: state=reviewed occurrences=218
PASS: Reviewed persisted across API restart        (assas-api.service → active)
PASS: Reviewed persisted across ingester restart   (assas-alerts.service → active)
PENDING: no new occurrence; merge-state preservation not live-tested
```

- Alert id 652 remained **Reviewed** after restarting both `assas-api` and
  `assas-alerts`: the state is persisted in SQLite and survives restarts of
  both services.
- **State preservation across a deduplication merge: PENDING (not failed).**
  `occurrence_count` remained 218 during the observation window (the rule did
  not fire again), so no live merge occurred to observe. The property is
  unit-tested: the deduplication path updates only `occurrence_count` and
  `last_event_time`, never `state` (`appliance/test_alerts.py`); a live
  confirmation requires a repeat firing within the window and has not been
  performed.

## Reproduction procedure (restart-persistence check)

Reads use localhost (local-bypass authentication); only the two service
restarts require privileges.

```bash
set -uo pipefail
ID=<alert id> ; API=http://127.0.0.1:8000
state(){ curl -fsS $API/alerts/$ID | python3 -c "import sys,json;print(json.load(sys.stdin)['state'])"; }
occ(){   curl -fsS $API/alerts/$ID | python3 -c "import sys,json;print(json.load(sys.stdin)['occurrence_count'])"; }
OCC0=$(occ); echo "before: state=$(state) occ=$OCC0"
sudo systemctl restart assas-api.service
for i in $(seq 1 30); do curl -fsS $API/healthz >/dev/null 2>&1 && break; sleep 1; done
S=$(state); [ "$S" = reviewed ] && echo "PASS: persisted across API restart" || echo "FAIL: $S"
sudo systemctl restart assas-alerts.service; sleep 8
S=$(state); [ "$S" = reviewed ] && echo "PASS: persisted across ingester restart" || echo "FAIL: $S"
OCC1=$(occ)
if [ "$OCC1" -gt "$OCC0" ]; then
  S=$(state); [ "$S" != new ] && echo "PASS: no revert on merge ($OCC0→$OCC1)" || echo "FAIL: reverted to New"
else
  echo "PENDING (not live-tested): occurrence_count unchanged ($OCC0→$OCC1)"
fi
```

## Alert state management — per-criterion acceptance verification (2026-11-07)

Verification method per criterion: **A** = automated test, **C** = code/SQL path.
Suites green at verification: appliance **555 passed**, mobile **80 passed**,
`flutter analyze` clean (mobile + design).

| # | Criterion | Verdict | How verified |
|---|---|---|---|
| 1 | Single security-alert list, newest → oldest | ✅ | `GET /alerts` orders by `last_event_time DESC` (api.py); the app renders one list with All/Open/Resolved tabs filtering that same list (`alert_list_screen.dart`). A/C |
| 2 | States New/Reviewed/Resolved; every new alert starts New | ✅ | Ingester `INSERT … state 'New'` hardcoded (alerts.py `upsert_alert`); `_STATE_DB` canonical casing; model `stateFromApi(null)→New`. A (`test_alerts.py`, `alerts_test.dart`) |
| 3 | Allowed transitions New→Reviewed, New→Resolved, Reviewed→Resolved | ✅ | `_ALLOWED_SOURCES` = {reviewed:(new), resolved:(new,reviewed)} enforced as one atomic guarded `UPDATE … WHERE LOWER(state) IN (allowed)`; illegal moves → 409. Backward/skip moves rejected. A/C (api.py; `test_api`/`test_frontend_contract`) |
| 4 | State persists across app or backend restart | ✅ | State stored in the SQLite `alerts.state` column (not in memory); the PATCH commits before returning; app reads it back via `GET /alerts`. Restart-safety cross-check in VERIFICATION #5 shows rows/states unchanged across restart. A/C |
| 5 | Unresolved counter = New + Reviewed only | ✅ | `GET /alerts/open_count` = `WHERE LOWER(state) IN ('new','reviewed')`; app hero reads `openAlertCount`; `SecurityAlert.isUnresolved = state != resolved`; signals exclude resolved. A (`alerts_test.dart` worstByMac excludes resolved) |
| 6 | Anomaly alerts use the same list and actions when anomaly detection is available | ✅ (structural) | The list/tabs/actions key on `alert_type` + `state`, not on a threat-only path; the same `SecurityAlert` model, endpoints and state machine serve any `alert_type`. Anomaly **detection** itself is a later sprint (`baseline=false`), so there are no anomaly rows to display yet — the pathway is ready, nothing special-cased to Threat. C |
| 7 | Resolved is terminal; a matching event after close creates an independent alert (new id, state New) | ✅ | `upsert_alert` takes the SINGLE most-recent matching alert (any state) and merges only if it is open (New/Reviewed) and within the window; if the newest match is Resolved the event inserts a fresh row (new id, state New, occurrence 1) and the resolved alert is untouched. **Edge case covered:** when the newest match is Resolved but an OLDER match is still open and inside the window, the event does NOT re-attach to the older open one — the newest match's state decides. Two tests: `test_resolved_alert_is_terminal_new_event_makes_independent_alert` and `test_resolved_newest_match_wins_over_older_open_in_window`. A (`test_alerts.py`) |

**Still pending (not automatable here):** the owner's on-device visual sign-off
of the released screens (tab switching, Review/Resolve round-trip, counter
updates) — tracked in VERIFICATION #7.
