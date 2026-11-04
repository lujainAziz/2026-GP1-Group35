# Alert State-Management Endpoints — Live Verification (2026-11-04)

**Status.** Alert state management (PBI-22) is deferred; its user interface is
currently hidden behind `alertManagement = false`. The endpoints verified below
remain deployed in the API, and all stored alert states are retained. This
document records the live test results as executed on 2026-11-04; it does not
assert that the deferred UI is in scope for this sprint.

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
