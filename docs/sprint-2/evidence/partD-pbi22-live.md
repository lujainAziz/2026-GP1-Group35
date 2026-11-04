# PBI-22 — live verification on the appliance (post-deploy)

**Status note (decision D8):** PBI-22 is deferred; its UI is hidden behind
`alertManagement=false`. The results below remain valid evidence for the
backend: the endpoints stay deployed and all stored states are retained.

Deployed `sprint-2 @ 16a4de2` on 2026-11-04 (backup
`/etc/suricata/assas.yaml.bak-20261104T160917Z`; `suricata -T` passed with the
IPv6 HOME_NET; all five services `active`; `/healthz` ok). No token value is
recorded anywhere below; the temporary pairing session was unpaired after the test.

## Results (actual)

**Endpoints live (read-only):** `GET /alerts/open_count` 200 (was 422 pre-deploy),
`GET /alerts?limit&offset` 200, `GET /alerts/{id}` 200,
`PATCH /alerts/{id}` route present (empty body → 422), `GET /devices/{mac}/alerts` 200.

**open_count is the true DB aggregate (not a page length):**
```
api /alerts/open_count = 569
sqlite  SELECT COUNT(*) FROM alerts
        WHERE alert_type='Threat' AND LOWER(state) IN ('new','reviewed') = 569   → MATCH
```
(The figure moved 568→569 between calls as a new alert was ingested — expected live.)

**Pagination returns distinct pages (not just HTTP 200):**
```
/alerts?limit=5&offset=0 → [785,1220,1216,1219,1218]
/alerts?limit=5&offset=5 → [1217,1210,1215,1214,1213]   → disjoint
```

**Authenticated state change over the LAN (192.168.100.236), paired session:**
```
no token : GET /alerts/open_count → 401 ;  PATCH /alerts/{id} → 401
token    : GET /alerts/open_count → 200
real alert id=652 : state BEFORE = new  → PATCH {"state":"reviewed"} → reviewed → re-read reviewed
session unpaired (cleaned up)
```
Note: id=652 is a **real** production alert; it was deliberately moved New→Reviewed
as the test (a legitimate user action). Chosen as the oldest New alert, not "latest".

## State persistence across restarts — PASS (actual, 2026-11-04)
Batch run on the appliance (localhost reads; sudo only for the two restarts):
```
BEFORE: state=reviewed occurrences=218
PASS: Reviewed persisted across API restart        (assas-api.service → active)
PASS: Reviewed persisted across ingester restart   (assas-alerts.service → active)
PENDING: no new occurrence; merge-state preservation not live-tested
```
- Alert id=652 stayed **Reviewed** after restarting both `assas-api` and
  `assas-alerts` → state is persisted in SQLite and survives both the API and the
  ingester restarting.
- **No revert to New on a dedup merge: still PENDING (not failed).**
  `occurrence_count` stayed **218** (the rule did not fire again during the
  window), so there was no live merge to observe. Re-check when this rule fires
  again. Unit-proven meanwhile: the dedup path updates only
  `occurrence_count`/`last_event_time`, never `state`
  (`test_alerts.py` dedup tests).

### Restart / persistence batch (the only sudo needed)
```bash
set -uo pipefail
ID=652 ; API=http://127.0.0.1:8000
state(){ curl -fsS $API/alerts/$ID | python3 -c "import sys,json;print(json.load(sys.stdin)['state'])"; }
occ(){   curl -fsS $API/alerts/$ID | python3 -c "import sys,json;print(json.load(sys.stdin)['occurrence_count'])"; }
OCC0=$(occ); echo "before: state=$(state) occ=$OCC0"

sudo systemctl restart assas-api.service
for i in $(seq 1 30); do curl -fsS $API/healthz >/dev/null 2>&1 && break; sleep 1; done
S=$(state); [ "$S" = reviewed ] && echo "PASS: persisted across API restart ($S)" || echo "FAIL: $S"

sudo systemctl restart assas-alerts.service; sleep 8
S=$(state); [ "$S" = reviewed ] && echo "PASS: persisted across ingester restart ($S)" || echo "FAIL: $S"

OCC1=$(occ)
if [ "$OCC1" -gt "$OCC0" ]; then
  S=$(state); [ "$S" != new ] && echo "PASS: occ $OCC0→$OCC1, state stayed '$S' (no revert)" || echo "FAIL: reverted to New"
else
  echo "PENDING (not live-tested): occurrence_count unchanged ($OCC0→$OCC1)"
fi
```
(The persistence reads use localhost — the local bypass — so no token is needed;
only the two restarts require sudo.)
