# Sprint 2 — Testing

Instructions and **recorded** results. Status: ☐ Planned · ◐ In progress · ☑ Done. No result is
recorded without evidence (command + output path). Raw logs: `docs/sprint-2/evidence/`.

Rules version used for all tests: ET Open downloaded 2026-11-02 (53,305 signatures loaded, 0
failed — see `README.md`). Record the rules date/version with every test run below.

---

## Part A — Suricata config  ☑ config-tested · ◐ runtime pending
| Test | How | Result | Evidence |
|---|---|---|---|
| Config + rules load | `sudo suricata -T -c /etc/suricata/assas.yaml -v` | ☑ exit 0, IDS mode, 53305 rules, 0 failed | `evidence/partA-suricata-T.log` (to archive) |
| logrotate parses | `sudo logrotate -d /etc/logrotate.d/suricata` | ☑ both patterns OK, no error; eve.json not managed | pasted 2026-11-02 |
| eve.json types = alert+stats only | after enable: `sudo jq -r .event_type /var/log/suricata/eve.json \| sort -u` | ◐ pending Batch 2 | — |
| IDS never drops/modifies | af-packet, no `copy-mode`; `stats.capture.kernel_drops` only | ◐ pending | — |
| **Real rotation** (not just `-d`) | `sudo ASSAS_EVE_MAX_BYTES=... appliance/suricata/rotate-eve.sh --force`: confirm `eve.json` renamed to `eve.json-<ts>`, a fresh `eve.json` with a **new inode** is created by Suricata, new events go to the new file and the rotated file stops growing, and the rotated file is **not** deleted/compressed | ◐ pending (live, this batch) | `evidence/partA-rotation-test.txt` |
| Rotation never deletes | run rotation; verify no eve file removed/compressed; timer `assas-suricata-rotate.timer` active | ◐ pending | same |

## Part B — Alert ingester (`appliance/test_alerts.py`)  ☐ Planned
Offline fixtures only: small PCAP → `suricata -r <pcap> -c <test-conf> -l <tmp>` → eve.json → feed
the ingester. Unit cases:
- severity map 1→Critical, 2→High, 3→Medium, ≥4→Low.
- device linking: src-only, dst-only, both (→source, other IP retained), neither (→NULL).
- dedup: same rule+device within window merges (`occurrence_count`++, `last_event_time` bumped,
  `event_time` kept); NULL-device grouped by rule+src+dst (unknown hosts not merged).
- resume: checkpoint written in same txn; restart → no duplicate rows.
- **multi-rotation restart recovery**: several `eve.json-<ts>` present at startup → every event
  ingested exactly once, in order.
- **reaper preserves unread files**: rotated file not yet fully consumed survives a reaper pass.
- truncation/gap logged explicitly.
Run: `cd appliance && ../.venv/bin/python -m pytest test_alerts.py -v` → record output path.

## Part C — API (`test_api.py`, `test_frontend_contract.py`)  ☐ Planned
- endpoints: `GET /alerts`, `GET /alerts/{id}`, `GET /devices/{mac}/alerts` ordered by
  `last_event_time` desc; auth via paired bearer (reuse `require_auth`); missing table → `[]`.
- **contract test**: exact literal strings `kind="threat"`, `state="new"`,
  `severity∈{critical,high,medium,low}` (casing locked).
Run: `cd appliance && ../.venv/bin/python -m pytest test_api.py test_frontend_contract.py -v`.

## Part D — Mobile (`app/mobile`)  ☐ Planned
- `flutter test` for the alerts list and detail widgets (title, severity, device, last time,
  occurrence count; hidden explanation/anomaly block).
- Screenshots of the finished Alerts tab, Alert detail, and Device-details alerts section saved to
  `evidence/ui/`.

## Summary of successes / failures / issues
Recorded as tests run (what passed, what failed and why, how resolved, remaining limitations).
Currently: Part A config load ☑; all runtime and B–D tests pending.
