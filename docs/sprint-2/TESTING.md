# Sprint 2 — Testing

Instructions and **recorded** results. Status: ☐ Planned · ◐ In progress · ☑ Done. No result is
recorded without evidence (command + output path). Raw logs: `docs/sprint-2/evidence/`.

Rules version used for all tests: ET Open downloaded 2026-11-02 (53,305 signatures loaded, 0
failed — see `README.md`). Record the rules date/version with every test run below.

---

## Part A — Suricata config  ☑ Done & tested (2026-11-02)
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

**Note (for Part B):** for ~1–3 s after rotation, before Suricata processes `SIGHUP`, `eve.json`
does not exist (seen in the test: "cannot statx … No such file"). The ingester must tolerate a
transient missing/!-existent `eve.json` (retry, don't error).

## Part B — Alert ingester (`appliance/test_alerts.py`)  ☑ unit-tested (22 passed)
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
- *Live end-to-end* (`assas-alerts.service` reading the real eve.json): recorded after the service
  is enabled (`evidence/partB-*`).

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
