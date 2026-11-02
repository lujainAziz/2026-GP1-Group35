# Defect found in live verification — Threat Alert Ingestion (PBI-14)

Found 2026-11-02 during live verification (read-only inspection; redacted — counts/rule-ids/offsets
only, no addresses). Two real defects in `appliance/alerts.py`. Automated unit tests pass but did not
cover these paths; the live run exposed them.

## Symptoms (observed)
- Alert rows grew 68 → 651; `SUM(occurrence_count)` = 1496 vs **748** events the ingester had read
  (`= 2×`). 101 `(rule_id, src_ip, dst_ip, event_time)` keys appear in **multiple** alert rows (one
  event at 20:24:03 split across 14 rows). → duplication / re-ingestion.
- `assas-alerts` journal: crash-looping every ~2 s with `UnicodeDecodeError: 'utf-32-be' codec`.

## Defect 1 — truncation/gap handler re-reads from offset 0 (duplication)
Journal at the reader restart: `TRUNCATION/GAP on eve.json (st_ino=909942): stored offset 7672248 >
size 7667712; re-reading from 0`. `process_file()` responds to `offset > size` by setting
`offset = 0` and re-reading the whole file, which **re-ingests every already-processed event**.
Re-read events carry their original (older) timestamps; against existing alerts whose
`last_event_time` is newer than the dedup window, they create **new** duplicate rows, and
within-window ones double `occurrence_count`. The exact `2×` excess (1496 vs 748) matches one full
re-read. PBI-14 requires logging a gap and **not** silently continuing; re-reading from 0 silently
re-ingests. (Why size < offset with the same inode 909942: eve.json was replaced/inode-reused around
the restart; logrotate is **not** the cause — `/etc/logrotate.d/suricata` correctly excludes
eve.json. File identity on `(st_dev, st_ino)` alone is unsafe against inode reuse.)

## Defect 2 — unhandled `UnicodeDecodeError` stalls ingestion
`process_file()` does `json.loads(s)` on a `bytes` line and catches only `json.JSONDecodeError`.
`json.loads(bytes)` performs encoding auto-detection and raises **`UnicodeDecodeError`** (a
`ValueError`, not a `JSONDecodeError`) on certain malformed bytes. That escapes the `except`, the
cycle's `with conn:` transaction rolls back, the offset never advances, and the daemon crash-loops —
**ingestion halted** since 23:22.

## Test gap
`test_alerts.py` truncation test asserts only that a warning is logged — not that **no duplicate
rows** result. No test feeds a line that triggers `UnicodeDecodeError` (only `JSONDecodeError`).

## Fix — code applied & tested (commit `10b78e7`); deploy + cleanup pending
1. ✅ `process_file` now catches `(json.JSONDecodeError, UnicodeDecodeError)` per line → a malformed
   line is skipped, the offset still advances past it, the daemon never stalls.
2. ✅ Truncation/gap (`offset > size`) no longer re-reads from 0: it logs the gap and resumes at EOF
   (`offset = size`, persisted) → never re-ingests. Gap events are not recovered (documented
   trade-off; matches "log a gap, don't silently continue").
3. ✅ Tests (`appliance/test_alerts.py`): truncation → no duplicate rows + resume-forward;
   `UnicodeDecodeError` line skipped without stalling, offset advances. Appliance suite 504 passed.
4. ☐ **Residual hardening (not yet done):** inode reuse where the replaced file is *larger* than the
   old offset would resume mid-file; add a first-bytes/creation fingerprint to file identity. Low
   likelihood with the rename+SIGHUP rotation (new file gets a new inode), tracked as follow-up.
5. ☐ **Deploy + data cleanup (sudo, pending approval):** the service runs `alerts.py` from the repo,
   so a restart loads the fix. The already-duplicated rows remain until cleaned — wipe `alerts` +
   `alert_ingest_state` and let the fixed ingester re-ingest cleanly from the current eve files.

## Status impact
Threat Alert Ingestion **resume-safety / dedup is NOT verified** in live operation (duplication +
current stall). Automated unit tests remain green but have the gap above. This blocks "Sprint 2
complete" alongside the already-open items.
