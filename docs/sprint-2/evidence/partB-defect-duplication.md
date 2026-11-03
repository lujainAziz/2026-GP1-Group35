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
   (`offset = size`, persisted) → never re-ingests. **This is DETECTED DATA LOSS, not a no-loss
   guarantee:** the events in the gap (between the lost EOF and the stored offset) are dropped and
   logged, never recovered. It trades unrecoverable loss of a small gap for the guarantee of no
   duplication (PBI-14: "log a gap, don't silently continue").
3. ✅ Tests (`appliance/test_alerts.py`): truncation → no duplicate rows + resume-forward;
   `UnicodeDecodeError` line skipped without stalling, offset advances. Appliance suite 504 passed.
4. ☐ **Residual hardening (not yet done):** inode reuse where the replaced file is *larger* than the
   old offset would resume mid-file; add a first-bytes/creation fingerprint to file identity. Low
   likelihood with the rename+SIGHUP rotation (new file gets a new inode), tracked as follow-up.
5. ✅ **Deploy + data cleanup (done 2026-11-03):** fail-closed batch stopped only `assas-alerts`,
   took a validated WAL-aware backup (`assas-precleanup-20261103-181205.db`, sha `fcfc73e6…`, +
   log copies) under `/home/assas/sprint2-backups/`, reset only `alerts` + `alert_ingest_state`
   (651 alerts + 2 checkpoints) in one transaction, and restarted the fixed reader. **Independent
   read-only verification** (`evidence/partB-cleanup-verify.txt`): 331 rows, **`SUM(occurrence_count)
   = 2843` == 2843 retained-log alert events (diff 0)** → no duplication, no loss vs the logs; live
   checkpoint `offset==size` (caught up), rotated file `consumed=1`. No crash loop. Pre-reset check
   found **0 genuine DB-only alerts**, and the backup preserves the prior 651-row state.
6. ☐ **Restart-safety confirmation (sudo, no delete):** one restart comparing rows + SUM(occurrence)
   + checkpoint offset before/after (row count alone can't detect occurrence-only re-ingestion).

## Root cause of `offset > size` (reboot, not accounting)
**Confirmed:** the Pi **rebooted at 2026-11-02 23:12 +03 (20:12 UTC)** — `who -b` = "system boot
2026-11-02 23:12", and all five services share `ExecMainStartTimestamp ≈ 23:12:46 +03` with
`NRestarts=0` (co-start = boot, not a single-service restart); this coincides with the SSH drop.
**Likely (not independently proven):** the ingester had read and committed `offset 7672248` from
eve.json; the unclean reboot lost eve.json's last unsynced ~4536 bytes, so on restart the on-disk
file was `7667712 < 7672248` → `offset > size`. The exact loss mechanism (unsynced tail vs. another
truncation at reboot) is not independently proven, but it is the explanation consistent with the
~4536-byte shortfall and a sound byte/partial-line accounting. Byte/
partial-line **accounting is sound** (`consumed = Σ(len(line)+1)` over complete lines only, so
`consumed ≤ bytes read` and the offset always lands on a line boundary ≤ real EOF; it cannot
over-commit). So the mismatch is a **durability artifact of the reboot**, and the re-read-from-0
response is what turned it into duplication — now fixed.

## Pre-cleanup verification on copies (production untouched)
Ran the FIXED ingester against a backup DB copy (alerts + checkpoints wiped, devices kept) and copies
of the retained eve files:
- no crash on the malformed line (skipped with a warning);
- clean re-ingest = **329 rows, SUM(occurrence_count) 2765 == 2765 alert events in the retained
  logs** (no duplication, no loss relative to the logs);
- live-eve `offset == size` (caught up); re-running `run_once` adds nothing (resume-safe).
- Retained-log event_time span: **2026-11-02T15:40:44 → 2026-11-03T20:40:03**.

**Historical availability:** all alert events Suricata has logged since 2026-11-02T15:40:44 are present
in the two retained eve files (nothing was reaped). The only events **not** available are the few
lost to the reboot tail-truncation; those are gone from the logs and **re-ingest cannot recover
them** (re-ingest reflects only what is in the retained logs — it is not a rebuild of deleted data).

## Status impact
Threat Alert Ingestion **resume-safety / dedup is NOT verified** in live operation (duplication +
current stall). Automated unit tests remain green but have the gap above. This blocks "Sprint 2
complete" alongside the already-open items.
