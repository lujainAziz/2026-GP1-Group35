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

## Fix plan (proposed — not yet applied)
1. Decode tolerantly and catch per line: `json.loads(raw.decode("utf-8", "replace"))` and/or
   `except (json.JSONDecodeError, UnicodeDecodeError)` → skip the bad line (offset still advances),
   never crash the cycle.
2. Truncation/gap must **not** re-read from 0: on `offset > size` (same inode), log a gap and set
   `offset = size` (resume forward) — never re-ingest. Harden file identity against inode reuse
   (e.g., also track first-bytes/creation signal), so a replaced file is treated as new (offset 0)
   only when it truly is new.
3. Unit tests: (a) a `UnicodeDecodeError`-triggering line is skipped without crashing or stalling and
   the offset advances; (b) after a simulated truncation, **no duplicate rows** and no
   occurrence_count inflation.
4. Data cleanup: de-duplicate the affected rows in `assas.db` and reset the checkpoint; restart
   `assas-alerts`. (Requires sudo; proposed separately.)

## Status impact
Threat Alert Ingestion **resume-safety / dedup is NOT verified** in live operation (duplication +
current stall). Automated unit tests remain green but have the gap above. This blocks "Sprint 2
complete" alongside the already-open items.
