# Alert-log reset after rule-scope tuning round 3 (executed 2026-11-10)

Team decision: start a clean alert log after round 3, so the list shows only
events after all three tuning rounds (Group A, round 2, round 3). Same
procedure as the 2026-11-05 reset (`alert-log-reset.md`). **Scope strictly
limited to `alerts` rows.**

## Procedure and results
1. `assas-alerts` stopped.
2. **Backup:** WAL-aware SQLite backup (sqlite3 backup API), stored outside the
   repository:
   `/home/assas/sprint2-backups/assas-before-alert-reset-20261110T182626Z.db`.
   `integrity_check` = ok; **352** alert rows in both the database and the
   backup.
3. **Deleted 352 rows** from `alerts` in a single transaction.
4. `alert_ingest_state` (read checkpoints) unchanged; devices unchanged.
5. `assas-alerts` restarted; all four services active. The alert count stayed
   **0** after the restart (no re-ingestion of past events).

## Live self-test after the reset
A phone on Assas-Test requested a test file from the appliance. Exactly **one**
alert appeared: 2100498 (GPL ATTACK_RESPONSE id check returned root), severity
High, linked to the correct phone. No Python SimpleHTTP alert appeared, as
expected, because 2034636 was disabled in round 3.

## Related
- Rule changes: `appliance/suricata/disable.conf` (Round 3 section) and
  `README.md` §Rule-scope tuning, round 3.
- Previous reset: `alert-log-reset.md` (2026-11-05).
