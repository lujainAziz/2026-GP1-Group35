# Alert-log reset after rule tuning (approved, executed 2026-11-05 00:55 +03)

Team decision: start a fresh alert log after the Group-A rule tuning. Executed on
the appliance with a fail-stop batch (reader auto-restarted on any failure via an
EXIT trap). **Scope strictly limited to `alerts` rows** — checkpoints, devices,
names, trust, pairing and rule settings untouched.

## Actual results (from the run at `20261104T215550Z` UTC)
```
PASS: reader caught up at the checked file boundaries        (checked AFTER stopping assas-alerts)
BACKUP_VALIDATED: /home/assas/sprint2-backups/assas-before-alert-reset-20261104T215550Z.db
RESET_COMMITTED: deleted 645 alerts                          (single transaction, alerts rows only)
PASS: checkpoints preserved                                  (alert_ingest_state NOT touched)
MANIFEST: /home/assas/sprint2-backups/alert-reset-20261104T215550Z.json
active                                                       (assas-alerts back up)
After restart: alert rows = 0 ; stored occurrences = 0 ; new source events = 0
PASS: checkpoints did not rewind; occurrences match new source events
```
- **Backup:** WAL-aware SQLite backup, integrity-checked and count-matched before
  any deletion; kept outside the repo in `/home/assas/sprint2-backups/` (with a
  JSON manifest), consistent with the earlier Part-B cleanup backups.
- **Deleted: 645 rows** (the pre-tuning log, including the 1 Reviewed / 1
  Resolved rows — preserved inside the backup).
- **No re-ingestion of the past:** read checkpoints (`alert_ingest_state`, 3
  rows) were preserved and did not rewind; immediately after restart the table
  held 0 rows with 0 new source events.

## Post-reset spot-check (00:57 +03, read-only)
`alerts` now contains **1 row**: `SURICATA IPv6 truncated packet`
(sid 2200013, event_time 2026-11-05T00:56:28 — **after** the reset), i.e. only
genuinely new events enter the fresh log. As expected and pre-agreed: the reset
zeroes the log but does **not** address the deferred STREAM/decoder noise — that
group is untouched pending the capture/mirror check, so such events will keep
appearing until that decision is made. `alert_id` numbering continues (no id
reuse). All three services `active`; the app refreshes itself via polling.

## Chain of decisions this evidence completes
1. Rule tuning (12 normal-usage SIDs) applied + verified — `README.md` §Rule-scope tuning,
   `evidence/rule-tuning/`, `appliance/suricata/disable.conf`.
2. Fresh alert log (this file): old 645 rows archived in the backup, table
   restarted clean.
3. Still pending: testmynids detection self-test (mirrored device over plain
   HTTP), capture/mirror check → then the STREAM/decoder decision, deferred IPv6
   attribution plan. (As of 2026-11-05 alert state management was hidden behind
   `alertManagement=false`; it was **released on 2026-11-07** — see
   `partD-pbi22-live.md` per-criterion verification.)
