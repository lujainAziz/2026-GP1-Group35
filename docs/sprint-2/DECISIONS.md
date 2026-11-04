# Sprint 2 — Decision Log

Formal record of scope and operational decisions taken during Sprint 2. The
other documents describe the **current state only**; the history of changes is
recorded here. Dates are appliance-local (+03).

| # | Date | Decision | Effect | Evidence / commit |
|---|------|----------|--------|-------------------|
| D1 | 2026-10-28 | Baseline: tag `sprint-1` at `4786e3c`; all Sprint-2 work on branch `sprint-2`; no direct commits to `main`. | Branching model for the sprint. | `PLAN.md` |
| D2 | 2026-11-02 | Install Suricata 7.0.10 (ET Open via a single `suricata-update`); stock service masked; no scheduled rule updates. | PBI-13 detection layer in place. | `README.md` §Suricata |
| D3 | 2026-11-02 | eve.json output restricted to `alert` + `stats`; no payload/packet capture; rename+SIGHUP rotation (no `copytruncate`). | Sprint-1 no-payload policy preserved; offset-based resume kept safe. | `assas.yaml`, `rotate-eve.sh` |
| D4 | 2026-11-03 | `FeatureRelease.alerts = true`: Alerts tab, alert details, device alerts (PBI-14). Home summaries, severity badges, display count, explanations remain gated. | Mobile alert surfaces live. | `87d819e` |
| D5 | 2026-11-04 | Alert-detail field policy: occurrences, first seen, rule id and ports are hidden in the UI; retained in the database and API. Last seen (= `last_event_time`) is shown. | UI simplification without data loss. | `cdad1da`, `5504d55` |
| D6 | 2026-11-04 | PBI-22 (alert state management) temporarily enabled in Sprint 2: `PATCH /alerts/{id}`, `GET /alerts/open_count`, tabs, Review/Resolve. Deployed and live-verified. | Superseded by D8. | `a9278cc`, `cdad1da`, `evidence/partD-pbi22-live.md` |
| D7 | 2026-11-04 | PBI-09/10 approved: unresolved linked alerts feed device signals — Attention, Home priority, severity colours (severity palette kept separate from trust/monitoring colours). Unlinked alerts attach to no device. | Device list/detail show alert severity; sorting reflects it. | `5504d55` |
| D8 | 2026-11-05 | **PBI-22 deferred (final).** `alertManagement = false`: Review/Resolve, state badges, All/Open/Resolved tabs and the live open-count hidden; the hero keeps the count design with the standard deferred marker. Backend endpoints, tests and stored states retained unchanged. | Current state. Supersedes D6. | `df5f387` |
| D9 | 2026-11-05 | Rule-scope tuning, Group A only: 12 normal-usage informational SIDs disabled via `disable.conf` (applied with `suricata-update --offline`). Severity mapping unchanged; STREAM/decoder rules unchanged pending the capture/mirror check. | Normal-usage alerts no longer generated; verified enabled-set diff limited to the 12 SIDs. | `c9be2c6`, `PROPOSAL-rule-tuning.md`, `evidence/rule-tuning/` |
| D10 | 2026-11-05 | Alert log reset: 645 existing `alerts` rows deleted after a validated WAL-aware backup; `alert_ingest_state` checkpoints preserved (no re-ingestion). Devices, names, trust, pairing and rules untouched. | Fresh alert log post-tuning. | `evidence/alert-log-reset.md` |

## Open items (no decision yet)
- **IPv6→device attribution** — plan pending approval: `PLAN-ipv6-linking.md`.
- **STREAM/decoder rule group** — pending the capture/mirror check
  (`PROPOSAL-rule-tuning.md` §Group C).
- **Detection self-test** (testmynids via a mirrored device over plain HTTP).
- **Dataset detection evaluation** — on hold; no downloads (`EVALUATION.md`).
- **Clean 2-hour resource run** without the co-resident dev agent.
- **Owner visual sign-off** of the mobile screens; merge `sprint-2 → main`.
