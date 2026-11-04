# Sprint 2 — Code-review response, PBI-22 move & UI pass

> **Scope reversal (final):** after everything below was delivered and live-verified,
> the team **deferred PBI-22 again**. `alertManagement` is now OFF: Review/Resolve,
> state badges, All/Open/Resolved tabs and the live open-count are hidden (the hero
> keeps its count design, muted). The PATCH/open_count endpoints, their tests, and
> all stored states remain in place untouched (nothing deleted, nothing reset to
> New) — the feature re-enables by flipping the flag. PBI-14 (list, details with
> Last seen, device alerts + linking) and PBI-09/10 (Attention/priority/severity
> colours) remain live.

Covers: the external code review of `959d2af`, the approved move of **PBI-22
(alert state management) into Sprint 2**, and the whole-app UI changes. Work is
on branch `sprint-2` only — **not merged to `main`, nothing deployed to the
Raspberry Pi, no datasets downloaded.** "Code pushed" ≠ "deployed on the Pi";
"generated screenshots" ≠ "live visual review" (both remain pending the owner).

## How tests were run
- **Appliance (Python):** the project venv has pytest — `.venv/bin/pytest`
  (pytest is **not** installed system-wide). Full suite: **516 passed, 108
  subtests** after the changes. These are *executed*, not just added.
- **Mobile (Flutter):** `flutter test` → **72 passed, 7 skipped** (the skipped
  are the golden/screenshot generators). `flutter analyze` clean (mobile +
  display). Display: one pre-existing test writes a preview PNG outside the repo
  and fails on a sandbox permission error (unrelated to these changes).
- A standalone ingester harness (`scratchpad/verify_alerts.py`) was used while
  iterating, but the committed evidence is the pytest suite above.

## Code-review findings

| # | Pri | Fix | Tests (executed) | Commit |
|---|-----|-----|------------------|--------|
| 1 | P1 | `process_file` opens the file first and takes identity/size from `os.fstat` on the held fd (no `stat(path)`→`open(path)` race) | `test_alerts.py` rotation/resume suite | `98840d0` |
| 2 | P1 | `reap` deletes a consumed rotated file only if, re-checked before unlink, it (a) hasn't grown past our offset, (b) has been quiescent ≥ `ASSAS_ALERT_REAP_GRACE`, and (c) **no process still holds it open** (`/proc/*/fd`). Size-checked-twice alone is insufficient. | `test_reaper_revokes_consumed_when_file_grows`, `test_reaper_does_not_delete_file_still_open_by_a_writer`, `test_reaper_holds_until_quiescent` | `98840d0`,`7cf201e` |
| 3 | P2 | App paginates `getAlerts`; device-details and alert-details fetch independently (`/devices/{mac}/alerts`, `/alerts/{id}`); open count is a DB aggregate (`/alerts/open_count`) | `test_frontend_contract.py` (open-count vs page length 251; offset paging) | `a9278cc`,`cdad1da` |
| 4 | P2 | `link_device` links only when exactly one device owns the IP; ambiguous (DHCP reuse) → `device_mac` NULL + logged | `test_link_device_ambiguous_ip_reuse_stays_unlinked` | `653f0ce` |
| 5 | P2 | Structurally-invalid records (null/list/scalar/non-object `alert`) skipped; offset advances; DB errors not swallowed; non-str timestamp tolerated | `test_structurally_invalid_records_skipped_not_fatal` | `98840d0` |
| 6 | P2 | Alerts have their own error/last-sync state in `AppState`; the hero flags "showing last known alerts" on a failed refresh; 401 still ends the session | mobile suite green; see also #9 | `cdad1da` |
| 7 | P2 | `resource_sampler`: missing Suricata stats written **blank** (not 0,0); drop totals are reset-aware (per-sample deltas, new segment on counter decrease); records PID start/end + `suricata_drop_measurement_valid` | smoke-run verified (missing→null, flags set) | `e68ce32` |
| 8 | P2 | `clean_resource_run.sh`: capture `grep -c` once (it prints 0 **and** exits 1 on no match) so the numeric test no longer mis-fires a false "agent appeared" warning | `bash -n` + both-case check | `e68ce32` |
| 9 | P2 | `HOME_NET` adds the standard local IPv6 ranges `fc00::/7` (ULA) + `fe80::/10` (link-local); the ISP-delegated global prefix is **deferred + documented** (dynamic — not guessed) | config review | `e68ce32` |

Also addressed from the review's "lower-priority notes": chronological
first/last on out-of-order merges (`event_time`=earliest, `last_event_time`=
latest, `test_merge_keeps_chronological_first_last_out_of_order`); shared
display-name source via `sanitizeDeviceName` applied to alert surfaces.

### Still open (surfaced by the review, not yet done)
- **FK on `alerts.device_mac`** (ER note): needs a data-preserving migration +
  device-deletion policy before enabling the constraint — tracked, not done here.
- **Live re-verification on the Pi** and the **dataset detection evaluation**
  remain pending (no deployment / no datasets, per instruction).

## PBI-22 (moved fully into Sprint 2)

- `PATCH /alerts/{id}` (authenticated): New→Reviewed, New→Resolved,
  Reviewed→Resolved; Resolved terminal (409 on illegal, 422 unknown, 404 absent).
  Single-column write; dedup never touches `state` (occurrence updates can't
  revert it). Persisted in SQLite → survives app + backend restart.
- `GET /alerts/open_count`: DB aggregate of New+Reviewed (declared before
  `/alerts/{id}` so `open_count` isn't parsed as an id).
- App: `FeatureRelease.alertManagement = true` (independent of the Home flags);
  Open/Resolved tabs, Review/Resolve actions and the state badge go live; hero
  shows the open count + "open alerts".
- Tests: `test_alert_state_transitions_persist_and_enforce_rules`,
  `test_new_to_resolved_is_allowed`, `test_alert_state_change_requires_auth`.

## UI changes (whole-app pass)

| Item | Change | Evidence |
|------|--------|----------|
| 1 | Alerts hero = big OPEN count + "open alerts" (DB aggregate; shrink-safe) | `evidence/ui/alerts-tab.png` |
| 2 | Font balance: shrink-safe hero, horizontally-scrolling tabs, title FittedBox; full-range overflow test (zoom {1.0,1.2} × scale {0.85,1.0,1.3} × widths {320,400}) | `test/detail_overflow_test.dart` |
| 3 | Occurrences / first & last seen / rule id / ports hidden on every surface (kept in DB + API) | `alerts-tab.png`, `alert-details.png` |
| 4 | Device-name unification on alert cards + details (`sanitizeDeviceName`) | `test/detail_overflow_test.dart` |
| 5 | Removed duplicate "N online" by the devices title (stays in the stats card) | `evidence/ui/device-list.png` |
| 6 | Connection wording Online / Outdated / Offline; sync label "OUTDATED" when stale; device presence unchanged (connection-level only) | `device_signals.dart` |
| 7 | Device filters: All (full width) + four exclusive pairs (Attention/Not attention, Trusted/Untrusted, Online/Offline, Monitored/Not monitored), combinable across pairs | `device_list_screen.dart`, `device_filter_test.dart` |
| 8 | Pairing success = "This phone is now paired with ASSAS." (removed the "only this phone" line; unpair/logout affects only this phone's session) | `pairing_result.dart` |
| 9 | Active identification shows loading/retry instead of a fake OFF toggle on load failure | `settings_screen.dart` |
| 10 | Home "Recent" no longer says "arrives in Sprint 2" / SOON · SPRINT 2; says the Home summary is deferred (PBI-24), section stays off | `dashboard_screen.dart` |

## Proposed backlog wording (no conflict)
- **PBI-14 — Threat Alerts (Sprint 2):** detection → ingestion → read API →
  mobile list/details/device alerts. The **open-alerts counter** on the Alerts
  screen is part of this (New+Reviewed, DB aggregate).
- **PBI-22 — Alert state management (moved to Sprint 2):** New/Reviewed/Resolved
  with the transitions above, authenticated `PATCH`, persistence, and the
  Review/Resolve UI + Open/Resolved tabs. The `alertManagement` flag gates this
  and is **independent** of the deferred Home surfaces.
- **PBI-24 (and Home summary / notifications / risk / anomaly): still deferred.**
  The Home open-alerts count and recent-alerts summary are **not** part of the
  PBI-22 move and remain hidden.
