# Sprint 2 — Implementation Plan

**Scope:** signature-based threat detection and Threat Alerts. The PBI-13 / PBI-14 acceptance items
and their status are tracked in `README.md` → *Requirements tracking*; this document is the
implementation plan behind them.

**Out of scope (reserved for later sprints):** anomaly detection, network risk level, alert
explanations, alert state management (Reviewed/Resolved), notifications, and remote access.

## Git organization

- Baseline tag `sprint-1` marks commit `4786e3c` (2026-10-24, "Merge pull request #14 from
  lujainAziz/fix/monitored-offline"), the end of Sprint 1.
- All Sprint 2 work lands on branch `sprint-2`, branched from `sprint-1`: one commit per item,
  pushed after each item. No commits are made directly to `main`.
- Merge-back: at sprint end a pull request `sprint-2 → main` is opened and merged through GitHub
  (matching the existing merge-PR workflow), after `TESTING.md` and `EVALUATION.md` are complete
  and approved.
- Constraints: additive changes only; existing discovery, capture, pairing, and app screens must
  keep working; no force pushes, no tag or branch overwrites, no discarding of uncommitted work,
  no unrelated changes, and no relocation of the project into per-sprint folders.

**Status legend:** ☐ Planned · ◐ In progress · ☑ Done & tested.

---

## Repository baseline

- **Capture interface: `eth1`** — defined by `appliance/systemd/assas-capture.service`
  (`ip link set eth1 promisc on`) and `ASSAS_CAPTURE_IFACE=eth1` in `assas-discovery.service`.
- SQLite database `assas.db` (default `/home/assas/assas/assas.db`, override via `ASSAS_DB_PATH`),
  WAL mode. Written by the discovery daemon; `api.py` opens it read-only (`mode=ro`) except for its
  own additive tables and columns (`mode=rw`).
- `api.py` gates every endpoint with `require_auth`: localhost and `PUBLIC_PATHS` bypass, otherwise
  a valid paired `Authorization: Bearer <token>` is required, checked against `paired_sessions`.
- The mobile alerts UI is already scaffolded and gated behind `FeatureRelease.alerts` (`false`) and
  `FeatureRelease.alertManagement` (`false`). The `SecurityAlert` model, its API contract, and
  `GET /alerts` already exist in `app/packages/assas_core`.
- Suricata is not installed. No `alerts` table exists.

---

## Suricata Configuration ☑

1. Suricata is installed via `apt` as a deliberate, approved step. The installed version is
   recorded from `suricata --build-info`.
2. Suricata runs in **IDS mode only** using af-packet on `eth1`. Inline/IPS mode, NFQUEUE, and any
   configuration capable of blocking, dropping, or modifying traffic are excluded.
3. Rules are the **ET Open** ruleset, installed with a single `suricata-update` run. Automatic or
   scheduled rule updates are not configured (no cron job, no update timer).
4. **eve.json** output:
   - `alert` is the only event type ingested into the `alerts` table.
   - Suricata `stats` output (eve `stats` event type and/or `stats.log`) is enabled at a modest
     interval to provide the packet-drop rate required by the Evaluation. Stats are used for evaluation
     only and are never written into the `alerts` table.
   - Other high-volume event types (flow, dns, http, tls, etc.) are disabled to limit CPU and disk
     usage.
5. A systemd service `appliance/systemd/assas-suricata.service` is added, consistent with the
   existing services (`Restart=on-failure`, `RestartSec=5`,
   `After=network-online.target assas-capture.service` so the interface is in promiscuous mode
   first). It runs Suricata in af-packet IDS mode on `eth1` with the Assas configuration.

**Log rotation** (prerequisite for Threat Alert Ingestion resume safety):
- Rotation uses a **rename-based scheme followed by the log-reopen signal supported by the
  installed Suricata version** (rename/`create` then `SIGHUP`, or `suricatasc` log-reopen where
  available). The exact mechanism is pinned to the installed version and documented in `README.md`.
- `copytruncate` is not used, as it corrupts offset-based resume.
- Rotated `eve.json.*` files are retained until the ingester has fully read them; rotation never
  deletes a file the ingester has not finished.

---

## Threat Alert Ingestion ☑

A daemon `appliance/alerts.py` and systemd service `appliance/systemd/assas-alerts.service`
(styled like the existing services, `After=assas-suricata.service`) read Suricata `alert` events
from eve.json and write Threat Alerts into SQLite. Unit tests live in `appliance/test_alerts.py`
using small offline PCAPs replayed with `suricata -r`.

**`alerts` table** — the ER-diagram columns plus two additive columns:

| Column | Notes |
|---|---|
| `alert_id` | Primary key |
| `device_mac` | FK → `devices.mac`, nullable |
| `alert_type` | `"Threat"` (constant this sprint) |
| `title` | Suricata signature message |
| `rule_id` | Suricata `signature_id` (sid) |
| `event_time` | First event time, kept stable across deduplication |
| `src_ip`, `dst_ip`, `src_port`, `dst_port` | From the event |
| `severity` | `"Critical"` / `"High"` / `"Medium"` / `"Low"` (see mapping) |
| `state` | `"New"` (constant this sprint) |
| `explanation`, `model_version`, `anomaly_score`, `threshold` | NULL this sprint |
| `occurrence_count` | Additive; starts at 1, incremented on deduplication |
| `last_event_time` | Additive; updated to the latest event time on deduplication |

**Severity from matched rule priority:** `1 → Critical`, `2 → High`, `3 → Medium`,
`≥ 4 → Low`.

**Device linking** — `src_ip` and `dst_ip` are matched against the device inventory
(`devices.last_ipv4`, `last_ipv6_global`, `last_ipv6_ll`, and legacy `ip`):
- one side matches → link that device;
- both sides match → link the source device; the other IP remains stored in the alert;
- neither matches → `device_mac` remains NULL.

**Deduplication** — the same rule firing for the same device again within the window updates the
existing alert instead of creating a new one:
- the window is measured from the last event, is configurable, and defaults to 5 minutes;
- `event_time` stays the first event time; `occurrence_count` is incremented; `last_event_time` is
  advanced;
- for alerts with `device_mac` NULL, the grouping key is rule + `src_ip` + `dst_ip`, so unrelated
  unknown hosts are never merged.

**Resume safety:**
- The eve.json read checkpoint — file identity `(st_dev, st_ino)` and byte `offset` — is persisted
  in an `alert_ingest_state` table within the same transaction as the alert write, so no event is
  stored twice across restarts.
- Rotated `eve.json.*` files are kept until fully read (coordinated with the Suricata Configuration rotation).
- Truncation or a gap (changed inode with unread bytes, offset beyond EOF, etc.) is logged
  explicitly; ingestion does not continue silently past it.

---

## Alert API (authenticated, read-only) ☑

New endpoints reuse the existing `require_auth` dependency:

- `GET /alerts` — all alerts, newest first by `last_event_time`.
- `GET /alerts/{alert_id}` — a single alert.
- `GET /devices/{mac}/alerts` — a device's alerts, newest first by `last_event_time`.

The response matches the existing `SecurityAlert` contract exactly, including string casing:
- `kind`: `"threat"` (lowercase), derived from `alert_type = "Threat"`;
- `severity`: lowercase `"critical"` / `"high"` / `"medium"` / `"low"`;
- `state`: lowercase `"new"`;
- plus `id`, `title`, `device_mac`, `device_name`, `time` (set to `last_event_time`),
  `source_ip`, `destination_ip`, `src_port`, `dst_port`, `rule_id`, `occurrence_count`, and the
  first/last event times;
- `explanation` and the anomaly fields are emitted as `null`.

A contract test asserts the exact string values (`"threat"`, `"new"`, and the four severity
strings) so any casing drift fails the test suite (extending `test_api.py` /
`test_frontend_contract.py`).

---

## Mobile Alert Screens (`app/mobile`) ☑ (visual review outstanding)

A complete audit of every widget, screen, and code path gated by `Released.alerts` /
`FeatureRelease.alerts` is produced and reviewed before the alerts flag is enabled. Code paths that
belong to later sprints (for example the Home open-alerts count, recent-alerts summary,
device-signal badges, and network risk) stay hidden or move behind their own later-sprint flag.
The flag is enabled only after that audit is approved.

With the existing design and styling preserved, the released feature-flag state is:
- `FeatureRelease.alerts` is `true`; `FeatureRelease.alertManagement` is `true` — **PBI-22 is
  RELEASED in Sprint 2** (team decision to restore it): the single newest-first alerts list with
  All/Open/Resolved tabs, Review/Resolve actions (New→Reviewed, New→Resolved, Reviewed→Resolved;
  Resolved terminal), New/Reviewed/Resolved badges, and the live unresolved counter
  (DB aggregate of New+Reviewed) in the hero, backed by `PATCH /alerts/{id}` and
  `GET /alerts/open_count`; state is persisted in SQLite and a matching event after an alert is
  Resolved starts a new independent alert (new id, state New). `alertSeverityBadges` is `true`
  (PBI-09/10): unresolved linked alerts feed the device signals (Attention, Home priority,
  severity palette). The Home open-alerts count/summary (PBI-24) and the 7-inch display count
  remain hidden (their own later flags).
- `SecurityAlert` and its `fromApi` factory are extended additively with `occurrence_count`, first
  and last event times, `src_port` / `dst_port`, and `rule_id` (kept in the DB and API).
- **Alerts tab:** hero = true open count (DB aggregate of New+Reviewed) + "open alerts"; a list of
  Threat Alerts showing title, severity, affected device, last event time and state, newest first.
  Occurrence count is hidden in the UI per the field-hiding decision.
- **Alert details:** title, time, device (shown once, with navigation), state badge, Review/Resolve,
  and Signal details = alert type, severity, last seen (= last event time), source/destination IP.
  Occurrences, first seen, rule ID and ports are hidden in the UI (kept in DB/API). The explanation
  and anomaly block is hidden behind a later-sprint flag, as those fields are NULL this sprint.
- **Device details:** the device's alerts replace the "Coming soon" section once the alerts flag is
  enabled.
- Flutter widget tests cover the list and details screens.

---

## Evaluation ◐

1. **Detection:** labeled attack traffic from CICIoT2023 and IoT-23 is replayed into the monitored
   interface. Dataset files are retrieved only after approval.
   - Detection is measured from the raw Suricata `alert` events, before deduplication.
   - An attack counts as detected only when a Suricata event is matched to that attack's traffic by
     time window and addresses; an alert merely appearing during the replay is not sufficient.
   - Alerts raised on benign traffic are recorded.
   - With ET Open, not every attack is expected to have a matching signature; detected and
     undetected attacks are recorded as observed, with no assumption of full coverage.
2. **Replay path:** traffic is replayed with `tcpreplay` from a second host into a mirrored (SPAN)
   switch port so it reaches `eth1`. The exact setup is recorded in `EVALUATION.md`.
3. **Resources:** a continuous 2-hour run with Suricata and all existing services records total
   device CPU on a 0–100% scale (target: average ≤ 75%), memory (target: < 4 GB of 8 GB), the
   traffic rate during the test, and Suricata's packet-drop rate (from the stats enabled in
   the Suricata Configuration).
4. Unit tests use small offline PCAPs with `suricata -r` only.

---

## Documentation (`docs/sprint-2/`)

- `README.md` — scope and differences from Sprint 1.
- `PLAN.md` — this implementation plan.
- `TESTING.md` — test instructions and recorded results.
- `EVALUATION.md` — replay setup, detection results, and resource measurements.

Planned versus completed and tested work is tracked with the status legend above and updated as
each item lands.
