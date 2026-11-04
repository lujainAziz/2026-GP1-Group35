# Sprint 2 — Scope and Changes from Sprint 1

Sprint 2 adds **signature-based threat detection** and **Threat Alerts** to the Assas appliance
(see the requirements-tracking table for the PBI-13 / PBI-14 items). Sprint 1 delivered passive
discovery, capture, classification, pairing, the read-only inventory API, and the mobile/display
apps; Sprint 2 is **additive** and must not change that behaviour.

Status legend: ☐ Planned · ◐ In progress · ☑ Done & tested. Every "Done" row links to the evidence
(commit, log path, or test). Results without evidence are not recorded.

Repo: `github.com/lujainAziz/Assas`, branch `sprint-2` (branched from tag `sprint-1` = `4786e3c`).
Commit links use `https://github.com/lujainAziz/Assas/commit/<hash>`.

**Branch sync with `main`.** `sprint-2` was cut at PR #14 (`4786e3c`). `main` then advanced to
PR #18 (`c8e42e5`) with UI/design updates not initially present in `sprint-2`; an earlier status
report stating otherwise was incorrect and is corrected here. On 2026-11-03 `origin/main`
(through `c8e42e5`) was merged into `sprint-2` (conflict-free) to include: #15 "Computer" device
label, #16 OUI registry docs, **#17 live signal line → "Soon · Sprint 5"**, **#18 "Now watching"
protocol tags → "Soon · Sprint 5"**. #17/#18 restore the approved design's gating of live-activity UI
that `sprint-2` had been showing. All Sprint 2 functionality is preserved.

## What is new vs Sprint 1
| Area | Sprint 1 | Sprint 2 addition |
|---|---|---|
| Detection | none | Suricata 7.0.10 IDS (ET Open signatures) on the capture interface |
| Services | `assas-capture`, `assas-discovery`, `assas-api` | + `assas-suricata` (☑ active), `assas-suricata-rotate.timer` (☑ active), + `assas-alerts` (☑ active) |
| Database | `devices`, `flows`, … | + `alerts`, `alert_ingest_state` tables (☑) |
| API | inventory endpoints | + read-only alert endpoints (☑) |
| Mobile | alerts UI gated off | alerts tab/detail/device-alerts enabled (☑ code+tests; visual review outstanding) |

## Requirements tracking
Single source for the PBI-13 / PBI-14 acceptance items; sections below carry the detail. Final
per-requirement pass/fail/not-tested verdicts (automated vs live) are in `VERIFICATION.md`.

| PBI | Requirement | Section | Status | Evidence |
|---|---|---|---|---|
| 13 | Suricata installed; version reported | Suricata Configuration | ☑ | `partA-suricata-T.log`, README |
| 13 | IDS mode on the capture interface (`eth1`); never blocks/modifies | Suricata Configuration | ☑ | `assas.yaml`, `partA-service-state.txt` |
| 13 | ET Open rules via `suricata-update` | Suricata Configuration | ☑ | `partA-et-open-source.txt`, `partA-suricata-T.log` |
| 13 | `eve.json` with alert events (+ stats for drop rate) | Suricata Configuration | ☑ | `partA-eve-event-types.txt` |
| 13 | systemd service consistent with existing units | Suricata Configuration | ☑ | `assas-suricata.service` |
| 13 | Resource targets: total CPU ≤75% avg, memory <4 GB | Evaluation | ◐ CPU 29.5% avg + 0% drops PASS; memory not validly judged (dev agent co-resident) | `resources/resource-2h-summary.json` |
| 14 | Ingest alerts from `eve.json` into `alerts` table | Threat Alert Ingestion | ☑ | `partBC-live.txt`, `test_alerts.py` |
| 14 | Severity from rule priority (1→Critical … ≥4→Low) | Threat Alert Ingestion | ☑ | `test_alerts.py` |
| 14 | Device linking (one/both→source/neither) | Threat Alert Ingestion | ☑ | `test_alerts.py` |
| 14 | Dedup window; `occurrence_count`/`last_event_time` | Threat Alert Ingestion | ☑ | `partBC-live.txt` (24→1), `test_alerts.py` |
| 14 | Resume safety (checkpoint, rotation, gap logging) | Threat Alert Ingestion | ☑ | `test_alerts.py` |
| 14 | Authenticated read-only alert endpoints | Alert API | ☑ | `test_api.py`, `test_frontend_contract.py`, `partBC-live.txt` |
| 14 | Mobile: alerts tab, details, device alerts | Mobile Alert Screens | ☑ code+tests; visual review outstanding | `test/alerts_test.dart`, `evidence/ui/` |
| 13+14 | Detection evaluation on replayed attack traffic | Evaluation | ☐ dataset download outstanding | `EVALUATION.md` |

---

## Environment (appliance)
Recorded 2026-11-02 from the live Pi.

| Item | Value | Evidence |
|---|---|---|
| Device | Raspberry Pi (aarch64) | `uname` in session |
| OS | Debian GNU/Linux 13 (trixie), 13.7 | apt / `/etc/os-release` |
| Kernel | `6.18.34+rpt-rpi-2712` | login banner |
| Python | system `/usr/bin/python3` (daemons), venv `/home/assas/assas/.venv` (API) | existing services |
| Capture interface | `eth1` (SPAN/mirror; promisc set by `assas-capture.service`) | `assas-capture.service`, `ASSAS_CAPTURE_IFACE=eth1` |

---

## Suricata Configuration  ☑ Done & tested (2026-11-02)

### Packages installed (2026-11-02, `apt-get install suricata`)
| Package | Version | Note |
|---|---|---|
| `suricata` | `1:7.0.10-1+deb13u4` | Debian trixie/main; `suricata -V` → "7.0.10 RELEASE" |
| `suricata-update` | `1.3.4-1+deb13u1` | rule manager |
| `libevent-2.1-7t64`, `libevent-core-2.1-7t64` | `2.1.12` → `2.1.13-stable-1~deb13u1` | mandatory security upgrade (hard dep); **2 upgraded, 30 new, 0 removed** |
| DPDK `librte-*`, `libxdp1` | `24.11.8-0+deb13u1`, `1.5.4-1` | hard deps of Debian suricata; unused at runtime (af-packet, not DPDK) |

Build features (`suricata --build-info`): `AF_PACKET support: yes`, `NFQueue support: yes`
(unused), `PF_RING: no`.

### Stock package footprint neutralised
- The package auto-enabled the stock `suricata.service` (created the multi-user wants symlink). It
  was **stopped + disabled + masked** so only the Assas unit runs: `systemctl is-enabled suricata`
  → `masked`, `is-active` → `inactive`.
- **No scheduled rule-update job** was installed: `systemctl list-timers '*suricata*'` → 0 timers;
  no `/etc/cron.*` entry; no `/etc/apt/apt.conf.d` hook. Automatic rule updates are intentionally
  **not** configured (team decision pending).

### Final configuration (repo is the source of truth; deployed to `/etc`)
| Repo file | Deployed to | Purpose |
|---|---|---|
| `appliance/suricata/assas.yaml` | `/etc/suricata/assas.yaml` (0640 root) | Assas IDS config |
| `appliance/suricata/gen_assas_yaml.py` | — | assertion-guarded generator from stock yaml |
| `appliance/suricata/assas-suricata.logrotate` | `/etc/logrotate.d/suricata` (0644 root) | rotation for stats.log/suricata.log only (replaces stock) |
| `appliance/suricata/rotate-eve.sh` | run in place | eve.json rotation: rename + SIGHUP reopen, never deletes |
| `appliance/systemd/assas-suricata.service` | `/etc/systemd/system/assas-suricata.service` | IDS unit |
| `appliance/systemd/assas-suricata-rotate.{service,timer}` | `/etc/systemd/system/` | periodic eve.json rotation check (5 min) |

`assas.yaml` is the Debian stock `/etc/suricata/suricata.yaml` with only these edits (full diff is
reproducible via the generator):
1. `af-packet` interface `eth0` → **`eth1`**. IDS only — no `copy-mode`/inline, never drops or
   modifies traffic.
2. `eve-log` event types reduced to **`alert` + `stats`** only. On `alert`: `tagged-packets: no`,
   `payload: no`, `payload-printable: no`, `packet: no`, `http-body: no`, `metadata: no` → no
   packet events, no stored payloads (keeps Sprint 1's no-payload rule).
3. `outputs.fast` (fast.log) disabled.
4. Global `stats.interval` `8` → **`30`** s (modest; feeds the Evaluation drop-rate).
5. Rules path unchanged: `default-rule-path: /var/lib/suricata/rules`, `rule-files: [suricata.rules]`.

**Log rotation.** The stock `/etc/logrotate.d/suricata` used `copytruncate` (forbidden — corrupts
the ingester's offset resume) and globbed `*.json`. It is replaced as follows:
- `stats.log` + `suricata.log`: ordinary logrotate (rename + `SIGHUP` reopen; `man suricata`:
  *"SIGHUP … close and re-open all log files"*). These are not consumed by the ingester, so
  count-based deletion is safe.
- **eve.json: rotated by `rotate-eve.sh`, driven by `assas-suricata-rotate.timer` (every 5 min).**
  When eve.json reaches the size threshold (`ASSAS_EVE_MAX_BYTES`, default 50 MiB) the script
  renames it to `eve.json-<UTC-ts>` (collision-proof, suffixed `.N` if needed) and sends `SIGHUP`
  to `assas-suricata.service` so Suricata reopens a fresh eve.json. A shared `flock`
  (`/run/assas-suricata-rotate.lock`) serialises the timer and any manual/forced run so two
  rotations can never overlap. The script **only renames — it never compresses or deletes** — so it
  is safe to run even while the ingester is stopped (rotated files accumulate until consumed). Deletion
  of a rotated eve file is owned exclusively by the Threat Alert Ingestion reaper, which
  acts only after a file is fully consumed. This is the complete replacement for logrotate on
  eve.json; logrotate never touches eve.json, so it can never delete an unread file.

### ET Open ruleset
| Item | Value | Evidence |
|---|---|---|
| Source | Emerging Threats Open (`et/open`) — suricata-update's built-in default (no source was explicitly enabled, so `suricata-update` used its default ET Open ruleset; `list-enabled-sources` → *"No enabled sources"*) | `partA-et-open-source.txt` |
| Source index | `https://www.openinfosecfoundation.org/rules/index.yaml` (accessed 2026-11-02) | suricata-update docs |
| Ruleset URL | canonical ET Open for this version: `https://rules.emergingthreats.net/open/suricata-7.0.10/emerging.rules.tar.gz` (accessed 2026-11-02; for a byte-exact capture run `sudo suricata-update list-sources`) | reference |
| Downloaded | 2026-11-02 15:09 | mtime of rules file |
| Output file | `/var/lib/suricata/rules/suricata.rules` — 46,029,036 bytes, 69,273 lines | `ls -l`, `wc -l` |
| Signatures loaded | **53,305 rules loaded, 0 failed** (53,310 signatures processed) | `partA-suricata-T.log` |
| Scheduled updates | none (one-shot only) | see "neutralised" above |

### Verification evidence (all under `docs/sprint-2/evidence/`)
- **Config + rules load** (exit 0): `suricata -T` → *"Setting engine mode to IDS mode by default"*,
  eve.json + stats.log initialised, *"53305 rules successfully loaded, 0 rules failed"*,
  *"Configuration provided was successfully loaded."* → `partA-suricata-T.log`.
- **Service**: `assas-suricata.service` `ActiveState=active`, `SubState=running`,
  `ExecMainStatus=0`, enabled; `assas-suricata-rotate.timer` enabled + active →
  `partA-service-state.txt`.
- **eve event types = `alert` + `stats` only** (no packet/flow/dns/…): `partA-eve-event-types.txt`
  (computed with `python3`; raw eve records are never committed — they contain addresses). During
  the check, 4 `alert` events had already fired on live traffic, confirming end-to-end detection.
- **logrotate excludes eve.json** (manages only stats.log/suricata.log): `partA-logrotate-patterns.txt`.
- **Real rotation** (forced, not just `-d`): `eve.json` inode `909884` → renamed
  `eve.json-20261102-124031` (554696 B, preserved uncompressed); Suricata reopened a fresh
  `eve.json` with **new inode `909942`** which **grew to 16089 B** after the next stats interval
  while the service stayed active → logging genuinely resumed → `partA-rotation-test.txt`.
- **Sensitive-data scan**: all evidence files scanned for IPv4/MAC/IPv6 → clean (no addresses
  committed).

> Operational note for Threat Alert Ingestion: for ~1–3 s after a rotation (before Suricata handles `SIGHUP`)
> `eve.json` briefly does not exist. The ingester must tolerate this (retry, not error).

### Official sources (accessed 2026-11-02)
- Suricata 7.0 user guide: `https://docs.suricata.io/en/suricata-7.0/`
- af-packet / running modes: `https://docs.suricata.io/en/suricata-7.0/configuration/suricata-yaml.html`
- suricata-update: `https://docs.suricata.io/en/latest/rule-management/suricata-update.html`
- Emerging Threats Open rules: `https://rules.emergingthreats.net/`
- Debian suricata package: `https://packages.debian.org/trixie/suricata`

### Commits (Suricata Configuration)
- `56cb66f` — docs(sprint-2): implementation plan.
- `921f950` — feat(suricata): Assas IDS config, service, log rotation.
- `ff0bb9f` — fix(suricata): drop eve.json from logrotate so unread files are never deleted.

---

## Threat Alert Ingestion  ☑ Done, unit-tested & live-verified

New daemon `appliance/alerts.py` + `appliance/systemd/assas-alerts.service` (runs as `root`, like
`assas-discovery`). It reads Suricata `alert` events from `eve.json` (+ rotated `eve.json-<ts>`) and
writes Threat Alerts into SQLite. Tests: `appliance/test_alerts.py` (22 passed).

**New tables (created by the ingester; API reads them read-only):**
- `alerts` — ER columns (`alert_id, device_mac, alert_type, title, rule_id, event_time, src_ip,
  dst_ip, src_port, dst_port, severity, state, explanation, model_version, anomaly_score,
  threshold`) **plus** additive `occurrence_count`, `last_event_time`. This sprint: `alert_type`
  constant `"Threat"`, `state` constant `"New"`; `explanation`/`model_version`/`anomaly_score`/
  `threshold` stay NULL. Indexes on `last_event_time`, `(device_mac,last_event_time)`,
  `(rule_id,device_mac)`.
- `alert_ingest_state` — `(st_dev, st_ino)` PK + `offset, size_at_eof, consumed, path` — the read
  checkpoint, written in the **same transaction** as the alert upserts.

**Behaviour:** severity from rule priority (1→Critical … ≥4→Low); device linking
(one→that device, both→source keeping the other IP, neither→NULL); dedup within a window (default
300 s, `ASSAS_ALERT_DEDUP_WINDOW`, measured from `last_event_time`; NULL-device key = rule+src+dst);
resume-safe checkpointing; follows the Suricata Configuration rotation (drains `eve.json-<ts>` by inode); reaper
deletes only fully-consumed rotated files (keeps `ASSAS_ALERT_KEEP_ROTATED`, default 3); logs
truncation/gaps. Configurable via env (`ASSAS_DB_PATH`, `ASSAS_EVE_PATH`,
`ASSAS_ALERT_DEDUP_WINDOW`, `ASSAS_ALERT_POLL_SECONDS`, `ASSAS_ALERT_KEEP_ROTATED`).

**Live verification** (2026-11-02, `evidence/partB-service-state.txt`, `evidence/partBC-live.txt`):
`assas-alerts.service` active; a real Suricata alert was ingested and served via the API, with
**dedup confirmed live** (24 firings → one alert, `occurrence_count=24`) and the address-less
decoder alert correctly left unlinked (`device_mac` NULL). Only aggregates/signature names are
committed — no raw addresses.

### Commits (Threat Alert Ingestion)
- `6d15b7d` feat(alerts): Suricata eve.json ingestion into alerts table.

## Alert API  ☑ Done & tested

Additive endpoints in `appliance/api.py`, gated by the existing `require_auth` (paired bearer token;
localhost bypass). A missing `alerts` table reads as empty.
- `GET /alerts` — all Threat Alerts, newest first by `last_event_time` (`limit` 1–1000, default 200).
- `GET /alerts/{alert_id}` — one alert (404 if unknown).
- `GET /devices/{mac}/alerts` — a device's alerts, newest first.

Response is the mobile `SecurityAlert` contract with **locked casing**: `kind="threat"`,
`state="new"`, `severity ∈ {critical,high,medium,low}`; plus `id`, `title`, `device_mac`,
`device_name` (user_name→hostname→model→"Unknown device"), `time` (= `last_event_time`),
`first_event_time`, `last_event_time`, `occurrence_count`, `rule_id`, `source_ip`/`destination_ip`,
`src_port`/`dst_port`; `explanation` and the anomaly fields are `null`. A contract test asserts the
exact strings so casing can't drift.

### Commits (Alert API)
- `810c3ab` feat(api): read-only alert endpoints with exact app contract.

## Mobile Alert Screens  ☑ code + analyze + unit tests; visual review pending

Only the three Sprint-2 deliverables are enabled; later-sprint surfaces are kept hidden behind their
own flags.

`FeatureRelease` (shared `assas_design`): `alerts = true`; new gates `alertsHome`,
`alertSeverityBadges`, `alertDisplay`, `alertExplanations` all **false**; `alertManagement`, `risk`
stay false.

**Scope (per `DECISIONS.md` D4–D8).** PBI-14 is live: the alerts list, alert
details (including Last seen), and device alerts with device linking. PBI-09/10
is live: unresolved linked alerts feed the device signals (Attention, Home
priority, severity colours). PBI-22 (alert state management) is deferred:
`alertManagement` is off, hiding Review/Resolve, the state badges, the
All/Open/Resolved tabs and the live open-alerts counter, while the backend
endpoints and stored states are retained unchanged. Occurrences, first seen,
rule id and ports are hidden in the UI and retained in the database and API.

| Surface | Sprint 2 | How |
|---|---|---|
| Alerts tab (list) | ✓ shown | hero keeps the count design but shows a muted "—" (live count = PBI-22, deferred); title, severity, device, last event time; newest first. Tabs, state pills and occurrence `N×` **hidden** (`alertManagement` off). |
| Alert details | ✓ shown | title, time, device (+nav), and Signal details: alert type, severity, **Last seen** (= last event time), source/destination IP. Review/Resolve + state badge **hidden** (PBI-22 deferred → SOON tag). Occurrences, first seen, rule ID and ports **hidden** (kept in DB + API); explanation block hidden. |
| Device details → alerts | ✓ shown | this device's alerts replace "Coming soon" |
| Home open-alerts count + recent summary | ✗ hidden | gated on `alertsHome` → stays "SOON" |
| Device-list severity badges / sort | ✗ hidden | gated on `alertSeverityBadges` |
| 7-inch display alert count | ✗ hidden | gated on `alertDisplay` → stays "SOON" |

Model `SecurityAlert` extended additively (`ruleId`, `srcPort`, `dstPort`, `occurrenceCount`,
`firstTime`, `lastTime`); `fromApi` reads the new keys.

Tests: `flutter analyze` clean (mobile + display); `flutter test` 63 passed/1 skipped incl.
`test/alerts_test.dart` (contract, gating, badge-hiding). Visual review of the three screens is
outstanding — screenshots are captured on a dev machine (the Pi session is headless); see
`evidence/ui/README.md`.

### Commits (Mobile Alert Screens)
- `87d819e` feat(app): Threat Alerts in mobile (Alerts tab, details, device alerts).

## Evaluation
Dataset download and detection replay are outstanding; the resource baseline is in progress. See
`PLAN.md` / `EVALUATION.md`.
`REPORT-NOTES.md` (evidence → report sections 4/5/6) is added at sprint end.

## Documentation discipline
- Software/package versions, final configs, file/service paths, changes vs Sprint 1, and commit
  links are recorded here as each step lands.
- Official tool/source links carry an access date.
- Dataset provenance (source page, download URL, DOI/reference, license, selected files + sizes +
  SHA-256) is recorded in `EVALUATION.md`; **no dataset is downloaded before explicit approval**.
- Raw results and test logs are stored under `docs/sprint-2/evidence/` with clear paths.
- **No passwords, tokens, or private network data (real MACs/IPs/hostnames) are committed.**
