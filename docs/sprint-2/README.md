# Sprint 2 — Scope and Changes from Sprint 1

Sprint 2 adds **signature-based threat detection** and **security alert display and state
management** to the Assas appliance. Sprint 1 delivered passive discovery, capture, classification,
pairing, the read-only inventory service, and the mobile and display applications; Sprint 2 is
**additive** and must not change that behaviour.

The functions delivered in this sprint are:
- **Signature-based threat detection** — an intrusion-detection engine inspects traffic on the
  capture interface and records detections, without ever blocking or modifying traffic.
- **Security alert ingestion** — detections are recorded as security alerts, de-duplicated, and
  linked to the device they concern.
- **The security alert service** — authenticated access for the applications to view the stored
  alerts and to update each alert's state.
- **Security alert display and state management** — the mobile application presents a single list
  of security alerts and lets the operator manage each alert's state (New, Reviewed, Resolved).
- **Device signals from unresolved alerts** — unresolved alerts raise the affected device's
  attention level and priority.

**What is implemented and verified by automated tests:** threat detection and its configuration;
security alert ingestion (de-duplication, device linking, resume safety); the security alert
service; security alert display and state management; and device signals from unresolved alerts.

**What is implemented but still awaiting verification:** the operator's on-device visual review of
the alert screens; a validated packet-drop measurement with the corrected tool; and a resource
measurement taken without the development agent co-resident.

**What is still in progress / not yet done:** the detection-accuracy evaluation on replayed attack
traffic (awaiting approval to download the datasets); and confirming the appliance's memory usage
against its target (the recorded measurement did not meet it).

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
| API | inventory endpoints | + alert endpoints: view + state update (☑) |
| Mobile | alerts UI gated off | alert list/details/per-device alerts + state management enabled (☑ code+tests; visual review outstanding) |

## Requirements tracking
Requirements grouped by function; the sections below carry the detail. Final per-requirement
pass / fail / not-tested verdicts (automated vs live) are in `VERIFICATION.md`.

| Function | Requirement | Section | Status | Evidence |
|---|---|---|---|---|
| Threat detection | Detection engine installed; version reported | Suricata Configuration | ☑ | `partA-suricata-T.log`, README |
| Threat detection | Detection-only on the capture interface (`eth1`); never blocks/modifies | Suricata Configuration | ☑ | `assas.yaml`, `partA-service-state.txt` |
| Threat detection | Community signature set installed and updatable | Suricata Configuration | ☑ | `partA-et-open-source.txt`, `partA-suricata-T.log` |
| Threat detection | Event log with alert events (plus statistics for the drop rate) | Suricata Configuration | ☑ | `partA-eve-event-types.txt` |
| Threat detection | Service definition consistent with the existing services | Suricata Configuration | ☑ | `assas-suricata.service` |
| Resource usage | Within limits: total CPU ≤75% avg, memory under target | Evaluation | ◐ CPU and drop-rate PASS; memory target not met; drop re-measurement pending | `resources/`, `EVALUATION.md` |
| Alert ingestion | Record detections as security alerts | Security Alert Ingestion | ☑ | `partBC-live.txt`, `test_alerts.py` |
| Alert ingestion | Severity from detection priority (highest→Critical … lowest→Low) | Security Alert Ingestion | ☑ | `test_alerts.py` |
| Alert ingestion | Link each alert to the device it concerns | Security Alert Ingestion | ☑ | `test_alerts.py` |
| Alert ingestion | De-duplicate recurring detections; keep count and first/last time | Security Alert Ingestion | ☑ | `partBC-live.txt`, `test_alerts.py` |
| Alert ingestion | Resume safely across restarts and log rotation | Security Alert Ingestion | ☑ | `test_alerts.py` |
| Alert service | Authenticated access to view alerts and update their state | Security Alert Service | ☑ | `test_api.py`, `test_frontend_contract.py`, `partBC-live.txt` |
| Alert display & state management | Single alert list; view details; per-device alerts; manage New/Reviewed/Resolved | Security Alert Display and State Management | ☑ code+tests; visual review outstanding | `test/alerts_test.dart`, `evidence/ui/`, `evidence/partD-pbi22-live.md` |
| Detection accuracy | Evaluation on replayed attack traffic | Evaluation | ☐ dataset download outstanding | `EVALUATION.md` |

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
5. `HOME_NET`: local IPv6 ranges `fc00::/7` (ULA) and `fe80::/10` (link-local) added.
6. `eve-log` `ethernet: yes` (src/dest MAC in events, for device attribution).
7. `EXTERNAL_NET` `"!$HOME_NET"` → **`"any"`** (see "EXTERNAL_NET widened (applied 2026-11-11)").
8. ASSAS header comment block inserted after the `---` line.

Rules path unchanged: `default-rule-path: /var/lib/suricata/rules`, `rule-files: [suricata.rules]`.

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
  of a rotated eve file is owned exclusively by the security-alert-ingestion reaper, which
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

> Operational note for security alert ingestion: for ~1–3 s after a rotation (before Suricata handles `SIGHUP`)
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

## Security Alert Ingestion  ☑ Done, unit-tested & live-verified

New daemon `appliance/alerts.py` + `appliance/systemd/assas-alerts.service` (runs as `root`, like
`assas-discovery`). It reads detection `alert` events from `eve.json` (+ rotated `eve.json-<ts>`) and
records them as security alerts in SQLite. Tests: `appliance/test_alerts.py` (51 passed).

**New tables (created by the ingester; API reads them read-only):**
- `alerts` — ER columns (`alert_id, device_mac, alert_type, title, rule_id, event_time, src_ip,
  dst_ip, src_port, dst_port, severity, state, explanation, model_version, anomaly_score,
  threshold`) **plus** additive `occurrence_count`, `last_event_time`. This sprint: `alert_type`
  constant `"Threat"`, `state` constant `"New"`; `explanation`/`model_version`/`anomaly_score`/
  `threshold` stay NULL (the plain-language explanation is looked up per classtype by the API, see
  *Threat Alert titles and explanations* below). Additive `category`, `classtype`, `device_role`
  (2026-11-14). Indexes on `last_event_time`, `(device_mac,last_event_time)`,
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

### Commits (Security Alert Ingestion)
- `6d15b7d` feat(alerts): Suricata eve.json ingestion into alerts table.

## Security Alert Service  ☑ Done & tested

The service **supports both viewing alerts and updating their state**. Additive endpoints in
`appliance/api.py`, gated by the existing `require_auth` (paired bearer token; localhost bypass). A
missing `alerts` table reads as empty.

Viewing:
- `GET /alerts` — all security alerts, newest first by `last_event_time` (`limit` 1–1000, default 200).
- `GET /alerts/{alert_id}` — one alert (404 if unknown).
- `GET /devices/{mac}/alerts` — a device's alerts, newest first.
- `GET /alerts/open_count` — the count of unresolved alerts (New + Reviewed) across the database.

State update:
- `PATCH /alerts/{alert_id}` — move one alert's state (New→Reviewed, New→Resolved, Reviewed→Resolved;
  Resolved is final). The transition is one atomic, guarded write; an illegal or backward move is
  rejected (409) and never reverts a Resolved alert.

Response is the mobile `SecurityAlert` contract with **locked casing**: `kind="threat"`,
`state="new"`, `severity ∈ {critical,high,medium,low}`; plus `id`, `title`, `device_mac`,
`device_name` (user_name→hostname→model→"Unknown device"), `time` (= `last_event_time`),
`first_event_time`, `last_event_time`, `occurrence_count`, `rule_id`, `source_ip`/`destination_ip`,
`src_port`/`dst_port`; `display_title`, `explanation`, `classtype`, `category` and `device_role`
(see *Threat Alert titles and explanations* below); the anomaly fields are `null`. A contract test
asserts the exact strings so casing can't drift.

### Commits (Security Alert Service)
- `810c3ab` feat(api): alert viewing endpoints with the exact app contract.
- state-update endpoint (`PATCH /alerts/{id}`) and the unresolved counter (`GET /alerts/open_count`) verified in `evidence/partD-pbi22-live.md`.

## Security Alert Display and State Management  ☑ code + analyze + unit tests; visual review pending

The mobile application presents the security alerts and lets the operator manage their states.
Functions belonging to later sprints are kept hidden behind their own release gates; the gating is
locked by an automated test.

**Delivered in this sprint.** The operator sees a **single list of security alerts, newest first**,
with All / Open / Resolved views. Each alert shows its title, severity, affected device and last
event time, and a state badge. Opening an alert shows its details and the device it concerns (with
navigation to that device), and offers the **Review** and **Resolve** actions. An alert begins as
**New**; it can move New → Reviewed, New → Resolved, or Reviewed → Resolved; **Resolved is final**.
A counter of **unresolved alerts (New and Reviewed)** is shown, and alert states are stored on the
appliance so they survive restarts of the application or the appliance services. If the same
detection recurs after an alert has been resolved, it is recorded as a **new, independent alert**
rather than reopening the resolved one. **Device signals from unresolved alerts** are also live:
an unresolved alert raises its device's attention level, priority and severity accent.

| Surface | This sprint | How |
|---|---|---|
| Alert list | shown | unresolved counter (New + Reviewed) in the header; All / Open / Resolved views; rows show title, severity, device, last event time and state; newest first. |
| Alert details | shown | title, time, device (with navigation), state badge and **Review / Resolve** actions (New→Reviewed, New→Resolved, Reviewed→Resolved; Resolved is final). Details: plain-language explanation with the device role line, alert type, original rule name, severity, **Last seen** (= last event time), source/destination address. First-seen time, rule identifier and ports are kept in the database and service but not shown. See *Threat Alert titles and explanations* below. |
| A device's own alerts | shown | shown in the device details screen. |
| Home summary of open alerts | hidden | later sprint; shows "SOON". |
| 7-inch display alert count | hidden | later sprint; shows "SOON". |

The alert model carries the recurrence count, first/last event times, ports and rule identifier,
read additively from the service response.

Tests: `flutter analyze` clean (mobile + display); `flutter test` **80 passed** including the alert
contract, state transitions, release gating and device-signal rules. The operator's on-device
**visual review** of the alert screens — including a Review → Resolve round-trip and the counter
decrementing as alerts resolve — is outstanding; screenshots are captured on a workstation (the
appliance session is headless). See `evidence/ui/README.md` and the per-criterion verification in
`evidence/partD-pbi22-live.md`.

### Commits
- `87d819e` feat(app): security alert screens in mobile (list, details, per-device alerts).
- `68cc749` feat: restore security alert state management (states, transitions, counter).

### Threat Alert titles and explanations (2026-11-14)

Sprint 2 decision (2026-11-11): Option 2. Threat Alert explanations ship in Sprint 2.
- **Plain title per classtype** in the alert list (e.g. "Malware activity", "Network scan").
- The **original Suricata rule name** is kept and shown in the alert details ("Rule" row); the
  **rule ID stays hidden** (kept in the database and service).
- **Explanation per classtype** in the details ("What happened"): what it means and what the user
  can do.
- **Device role line** from the stored source/destination: "This device started the activity." or
  "This device was the target."; no line for unlinked or MAC-attributed alerts.
- **Fallback "Security alert"** (and a generic explanation) for rules with no classtype, including
  the four ASSAS TEST rules, or a classtype not in the table; severity is unchanged.
- The wording lives in `docs/sprint-2/threat-alert-titles.md` (team-reviewed) and
  `appliance/alert_text.py`; `appliance/test_alert_text.py` keeps the two in sync row for row.
- How: the ingester stores eve's `category` and maps it to the short classtype through
  `/etc/suricata/classification.config`, and stores the device role when it links the alert; the
  service adds `display_title` and `explanation` when the alert is read. Existing alerts keep
  NULL in the new columns and show the fallback.

**Verified on the device (2026-11-14):** the Norton scan alerts got classtype `bad-unknown` /
`policy-violation` and device role `source`, linked to the laptop; the ASSAS TEST Low alert got
"Security alert"; the web app shows the plain titles, the explanation, the role line and the Rule
row in the details.

## Evaluation
Two evaluations, by function:
- **Detection accuracy** on replayed attack traffic — **not yet performed**: no dataset has been
  downloaded (awaiting approval) and no replay has run. The on-device test showed only that a
  detection travels end-to-end into the application, which is not an accuracy measure.
- **Resource usage** — measured. The 2-hour live-traffic baseline is complete (CPU and packet-drop
  targets met; **memory target not met**). The additional run **taken without the development agent
  co-resident is complete** and confirms the **memory target is still not met**; its packet-drop
  figure is recorded but **not yet validated** — a measurement-tool defect (the process-name
  detector) has been fixed, and the **re-measurement of the drop rate is still pending** an
  agent-free window.

Full figures, the memory accounting and the held replay commands are in `EVALUATION.md`.

## Documentation discipline
- Software/package versions, final configs, file/service paths, changes vs Sprint 1, and commit
  links are recorded here as each step lands.
- Official tool/source links carry an access date.
- Dataset provenance (source page, download URL, DOI/reference, license, selected files + sizes +
  SHA-256) is recorded in `EVALUATION.md`; **no dataset is downloaded before explicit approval**.
- Raw results and test logs are stored under `docs/sprint-2/evidence/` with clear paths.
- **No passwords, tokens, or private network data (real MACs/IPs/hostnames) are committed.**

---

## Rule-scope tuning (applied 2026-11-05)

Alerts must flag suspicious activity rather than normal usage. Twelve
informational ET Open signatures that only record ordinary usage (Discord
domain lookups/SNI, Android/Windows connectivity checks, standard STUN, a CDN
lookup) are disabled per SID via `/etc/suricata/disable.conf`;
`appliance/suricata/disable.conf` is the committed source of truth and lists
each SID with its name and reason. `suricata-update` re-applies the file on
every run, so the exceptions persist across rule updates.

Application and verification (evidence: `evidence/rule-tuning/`):
- Applied with `suricata-update --offline` (cached ruleset; no download), after
  backups of the rules file and the previous configuration.
- Enabled rules **53,305 → 53,293 (−12)**; the enabled-SID diff equals exactly
  the 12 approved SIDs (nothing else removed, nothing added); `suricata -T`
  passed; the service remained active.
- Post-apply monitoring (live + rotated eve.json, by event timestamp): new
  alerts continue from other rules while the 12 disabled SIDs produced **zero**
  new events.
- The severity mapping is unchanged, no stored alerts were altered, and the
  SURICATA STREAM/decoder rule group is unchanged pending the capture-path
  check (see Known limitations).

### Rule-scope tuning, round 2 (applied 2026-11-10)

Team decision on 2026-11-09: disable every rule that only produces trivial
alerts (normal usage or harmless protocol oddities). The full list with names
and reasons is in `appliance/suricata/disable.conf`.

- Prerequisite: the capture-load check (`evidence/capture-load-check.md`) found
  no capture loss, so STREAM events are not caused by missed packets.
- Scope: 27 SIDs plus the whole `stream-events.rules` group (59 rules: 58 alert
  rules and 1 drop rule, 2210057, which acts as an alert in IDS mode). 2100498
  stays enabled as the detection self-test. packed-exe and ZeroSSL rules stay
  enabled.
- Applied with `suricata-update --offline` after backups of
  `/etc/suricata/disable.conf` and the rules file (stored outside the
  repository).
- Enabled rules **53,293 → 53,207 (−86)**, counted as lines starting with
  `alert`, `drop`, `pass` or `reject`; this method matches the round 1 figure of
  53,293. The enabled-SID diff equals exactly the 27 SIDs plus the 59
  stream-events SIDs; nothing was added.
- `suricata -T` passed; the service was restarted at 2026-11-10 00:49:55 (+03)
  and loaded 53,212 signatures; all services active.
- Post-apply monitoring 00:49:55 to 01:03 (+03), with a phone streaming video on
  Assas-Test: none of the 86 disabled rules produced an event (checked by
  `last_event_time`, so deduplicated repeats are included). New alerts came only
  from rules outside the list.
- Pi tests after the change: test_api and test_frontend_contract with unittest
  (148 tests, OK). test_alerts.py uses pytest and was not collected by that
  run; on 2026-11-10 the full suite was run with pytest: 559 passed.
- No stored alerts were altered or deleted.

### Rule-scope tuning, round 3 (applied 2026-11-10)

Same team decision as round 2: disable every rule that only produces trivial
alerts. The names and reasons are in `appliance/suricata/disable.conf`.

- Scope: 8 SIDs: 2029575, 2054136, 2054151, 2064184, 2064185, 2031231, 2034636
  and 2200075. This includes ZeroSSL (2031231), which round 2 had kept enabled.
  packed-exe rules and 2100498 (detection self-test) stay enabled.
- 2029575 showed as Critical and 2054136/2054151 as High because their
  classtypes have priority 1 and 2 in `classification.config`; the severity
  mapping itself is correct.
- Applied with `suricata-update --offline` after backups of
  `/etc/suricata/disable.conf` and the rules file (stored outside the
  repository).
- Enabled rules **53,207 → 53,199 (−8)**, same counting method as round 2. The
  enabled-SID diff equals exactly the 8 SIDs; nothing was added.
- `suricata -T` passed; the service was restarted and all services are active.

### Severity test rules (applied 2026-11-10)

Purpose: verify that the full pipeline handles all four severity levels
(capture, detection, priority-to-severity mapping, device linking, display).
These are test rules, not attack simulation; real-attack detection is shown by
the ET Open rules and the dataset evaluation.

- Four local rules, SIDs 1000001-1000004, priority 1-4 (Critical, High,
  Medium, Low). Each fires on an HTTP request to `/assas-test/<level>` on the
  appliance. The request is harmless (the server answers 404).
- Loaded through `suricata-update` with `/etc/suricata/update.yaml`: a `local:`
  entry for `/etc/suricata/assas-test.rules` and an explicit `disable-conf`,
  so all tuning rounds stay applied. Both files are in `appliance/suricata/`.
- Applied with `suricata-update --offline` after a backup of the rules file
  (stored outside the repository).
- Enabled rules **53,199 → 53,203 (+4)**, same counting method as round 2. The
  enabled-SID diff equals exactly 1000001-1000004; nothing was removed.
- `suricata -T` passed; the service was restarted and all services are active.
- Live check: requests from a laptop, an iPad and a phone on the monitored
  Wi-Fi produced Critical, High, Medium and Low alerts, each linked to the
  requesting device.
- Note: repeated requests to the same path from the same device within 5
  minutes merge into one alert (the occurrence count increases).

### EXTERNAL_NET widened (applied 2026-11-11)

Team decision on 2026-11-11: `EXTERNAL_NET` changed from `"!$HOME_NET"` to
`"any"` in `/etc/suricata/assas.yaml` (the stock line is commented out and the
stock `"any"` line uncommented), so rules also match attacks coming from
devices inside the home network.

- Why: of the 53,203 enabled rules, 32,412 reference `EXTERNAL_NET` on one
  side: 12,015 use it as the source (an attacker outside the home), and the
  rest mostly as the destination (for example, a device contacting a server on
  the Internet). With `"!$HOME_NET"`, none of these rules could match traffic
  where both sides are devices inside the home network. Counted on the device
  on 2026-11-14 over enabled rule lines only (lines starting with alert, drop,
  pass or reject).
- Applied after a backup of `/etc/suricata/assas.yaml` (stored outside the
  repository). `suricata -T` passed; the service was restarted and all
  services are active.
- `appliance/suricata/assas.yaml` and `gen_assas_yaml.py` (edit 7) match the
  device.
- Effect on alert volume: monitoring in progress.
- Evidence: `evidence/internal-scan-detection.md` (an internal scan by a laptop
  on Assas-Test, detected only because of this change).

## Alert-log reset (2026-11-05)

To start a clean log after the rule tuning, the 645 existing `alerts` rows were
deleted in a single transaction after a validated WAL-aware SQLite backup
(stored outside the repository with a JSON manifest). Read checkpoints
(`alert_ingest_state`) were preserved, so no historical event was re-ingested;
immediately after the reader restarted the table held 0 rows, and only events
newer than the reset enter the new log. Devices, names, trust, pairing and rule
configuration were untouched. Evidence: `evidence/alert-log-reset.md`.

## Alert-log reset (2026-11-10)

Team decision: start a clean log after rule-scope tuning round 3, so the list
shows only events after all three tuning rounds. Same procedure as 2026-11-05:
the 352 existing `alerts` rows were deleted in a single transaction after a
WAL-aware SQLite backup (integrity check ok, 352 rows in both the database and
the backup; stored outside the repository). Read checkpoints
(`alert_ingest_state`) and devices were unchanged; after the reader restarted
the table stayed at 0 rows (no re-ingestion). A live self-test afterwards
produced exactly one alert (2100498, High), linked to the correct phone.
Evidence: `evidence/alert-log-reset-2026-11-10.md`.

## Known limitations

- **IPv6/IPv4 attribution (implemented 2026-11-05):** discovery records every
  device's full local address set in the additive `device_addresses` table
  (MAC, address, family, evidence source, first/last sighting) from ARP, DHCP,
  validated passive NDP (an NS/NA pair is accepted only when its link-layer
  option is present and equals the frame's source MAC; DAD probes carry no
  proof; the gateway's MAC is excluded entirely since Proxy NDP lets a router
  answer for other hosts), the kernel NDP cache (INCOMPLETE/FAILED entries
  discarded; gateway MAC excluded) and locality-guarded observed traffic.
  "Local" is strict: an address must fall inside the monitored networks — the
  discovery interface's own subnets/prefixes plus on-link prefixes learned
  from Router Advertisements on the SPAN (link-local source, on-link flag,
  bounded count) — merely being RFC 1918 or ULA is not accepted, so internet
  servers are never attributed to the router's MAC. A fan-out cap bounds
  router-like behaviour counted over a recent window (history is kept; a
  device's new addresses are never permanently blocked). The alert reader
  treats the evidence set as authoritative for any address it knows: linking
  requires the alert's event time inside [first_seen − 2 h, last_seen + 24 h],
  and a stale entry still present in the single-value inventory columns cannot
  bypass an expired window (columns remain a fallback only for addresses with
  no evidence at all). Exactly one owning device links the alert; a conflict
  or missing evidence leaves `device_mac = NULL`; a bounded relink pass
  (default 24 h) repairs recent unlinked alerts when evidence arrives late —
  without touching occurrence counts, states or older rows. Residual limits: linking is evidence-coverage dependent (an address
  never observed by any evidence source stays unlinked), decoder events
  without addresses link by the frame MAC instead (eve `ethernet: yes`): only
  to a known inventory device, with gateway/multicast/appliance MACs excluded
  and ambiguity left unlinked — identifying the MAC does not assert the device
  crafted a malformed frame, and historical alerts outside the relink
  window are not rewritten (`evidence/partD-alert-data-investigation.md`
  documents the pre-implementation data).
- **Protocol/engine events:** SURICATA STREAM and decoder signatures (TCP
  anomalies, truncated IPv6 packets) surface as Medium threat alerts. They are
  diagnostics of traffic/capture quality rather than threat indicators; their
  tuning is deliberately deferred until the capture path (mirror/offload
  settings) is examined. (Decision made on 2026-11-09: see "Rule-scope
  tuning, round 2".)
- **Detection evaluation:** the replayed-dataset evaluation has not been run
  (datasets on hold); unit and live tests do not substitute for it
  (`EVALUATION.md`).
- **Memory target:** the 2-hour baseline included a co-resident development
  agent; the <4 GB judgement awaits a clean run (`EVALUATION.md §4`).
