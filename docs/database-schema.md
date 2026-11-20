# Database schema

The discovery daemon (`appliance/discovery.py`) writes a single SQLite database,
`assas.db` (default `/home/assas/assas/assas.db`, override with `ASSAS_DB_PATH`).
A separate process, the alert ingester (`appliance/alerts.py`, service
`assas-alerts`), writes the Threat Alert tables in the same file.
The API (`appliance/api.py`) opens it read-only, except for the API-owned tables and
columns marked below. WAL journal mode allows concurrent reads while the daemons write.

Verified against the live appliance database on 2026-11-20 (commit `40e1580`).
The Release 1 alert changes (`alerts.priority`, the severity labels, the removed
`Reviewed` state, the `alert_reads` table) are documented from the code; they are not yet verified on the
live appliance database.

| Table | Written by | Purpose |
|---|---|---|
| `devices` | discovery daemon (+ API for `user_name`, `trusted`) | One row per device MAC: identity, classification and presence. |
| `flows` | discovery daemon (`appliance/flows.py`) | Directional traffic metadata per 60-second window. |
| `live_activity` | discovery daemon (`appliance/live_activity.py`) | Rolling live-traffic summary for the display and app. |
| `daemon_heartbeat` | discovery daemon (`appliance/flows.py`) | Last time the capture service was alive. |
| `paired_sessions` | API | One row per paired phone. |
| `app_settings` | API / discovery daemon | Appliance settings (single row). |
| `appliance_identity` | API | Persistent public identifier of this appliance (single row). |
| `device_addresses` | discovery daemon | Every local address seen for each device, with first/last sighting. Used to link alerts to devices. |
| `alerts` | alert ingester (+ API for `state`) | One row per Threat Alert from Suricata. |
| `alert_ingest_state` | alert ingester | Read position in each Suricata `eve.json` file. |
| `alert_reads` | API | Per-phone "read" marker for alerts (not an alert state). |

`sqlite_sequence` also exists; it is SQLite's internal counter for the
`AUTOINCREMENT` keys of `paired_sessions` and `alerts` and is not used by Assas code.

Timestamps stored as TEXT are **server-local naive ISO-8601** to the second
(e.g. `2026-09-20T10:57:37`). Timestamps stored as REAL are **Unix epoch seconds**.

Indexes besides the primary keys:

| Index | Columns | Used for |
|---|---|---|
| `idx_alerts_dedup` | `alerts(rule_id, device_mac)` | Finding the alert a repeated event merges into (de-dup). |
| `idx_alerts_device` | `alerts(device_mac, last_event_time)` | Alerts of one device, newest first. |
| `idx_alerts_last_event` | `alerts(last_event_time)` | Alert list ordered by time; relink window. |
| `idx_device_addresses_addr` | `device_addresses(addr)` | Finding which device owns an address. |

## Table: `devices`

| Column | Type | Meaning |
|---|---|---|
| `mac` | TEXT (PK) | Device MAC address, lowercase colon form. |
| `ip` | TEXT | Most recently seen address (IPv4 or IPv6). Kept for compatibility; the API prefers the three columns below. |
| `last_ipv4` | TEXT | Most recently seen IPv4 address. |
| `last_ipv6_global` | TEXT | Most recently seen global IPv6 address. |
| `last_ipv6_ll` | TEXT | Most recently seen link-local IPv6 address (`fe80::`). |
| `vendor` | TEXT | Vendor name (OUI lookup or inferred). |
| `vendor_source` | TEXT | How `vendor` was derived; `inferred: ...` for guesses (e.g. on randomized MACs). |
| `first_seen` | TEXT | First time this MAC was ever recorded. |
| `last_seen` | TEXT | Most recent write of any kind for this device. |
| `status` | TEXT | `online` / `observed` / `offline` / `candidate` (see below). |
| `hostname` | TEXT | Observed hostname (mDNS/LLMNR/NetBIOS/DHCP), if any. |
| `device_type` | TEXT | Classified type, e.g. `Router`, `Mobile (Apple)`, `Smart TV / Media Device`. |
| `model` | TEXT | Model when derived from an official code (mDNS model id, UPnP description, DHCP vendor class, model database). Never taken from the hostname. |
| `dhcp_signature` | TEXT | DHCP option-55 parameter-request-list signature (evidence needle). |
| `vendor_class` | TEXT | DHCP vendor-class string (evidence needle, e.g. `TL-SG105E`). |
| `upnp_location` | TEXT | UPnP device description URL observed for this device. |
| `class_score` | INTEGER, default 0 | Weight of the winning device-type evidence. |
| `class_source` | TEXT | Reason for `device_type` (evidence needle, e.g. `default gateway`). |
| `model_score` | INTEGER, default 0 | Weight of the winning model evidence. |
| `model_source` | TEXT | Reason for `model` (evidence needle). |
| `is_monitored` | INTEGER (0/1), default 0 | Unicast traffic sent by this device has been seen on the mirrored (SPAN) port, so Assas can monitor it. Broadcast and multicast frames do not count, because the switch floods them to every port, including the mirrored one. 0 = never seen that way. Once set to 1 it stays 1, so the API does **not** use it for `monitored` (see `last_monitored_seen`). |
| `last_monitored_seen` | TEXT | Last time unicast traffic sent by this device was seen on the mirrored (SPAN) port (same rule as `is_monitored`; broadcast/multicast do not count). The API reports `monitored = true` only while this is within the monitored window (default 120 s, env `ASSAS_MONITORED_WINDOW_SECONDS`); `NULL` or older = "Not Monitored" in the app. For an Offline device the window is measured from its `last_seen` instead (see below). |
| `last_span_seen` | TEXT | Last time seen via mirrored (SPAN) traffic. |
| `session_seen` | INTEGER (0/1), default 0 | Seen with live traffic during the current daemon run. |
| `traffic_seen` | INTEGER (0/1), default 0 | Ever seen carrying traffic on the mirror. |
| `last_traffic_seen` | TEXT | Last time traffic was observed. |
| `is_ap_client` | INTEGER (0/1), default 0 | Seen as a client of the Assas-Test AP. |
| `ap_associated` | INTEGER (0/1), default 0 | Currently associated to the AP. |
| `last_ap_seen` | TEXT | Last time seen associated to the AP. |
| `membership_source` | TEXT | How AP association was determined. |
| `discovered_current` | INTEGER (0/1), default 0 | Currently present on the subnet (fresh ARP/discovery). |
| `last_discovery_seen` | TEXT | Last time confirmed present on the subnet. |
| `user_name` | TEXT | User-chosen display label. API-owned (set via `PUT /devices/{mac}/name`); never written by discovery. `NULL` when unset. |
| `trusted` | INTEGER (0/1), NOT NULL, default 0 | User marked the device as trusted. API-owned. |

### Notes
- **Evidence needles**: `class_source`, `model_source`, `vendor_source`,
  `dhcp_signature`, `vendor_class`, `upnp_location` store only short matched tokens
  or reasons, never full query names or per-flow data.
- **Status derivation** (written by the daemon):
  - `online`: `discovered_current=1` **or** `ap_associated=1`.
  - `observed`: seen via SPAN traffic but not currently on the subnet / AP.
  - `offline`: neither present nor carrying live traffic.
  - `candidate`: inserted from a weak signal, never confirmed present.
- **Presence in the API**: `online` / `observed` count as online only if
  `last_seen` is within the last 120 seconds; otherwise the API reports offline.
  This never changes `is_monitored` or `last_monitored_seen`.
- **Monitored in the API**: `monitored` is true only if `last_monitored_seen` is
  within the monitored window (default 120 seconds, env
  `ASSAS_MONITORED_WINDOW_SECONDS`). A device that leaves the mirrored port's
  coverage becomes "Not Monitored" once the window passes. For an Offline
  device the window is measured back from its `last_seen` instead of now, so it
  keeps the state it had when it was last online (no usable `last_seen`: now).
- **IP shown by the API**: `last_ipv4`, then `last_ipv6_global`, then
  `last_ipv6_ll` as a last resort.

## Table: `flows`

Directional flow metadata from passive capture (PBI-03). Payloads are never stored.
A flow is one direction of an IP / protocol / port tuple inside one 60-second window.

| Column | Type | Meaning |
|---|---|---|
| `window` | INTEGER, NOT NULL | Time window number: `floor(epoch_seconds / 60)`. |
| `src_ip` | TEXT, NOT NULL | Source IPv4 or IPv6 address. |
| `dst_ip` | TEXT, NOT NULL | Destination IPv4 or IPv6 address. |
| `protocol` | INTEGER, NOT NULL | `6` = TCP, `17` = UDP, otherwise the IP protocol / IPv6 next-header number. |
| `src_port` | INTEGER, NOT NULL | Source port; `-1` when not available (no TCP/UDP header, non-initial fragments). |
| `dst_port` | INTEGER, NOT NULL | Destination port; `-1` when not available. |
| `first_seen` | REAL, NOT NULL | First packet of this flow in the window (epoch seconds). |
| `last_seen` | REAL, NOT NULL | Last packet of this flow in the window (epoch seconds). |
| `packet_count` | INTEGER, NOT NULL | Packets in the window. |
| `byte_count` | INTEGER, NOT NULL | IP-layer bytes (Ethernet headers excluded). |

Primary key: (`window`, `src_ip`, `dst_ip`, `protocol`, `src_port`, `dst_port`).
Rows are buffered in memory and merged on flush (`ON CONFLICT ... DO UPDATE`), so a
repeated flush never counts packets twice.

## Table: `live_activity`

Single row (`id = 1`) holding the rolling live-traffic summary served by
`GET /activity`.

| Column | Type | Meaning |
|---|---|---|
| `id` | INTEGER (PK), always 1 | Single-row table. |
| `data` | TEXT, NOT NULL | JSON: recent packets-per-second samples (at most 12) and the protocols seen recently (e.g. `ARP`, `MDNS`, `UDP`). No DNS query names or payloads. |

`GET /activity` returns `{"available": false}` when the table does not exist yet, and
marks the data `stale` when it is too old.

## Table: `daemon_heartbeat`

Single row (`id = 1`). The capture service writes it on every flush, even when no
device sends traffic.

| Column | Type | Meaning |
|---|---|---|
| `id` | INTEGER (PK), always 1 | Single-row table. |
| `updated_at` | REAL, NOT NULL | Last heartbeat (epoch seconds). |

`/healthz` reports `daemon_stale: true` when the heartbeat is older than the stale
limit, so the app can tell "API up but discovery stopped" apart from a quiet network.

## Table: `paired_sessions`

One row per paired phone (PBI-08). Created by the API on the first successful
pairing; readers treat a missing table as "nobody is paired yet".

| Column | Type | Meaning |
|---|---|---|
| `id` | INTEGER (PK, AUTOINCREMENT) | Row id. |
| `token_hash` | TEXT, UNIQUE, NOT NULL | SHA-256 hex digest of the phone's token. The token itself is never stored. |
| `created_at` | TEXT, NOT NULL | When the phone paired. |
| `device_name` | TEXT, NOT NULL, default `'Unnamed phone'` | Phone name sent with `POST /pair` (max 40 characters), shown on the display. |

`POST /unpair` deletes the calling phone's row and its `alert_reads` rows (same
transaction); other phones stay paired.

## Table: `app_settings`

Single row (`id = 1`).

| Column | Type | Meaning |
|---|---|---|
| `id` | INTEGER (PK), always 1 | Single-row table. |
| `active_probes` | INTEGER (0/1), NOT NULL, default 0 | "Active identification" switch in the app. 0 = passive only (no nmap / mDNS / NBNS probes). The daemon reloads it at runtime. |

## Table: `appliance_identity`

Single row (`id = 1`).

| Column | Type | Meaning |
|---|---|---|
| `id` | INTEGER (PK), always 1 | Single-row table. |
| `value` | TEXT, NOT NULL | Random UUID created once. Public identifier returned by `/healthz` and `/pair` so the app knows it is talking to the same appliance. Not a credential. |

## Table: `device_addresses`

Address ownership evidence (PBI-14). One row per (`mac`, `addr`): the full set of
local addresses each device has used. Unlike the `last_*` columns of `devices`, a
new address never replaces an old one. Written by the discovery daemon; the alert
ingester only reads it.

| Column | Type | Meaning |
|---|---|---|
| `mac` | TEXT, NOT NULL | Device MAC (same form as `devices.mac`). |
| `addr` | TEXT, NOT NULL | Address: IPv4 dotted, IPv6 exploded lowercase (the form Suricata writes in `eve.json`). |
| `family` | TEXT, NOT NULL | `ipv4`, `ipv6` (global or ULA) or `ipv6-ll` (link-local). |
| `source` | TEXT, NOT NULL | Evidence source: `arp`, `ndp`, `dhcp` (authoritative) or `span` / `discovery` (traffic-derived). |
| `first_seen` | TEXT, NOT NULL | First time this device was seen with this address. Never changed after insert. |
| `last_seen` | TEXT, NOT NULL | Most recent sighting. |

Primary key: (`mac`, `addr`).

### Notes
- **What is recorded**: only addresses on the monitored link (the discovery
  interface's subnets and prefixes, plus prefixes from Router Advertisements;
  IPv6 link-local always counts). Off-link, loopback, multicast and unspecified
  addresses are never stored. At most 16 global IPv6 addresses seen in the last
  48 hours are recorded per device (`ASSAS_ADDR_FANOUT_CAP`,
  `ASSAS_ADDR_FANOUT_WINDOW_HOURS`); further ones are skipped.
- **Source upgrade**: on a repeat sighting `last_seen` is bumped, and an
  authoritative source (`arp` / `ndp` / `dhcp`) replaces a traffic-derived one
  (`span` / `discovery`), never the reverse.

## Table: `alerts`

Threat Alerts from Suricata `alert` events in `eve.json` (PBI-14, PBI-22). Written
by the alert ingester; the API writes only `state`. Payloads are never stored.

| Column | Type | Meaning |
|---|---|---|
| `alert_id` | INTEGER (PK, AUTOINCREMENT) | Alert id. |
| `device_mac` | TEXT | Linked device (see device linking below). `NULL` when no single device could be linked. |
| `alert_type` | TEXT, NOT NULL, default `'Threat'` | Alert kind. The ingester writes only `Threat`, and the API serves only `Threat` rows. |
| `title` | TEXT, NOT NULL | Suricata rule signature text; `Suricata alert` when the event has none. The API returns it as `title` and adds a plain-language `display_title` from `classtype`. |
| `rule_id` | INTEGER | Suricata signature id (`alert.signature_id`). Returned by the API for internal use; never shown to the user. |
| `event_time` | TEXT, NOT NULL | Earliest event of this alert. Ingest time when the event has no usable timestamp. |
| `src_ip` | TEXT | Source address of the first event; `NULL` for events without addresses (e.g. decoder events). |
| `dst_ip` | TEXT | Destination address of the first event; `NULL` as above. |
| `src_port` | INTEGER | Source port of the first event; `NULL` when absent. |
| `dst_port` | INTEGER | Destination port of the first event; `NULL` when absent. |
| `severity` | TEXT, NOT NULL | From the rule priority (`alert.severity`): 1 = `High`, 2 = `Medium`, 3 or more / missing = `Low`. There is no `Critical`. |
| `state` | TEXT, NOT NULL, default `'New'` | `New` / `Resolved`. **API-owned after insert**: the ingester inserts `New` and never changes it; the API changes it via `PATCH /alerts/{alert_id}` (New→Resolved only; `Resolved` is final). |
| `explanation` | TEXT | Stored explanation; not written today. When `NULL` the API shows the `classtype` text. |
| `model_version` | TEXT | Not written or read by any code today (always `NULL`). |
| `anomaly_score` | REAL | Not written or read by any code today (always `NULL`). |
| `threshold` | REAL | Not written or read by any code today (always `NULL`). |
| `occurrence_count` | INTEGER, NOT NULL, default 1 | Number of events merged into this alert (see de-dup below). |
| `last_event_time` | TEXT, NOT NULL | Latest event of this alert. |
| `category` | TEXT | Suricata `alert.category` (the classtype description), as received. `NULL` for rules without a classtype. |
| `classtype` | TEXT | Short classtype name, mapped back from `category` through Suricata's `classification.config`. `NULL` when unknown or ambiguous; the API then shows a fallback title. |
| `device_role` | TEXT | Side of the first event the linked device was on: `source` / `target`. `NULL` when unlinked or linked by MAC. |
| `priority` | INTEGER | Raw Suricata rule priority (eve `alert.severity`) that `severity` was derived from; `NULL` when the event had none. Rows converted in Release 1 from the old `Low` label also have `NULL` (the old label does not say whether it was 4 or more). |

`category`, `classtype` and `device_role` were added after the table first shipped.
Only the ingester adds them, at startup; rows from before that have `NULL`. The API
never alters the `alerts` table: if it starts before the ingester has added a
column, it reads that column as `NULL`.

`priority` is also added only by the ingester, by the one-time Release 1 conversion below.

### Notes
- **Release 1 conversion** (one time, ingester only, `alerts.migrate_release1`):
  in a single transaction the ingester adds `priority`, fills it from the old
  label, and rewrites the labels: `Critical`→`High`, `High`→`Medium`,
  `Medium`→`Low`, `Low`→`Low`; it also sets every `Reviewed` alert to `New`.
  The column's existence marks the conversion as done, so it never runs twice
  (running it again would shift `High` to `Medium`), and a fresh table is never
  converted. If any step fails the whole conversion rolls back. The API reads a
  leftover `Critical` as `high` and a leftover `Reviewed` as `new`.
- **De-dup**: a new event is merged into the most recent alert with the same
  `rule_id` and the same `device_mac` (for unlinked alerts: same `rule_id`,
  `src_ip` and `dst_ip`, so unknown hosts never merge), if that alert is not
  `Resolved` and its `last_event_time` is within 5 minutes of the event
  (`ASSAS_ALERT_DEDUP_WINDOW`, seconds). The window slides: it is measured from
  the latest event, so a long run of repeats stays one alert. A merge adds 1 to
  `occurrence_count`
  and widens `event_time` / `last_event_time`; every other column, including
  `state`, keeps its value. If the newest match is `Resolved` or outside the
  window, a new alert is inserted with state `New`.
- **Device linking**: each of `src_ip` / `dst_ip` is matched to a device.
  `device_addresses` decides for any address it has rows for, using only rows
  whose [`first_seen` − 2 h, `last_seen` + 24 h] window contains the event time
  (`ASSAS_ADDR_PRE_SLACK_HOURS`, `ASSAS_ADDR_GRACE_HOURS`); addresses with no
  rows fall back to the `devices` address columns. An address links only when
  exactly one device owns it; the appliance's own address, the gateway,
  multicast, broadcast and unspecified addresses never link. One side matches:
  that device, role `source` or `target`. Both match: the source device, role
  `source`. Neither: unlinked. Events without addresses are linked by Ethernet
  MAC only when exactly one side is a known device that is not the gateway or
  the appliance (no role).
- **Relink**: unlinked alerts whose `last_event_time` is within the last
  24 hours (`ASSAS_ALERT_RELINK_HOURS`) are retried when new address evidence
  arrives. Only `device_mac` and `device_role` are set.

## Table: `alert_reads`

Which alerts each paired phone has read (Release 1). Written only by the API.
"Read" is a marker kept per phone, not an alert state: `alerts.state` stays
`New` / `Resolved`, and the ingester never touches this table.

| Column | Type | Meaning |
|---|---|---|
| `session_id` | INTEGER, NOT NULL | The phone: `paired_sessions.id`. |
| `alert_id` | INTEGER, NOT NULL | The alert: `alerts.alert_id`. |
| `read_count` | INTEGER, NOT NULL | The alert's `occurrence_count` when this phone read it. |
| `read_at` | TEXT, NOT NULL | When this phone read it. |

Primary key: (`session_id`, `alert_id`).

- **Read rule**: an alert is read for a phone when it is `Resolved`, or when the
  phone's row has `read_count` ≥ the alert's current `occurrence_count`. A
  detection merged into the alert raises `occurrence_count`, so it becomes unread
  again. No row means unread.
- **Written** by `POST /alerts/{alert_id}/read` (insert or update, storing the
  current `occurrence_count`). `POST /unpair` deletes the phone's rows.
- **Created** by the API at startup, or by `POST /pair` / `POST /alerts/{alert_id}/read`
  if it does not exist yet. In the same transaction as the `CREATE`, every phone
  already paired gets a row for every existing unresolved alert (the Release 1
  rollout: existing alerts start read). The table's existence marks this as done,
  so it runs once. `POST /pair` creates the table before adding the new phone, so
  a phone paired later gets no rows: the unresolved alerts that exist when it
  pairs start unread for it.

## Table: `alert_ingest_state`

Read checkpoint of the alert ingester: one row per `eve.json` file (the live file
and rotated `eve.json-<timestamp>` files), identified by inode. Written in the same
transaction as the alerts read from that file, so no event is stored twice after
a restart.

| Column | Type | Meaning |
|---|---|---|
| `st_dev` | INTEGER, NOT NULL | Device number of the file (part of its identity). |
| `st_ino` | INTEGER, NOT NULL | Inode number of the file (part of its identity). |
| `path` | TEXT | Path the file was last read under (changes when it is rotated). |
| `offset` | INTEGER, NOT NULL, default 0 | Bytes read so far (up to the last complete line). |
| `size_at_eof` | INTEGER | File size when it was marked fully read; `NULL` before. |
| `consumed` | INTEGER (0/1), NOT NULL, default 0 | 1 = rotated file fully read and may be deleted. Set back to 0 if the file grows again. |
| `updated_at` | TEXT | Last time `offset` was written. |

Primary key: (`st_dev`, `st_ino`). The row is deleted when the ingester deletes the
rotated file (or finds it already gone).

See [API_CONTRACT.md](API_CONTRACT.md) for how these fields are exposed over HTTP.
