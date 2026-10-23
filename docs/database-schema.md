# Database schema

The discovery daemon (`appliance/discovery.py`) writes a single SQLite database,
`assas.db` (default `/home/assas/assas/assas.db`, override with `ASSAS_DB_PATH`).
The API (`appliance/api.py`) opens it read-only, except for the API-owned tables and
columns marked below. WAL journal mode allows concurrent reads while the daemon writes.

Verified against the live appliance database on 2026-10-17 (commit `f9d157b`).

| Table | Written by | Purpose |
|---|---|---|
| `devices` | discovery daemon (+ API for `user_name`, `trusted`) | One row per device MAC: identity, classification and presence. |
| `flows` | discovery daemon (`appliance/flows.py`) | Directional traffic metadata per 60-second window. |
| `live_activity` | discovery daemon (`appliance/live_activity.py`) | Rolling live-traffic summary for the display and app. |
| `daemon_heartbeat` | discovery daemon (`appliance/flows.py`) | Last time the capture service was alive. |
| `paired_sessions` | API | One row per paired phone. |
| `app_settings` | API / discovery daemon | Appliance settings (single row). |
| `appliance_identity` | API | Persistent public identifier of this appliance (single row). |

`sqlite_sequence` also exists; it is SQLite's internal counter for the
`AUTOINCREMENT` key of `paired_sessions` and is not used by Assas code.

Timestamps stored as TEXT are **server-local naive ISO-8601** to the second
(e.g. `2026-09-20T10:57:37`). Timestamps stored as REAL are **Unix epoch seconds**.
No indexes exist besides the primary keys.

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
| `last_monitored_seen` | TEXT | Last time unicast traffic sent by this device was seen on the mirrored (SPAN) port (same rule as `is_monitored`; broadcast/multicast do not count). The API reports `monitored = true` only while this is within the monitored window (default 120 s, env `ASSAS_MONITORED_WINDOW_SECONDS`); `NULL` or older = "Not Monitored" in the app. |
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
  coverage becomes "Not Monitored" once the window passes.
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

`POST /unpair` deletes the calling phone's row; other phones stay paired.

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

See [API_CONTRACT.md](API_CONTRACT.md) for how these fields are exposed over HTTP.
