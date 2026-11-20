# ASSAS Device Inventory API — Contract

HTTP API over the appliance's SQLite database: the discovery daemon's device
inventory and the alert ingester's Threat Alerts. It is mostly read-only. The only
requests that change anything are pairing (`POST /pair/verify`, `POST /pair`,
`POST /unpair`), a device's trust and name (`PUT /devices/{mac}/trust`,
`PUT /devices/{mac}/name`), the appliance settings (`PUT /settings`), an
alert's state (`PATCH /alerts/{alert_id}`) and a phone's alert read marker
(`POST /alerts/{alert_id}/read`). This is the contract the Flutter app
builds against. All responses are JSON.

## Base URL / reachability
- The API (uvicorn) binds `0.0.0.0:8000`, so it is reachable on the LAN, not just
  localhost. Use the mDNS hostname, which is stable across networks:
  **`http://assas-pi.local:8000`**.
- The Pi's IP is DHCP and **varies by network** (we move between homes and the
  university), so do not hardcode it — resolve `assas-pi.local` (or discover the
  appliance via mDNS, see below). On the Pi, `hostname -I` prints the current IP.
- Management is over **eth0** (cable, switch port 3). wlan0 is a manual fallback only and
  does not auto-connect (normally no IP); eth1 is capture-only and has no IP.
- The API runs as the `assas-api` systemd service. Restart with:
  ```
  sudo systemctl restart assas-api
  ```
  To run it by hand instead (from `appliance/`):
  ```
  cd /home/assas/assas/appliance && /home/assas/assas/.venv/bin/uvicorn api:app --host 0.0.0.0 --port 8000
  ```

## Service discovery (mDNS / Bonjour)
Because the IP changes per network, the appliance advertises the API over mDNS so the app
can find it without any hardcoded address. Avahi publishes:

- **Service type:** `_assas._tcp`
- **Port:** `8000`
- **Host:** `assas-pi.local` (the A record resolves to the current IP)
- **TXT:** `path=/` (API base path)

**Flutter app (implemented, real-backend path):** the mobile app discovers the appliance
via the [`nsd`](https://pub.dev/packages/nsd) package
(`app/mobile/lib/services/appliance_locator.dart`). DNS-SD runs only on the real-backend
path. The current **DEMO** mode is the active default and serves canned data, so it does
**not** perform the `_assas._tcp` browse at all.
Resolution order (real backend): an explicit `ASSAS_API_BASE_URL` `--dart-define` override
wins; otherwise, on supported native platforms it browses `_assas._tcp`, takes the first
result's IPv4 + port, and builds the base URL; it falls back to
`http://assas-pi.local:8000` on web or on any discovery failure/timeout/denied-permission/
empty result. Never hardcodes an IP. DNS-SD is not attempted on Flutter Web (the plugin is
native-only).

**Use the IPv4 address.** A resolve of `_assas._tcp` / `assas-pi.local` returns multiple
addresses — an IPv4 (e.g. `192.168.100.216`), a **global IPv6**, and loopback. The API
listens on IPv4 only (`0.0.0.0:8000`), so the app must connect over the **IPv4** result;
the IPv6 address will refuse the connection. Prefer the A record / IPv4 endpoint from the
mDNS result and ignore AAAA. This is deliberate — see Known limitations.

The service definition lives in the repo at `appliance/avahi/assas-api.service`; install
it on the Pi with the commands in that file's README section below (see
`appliance/avahi/`).

## Authentication (pairing, PBI-08)

Every endpoint needs a paired token, except:
- requests from the appliance itself (`127.0.0.1` / `::1`), e.g. the 7-inch display;
- `GET /healthz`, `POST /pair/verify`, `POST /pair` and `GET /pairing/code` (the
  last one answers the appliance only).

Send the token on every request:
```
Authorization: Bearer <token>
```
A request without a valid token gets `401` with the header `WWW-Authenticate: Bearer`.

### GET /pairing/code
The current pairing code, for the display. Appliance only: any other caller gets
`403`, even a paired phone. The code has 6 characters from
`ABCDEFGHJKMNPQRSTUVWXYZ23456789` (no 0/O/1/I/L, so it is easy to read) and lives
60 seconds (env `ASSAS_PAIRING_CODE_TTL_SECONDS`). A new code is made only when the
old one has expired and someone asks for it.
```json
{"code": "K7MQ3X", "expires_at": "2026-10-10T15:46:30"}
```

A code works only once: as soon as it is accepted (by `/pair/verify` or `/pair`)
it is dropped and the display shows a new one.

### POST /pair/verify
Step 1 of pairing: checks the code, so the app can say it is wrong before it asks
for the phone name. No token needed.

Body: `{"code": "K7MQ3X"}` (letter case and surrounding spaces are ignored).
- `200` → `{"ticket": "...", "expires_at": "2026-10-10T15:50:30+03:00"}`. The code
  is used up.
- `401` → invalid or expired code (same `detail` as `/pair`). Counts toward the
  same 5 failed attempts as `/pair`.
- `422` → the `code` field is missing.

Ticket rules:
- Valid for 180 seconds (env `ASSAS_PAIRING_TICKET_TTL_SECONDS`).
- Single use: `/pair` consumes it.
- Only one ticket is active at a time: a new successful verify replaces the old one.
- Kept only in memory (as a SHA-256 hash); a restart of the API drops it.

### POST /pair
Step 2 of pairing. The body takes one of two forms:
- `{"ticket": "...", "device_name": "Sara's phone"}` (two-step pairing, preferred);
- `{"code": "K7MQ3X", "device_name": "Sara's phone"}` (one step, still supported;
  letter case and surrounding spaces in the code are ignored).

`device_name` is optional (at most 40 characters, trimmed; missing or blank means
"Unnamed phone").

- `200` → `{"token": "...", "appliance_id": "..."}`. The app must store the token:
  it is never shown again. The ticket or code is used up.
- `401` with a ticket → `"Pairing ticket is invalid or expired. Start pairing
  again."` (also for a ticket that was already used). A bad ticket does **not**
  count toward the 5 failed attempts.
- `401` with a code → invalid or expired code. After 5 wrong codes (from
  `/pair/verify` and `/pair` together) the current code is dropped and the display
  shows a new one, so guessing is useless.
- `422` → both `code` and `ticket` are sent, or neither.
- `503` → the database is not available yet. The ticket or code is already used
  up, so the app must start pairing again.

Only a SHA-256 hash of the token is stored (table `paired_sessions`, see
[database-schema.md](database-schema.md)), so a copy of the database cannot be used
to log in.

### POST /unpair
Ends the calling phone's session: its token stops working at once, and its alert
read markers are deleted. Other paired phones are not affected. Returns `204`
with no body.

## Timestamps
All timestamps are **server-local naive ISO-8601** to the second, e.g.
`2026-09-20T10:57:37` (no timezone suffix). Staleness is computed on the server
with the same local clock, so the app does not need to reason about timezones —
prefer the `/healthz` fields below over doing date math on the client.

## Status model (source of truth)
Each device row carries a `status`, written by the daemon:
- `online`   — currently present: on the subnet (`discovered_current=1`) **or**
               associated to the AP (`ap_associated=1`).
- `observed` — seen via mirrored (SPAN) traffic but not currently on the subnet / AP.
- `offline`  — not currently present and no live traffic.
- `candidate`— inserted from a weak signal, never confirmed present.

`/devices?online_only=true` uses the displayed `presence`: fresh `online` and
`observed` records are included, and records older than 120 seconds are excluded.
Legacy records without `last_seen` retain their stored presence. Use
`status=online` when an exact raw-status match is required.

---

## GET /healthz
Liveness of the API **and** the daemon. Use it to tell "API up but daemon stopped"
from live data.

Example:
```json
{
  "status": "ok",
  "db_available": true,
  "last_write": "2026-09-20T10:57:37",
  "seconds_since_write": 3,
  "daemon_stale": false
}
```
- `last_write` — newest of `last_seen` / `last_discovery_seen` / `last_traffic_seen`
  across all devices (the daemon's most recent write). `null` if the DB is empty.
- `seconds_since_write` — server-local `now - last_write`, integer seconds; `null`
  if `last_write` is `null`.
- `daemon_stale` — `true` when `seconds_since_write` exceeds the threshold
  (default 120s, env `ASSAS_HEARTBEAT_STALE_SECONDS`) or when there is no write yet.
- If the database file itself cannot be opened, the endpoint returns HTTP `503`
  with `{"detail": "..."}` (treat as "backend down").

**App detection rules**
- Request fails / times out → **backend unreachable**.
- HTTP 503 → **backend up, database unavailable**.
- 200 with `daemon_stale: true` → **API up, daemon stopped/stale** (show last data as stale).
- 200 with `daemon_stale: false` → **live**.

---

## GET /devices
List devices (summary rows).

Query params:
- `status` (str) — exact match on the status column.
- `device_type` (str) — exact match.
- `online_only` (bool, default false) — only displayed `presence = 'online'`, filtered before pagination.
- `limit` (int, default 100, min 1, max 500), `offset` (int, default 0). Ordered by `mac`.

Example element:
```json
{
  "mac": "72:a3:36:be:90:06",
  "ip": "192.168.1.5",
  "hostname": null,
  "device_type": "Mobile (Apple)",
  "model": "iPhone",
  "vendor": null,
  "vendor_source": null,
  "status": "online",
  "user_name": null,
  "first_seen": "2026-09-14T17:06:16",
  "last_seen": "2026-09-20T10:57:37"
}
```
`vendor_source` is normalized: a vendor on a randomized (locally-administered) MAC
is reported as `"inferred: private MAC"` rather than presented as an OUI fact.

`user_name` is the user-chosen label set via `PUT /devices/{mac}/name`; it is
`null` until a name is set.

`monitored` (bool, in both `/devices` and `/devices/{mac}`) means unicast
traffic from the device was seen on the mirrored (SPAN) port **recently**:
within the last 120 seconds by default (env `ASSAS_MONITORED_WINDOW_SECONDS`).
It is not "ever seen": a device that leaves the monitored network turns
`false` once the window passes, and a device never seen that way is `false`.
For an Offline device (same Online/Offline rule as `presence`) the window is
measured back from its `last_seen` instead of now, so it keeps the monitoring
state it had when it was last online; being idle or offline alone never makes
it `false`. If an Offline device has no usable `last_seen`, now is used.

---

## GET /devices/{mac}
Full detail for one device, including the classification explanation. `mac` accepts
`:`/`-`/bare-12-hex forms. `404` if unknown.

Example:
```json
{
  "mac": "72:a3:36:be:90:06",
  "ip": "192.168.1.5",
  "hostname": null,
  "device_type": "Mobile (Apple)",
  "model": "iPhone",
  "vendor": null,
  "vendor_source": null,
  "status": "online",
  "user_name": null,
  "first_seen": "2026-09-14T17:06:16",
  "last_seen": "2026-09-20T10:57:37",
  "dhcp_signature": null,
  "vendor_class": null,
  "upnp_location": null,
  "is_ap_client": false,
  "ap_associated": false,
  "last_ap_seen": null,
  "membership_source": null,
  "discovered_current": true,
  "last_discovery_seen": "2026-09-20T10:57:37",
  "traffic_seen": true,
  "session_seen": false,
  "last_traffic_seen": "2026-09-20T10:57:35",
  "class_source": "mDNS model (mapped identifier)",
  "classification": {
    "device_type": "Mobile (Apple)",
    "class_source": "mDNS model (mapped identifier)",
    "class_score": 80,
    "model": "iPhone",
    "model_source": "mDNS model (mapped identifier)",
    "model_score": 80,
    "vendor": null,
    "vendor_source": null
  }
}
```

### Classification / evidence
`classification` explains *why* the device got its type/vendor. Every value is a
stored **needle** — a short reason or matched token, e.g. `"default gateway"`,
`"UPnP device description"`, `"stored hostname"`, `vendor_class: "TL-SG105E"`.
The backend never stores or exposes full query names or per-flow data.
- `class_source` / `class_score` — winning device-type reason and its weight.
- `model_source` / `model_score` — how the model string was derived and its weight.
- `vendor_source` — how the vendor was derived (`"inferred: private MAC"` for guesses).
- Raw evidence needles also appear at top level: `dhcp_signature`, `vendor_class`,
  `upnp_location`.
- `class_source` is duplicated at top level for backward compatibility.

---

## PUT /devices/{mac}/name
Set or clear a user-chosen display name for one existing device. `mac` accepts
`:`/`-`/bare-12-hex forms and is matched after normalization. Requires a paired
token like the other write endpoints.

Body:
```json
{"name": "Living Room TV"}
```
- The name is trimmed. `null`, `""`, or a whitespace-only value clears it (stored
  as `null`).
- Maximum length is **40 characters, measured after trimming**: `<= 40` is accepted
  (`200`); a longer value is rejected with `422` before any write.
- The `name` field must be present: a body without it (e.g. `{}`) is `422`, and a
  non-string value is `422`.

Responses:
- `200` → `{"mac": "...", "user_name": "Living Room TV"}` (or `"user_name": null`
  when cleared). The `mac` is echoed in normalized form.
- `404` → no device with that MAC (nothing is created).
- `422` → missing/non-string `name`, or a trimmed value longer than 40 characters.
- `503` → the database is not available yet.

This touches only the `user_name` column of the one existing row; it never affects
discovery, classification, monitoring, status, or trust.

---

## GET /summary
Aggregate counts. Shape:
```json
{
  "total_known": 81,
  "current_subnet": 9,
  "traffic_runtime": 3,
  "traffic_inventory": 2,
  "traffic_only_hidden": 1,
  "ap_current": 0,
  "historical": 66,
  "by_status": [{"status": "online", "count": 9}, {"status": "offline", "count": 66}],
  "by_device_type": [{"device_type": "Mobile (Apple)", "count": 4}]
}
```

---

## Threat Alerts
Threat Alerts come from Suricata detections. The alert ingester writes them (see the
`alerts` table in [database-schema.md](database-schema.md)); the API serves them and
changes only an alert's `state`. All alert endpoints need a paired token like the
other data endpoints. If the `alerts` table does not exist yet (the ingester never
ran), lists are empty, the open count is `0` and a single alert is `404`.

### Alert object
Example (addresses and names are placeholders):
```json
{
  "id": "17",
  "kind": "threat",
  "title": "ET SCAN Suspicious inbound to mySQL port 3306",
  "display_title": "Network scan",
  "explanation": "A device scanned the network to find other devices and open services. Check whether this scan was expected.",
  "classtype": "network-scan",
  "category": "Detection of a Network Scan",
  "device_mac": "<device MAC>",
  "device_name": "<device name>",
  "device_role": "source",
  "time": "2026-11-20T10:04:00",
  "first_event_time": "2026-11-20T10:00:00",
  "last_event_time": "2026-11-20T10:04:00",
  "occurrence_count": 4,
  "rule_id": 2010937,
  "severity": "low",
  "state": "new",
  "source_ip": "<source IP>",
  "destination_ip": "<destination IP>",
  "src_port": 51234,
  "dst_port": 3306,
  "model_version": null,
  "anomaly_score": null,
  "threshold": null
}
```
- `id` — the alert id, as a string.
- `kind` — always `"threat"`.
- `title` — the original Suricata rule name (signature), unchanged.
- `display_title` / `explanation` — plain-language text chosen by the Suricata
  category (stored as `classtype`). The wording is in
  [sprint-2/threat-alert-titles.md](sprint-2/threat-alert-titles.md). With no
  classtype, or one not in that table, the title is `"Network activity detected"`
  and the explanation names the original rule, e.g. `Assas detected network
  traffic that matched a security rule ("ASSAS TEST High"). The original rule
  details are shown below.` The rule ID is never put in user-facing text.
- `rule_id` — the Suricata signature id (SID). For internal use (de-dup,
  support); the app does not show it to the user.
- `classtype` / `category` — the short classtype and Suricata's category text;
  `null` when unknown.
- `device_mac` — the linked device, or `null` when no single device could be linked.
- `device_name` — the device's user name, else a readable hostname, else its model,
  else `"Unknown device"` (always `"Unknown device"` for unlinked alerts).
- `device_role` — `"source"` (the device started the activity), `"target"`, or
  `null` (unlinked or not known).
- `severity` — lowercase `"high"` / `"medium"` / `"low"`, from the rule priority:
  1 → high, 2 → medium, 3 or more (or missing) → low. There is no `"critical"`.
- `state` — lowercase `"new"` or `"resolved"`. There is no `"reviewed"`.
- `read` — whether the **calling phone** has read the alert. It is a per-phone
  marker, not a state: states stay `new` and `resolved`, and other phones keep
  their own value. `true` once this phone opened the alert's details
  (`POST /alerts/{alert_id}/read`) and no detection was merged into it since;
  a new merged detection makes it `false` again. A resolved alert is always
  `true`. `null` for a request from the appliance itself without a token (e.g.
  the 7-inch display), which has no phone.
- **Repeated detections**: the same rule (`rule_id`) on the same device within a
  5-minute sliding window is one alert. `occurrence_count` is the number of
  detections, `first_event_time` the first and `last_event_time` the latest;
  `time` equals `last_event_time` (lists are ordered by it). A detection after
  the alert was resolved starts a new alert. Unlinked alerts merge only when the
  source and destination addresses also match.
- `source_ip` / `destination_ip` / `src_port` / `dst_port` — of the first
  detection; `null` when the event had none.
- `model_version`, `anomaly_score`, `threshold` — always `null` (anomaly alerts are
  a later sprint).

### GET /alerts
All Threat Alerts, newest first by `last_event_time` (ties by id, so paging is
stable). Query params: `limit` (int, default 200, min 1, max 1000), `offset` (int,
default 0), and `filter=unread` (optional): only the calling phone's unread alerts
that are still unresolved (the app's Unread tab). `filter=unread` without a phone
session is `409`; any other `filter` value is `422`.

### GET /alerts/unread_count
The number of the calling phone's unread, unresolved alerts in the whole database
(the Unread tab badge), not just one page:
```json
{"unread": 3}
```
`409` for a request without a phone session (the appliance itself).

### GET /alerts/open_count
The number of unresolved (`new`) alerts in the whole database, not just one page:
```json
{"open": 12}
```
The phone's Alerts screen shows this number. The 7-inch display shows it on its
"Unresolved alerts" card: the display runs on the appliance and calls the API from
`127.0.0.1`, so it needs no token (see Authentication). It polls every 5 seconds.
If a poll fails it keeps the last count, dimmed and marked "Last known". Before
the first count arrives, or on an appliance without this endpoint (`404`), it
shows "—". A count of 0 reads "No unresolved alerts".

### GET /alerts/{alert_id}
One alert. `404` if unknown.

### POST /alerts/{alert_id}/read
Marks one alert read for the calling phone; the app calls it when the alert's
details are opened (there is no button). No body. It never changes `state`.
- `200` → the alert object, with `read: true`. Calling it again is a no-op `200`.
- `404` → no alert with that id.
- `409` → the request has no phone session (the appliance itself).
- `503` → the database is not available yet.

The marker stores how many detections the alert had when it was read, so a later
merged detection makes it unread again.

**How alerts start** (read markers are kept per phone, in `alert_reads`, see
[database-schema.md](database-schema.md)):
- When Release 1 first starts, every alert that already exists is read for every
  phone already paired.
- A phone paired later starts with the unresolved alerts that exist when it pairs
  unread, and resolved ones read (resolved alerts are always read).
- `POST /unpair` deletes the phone's read markers together with its session.

### GET /devices/{mac}/alerts
The alerts linked to one device, newest first. `mac` accepts `:`/`-`/bare-12-hex
forms. Same `limit` / `offset` as `GET /alerts`. A MAC with no alerts returns `[]`.

### PATCH /alerts/{alert_id}
Changes one alert's state. The only move is **New → Resolved**; `Resolved` is final.
Body:
```json
{"state": "resolved"}
```
- `200` → the updated alert object. Asking for the state the alert already has
  (e.g. resolving a resolved alert) is a no-op `200`, so two phones resolving at
  once both succeed.
- `404` → no alert with that id.
- `409` → the move is not allowed (e.g. `"new"` on a resolved alert).
- `422` → unknown state, including `"reviewed"`.
- `503` → the database is not available yet.

The change is one guarded write, so a resolved alert is never reverted. The
ingester never changes `state`; new detections of a resolved alert's rule start
a new alert.

### Network Alert Level (not served yet)
The Network Alert Level (the highest severity among unresolved alerts) is planned
for Sprint 5. There is no endpoint yet; the app and the display show it as "Soon".

---

## Polling guidance
- Poll `GET /devices` every **5s** for the list.
- Poll `GET /healthz` every **5–10s** to drive the connection banner (live /
  unreachable / stale). Fetch `GET /devices/{mac}` on demand when a row is opened.
- Keep the last good data on screen when a poll fails; flip the banner using the
  detection rules under `/healthz`.

---

## Known limitations
- **Tokens do not expire.** A paired token stays valid until that phone calls
  `POST /unpair`. There is no automatic expiry yet.
- **Deliberate IPv4-only binding.** uvicorn binds `0.0.0.0:8000` (IPv4) and is **not**
  bound to `::`. Pairing (PBI-08) now protects the data endpoints, but enabling IPv6
  is still a separate decision. Until then the app must use the IPv4 address from the
  mDNS result (see Service discovery).
