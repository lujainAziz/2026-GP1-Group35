# ASSAS Device Inventory API — Contract

Read-only HTTP API over the discovery daemon's SQLite inventory. This is the
contract the Flutter app builds against. All responses are JSON.

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
- `GET /healthz`, `POST /pair` and `GET /pairing/code` (the last one answers the
  appliance only).

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

### POST /pair
Body: `{"code": "K7MQ3X"}` (letter case and surrounding spaces are ignored).
- `200` → `{"token": "..."}`. The app must store it: it is never shown again.
- `401` → invalid or expired code. After 5 wrong codes the current code is dropped
  and the display shows a new one, so guessing is useless.
- `422` → the `code` field is missing.
- `503` → the database is not available yet.

Only a SHA-256 hash of the token is stored (table `paired_sessions`, see
[database-schema.md](database-schema.md)), so a copy of the database cannot be used
to log in.

### POST /unpair
Ends the calling phone's session: its token stops working at once. Other paired
phones are not affected. Returns `204` with no body.

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
