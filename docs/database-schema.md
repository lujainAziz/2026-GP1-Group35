# Database schema

The discovery daemon (`appliance/discovery.py`) writes a single SQLite database,
`assas.db` (default `/home/assas/assas/assas.db`, override with `ASSAS_DB_PATH`).
The API (`appliance/api.py`) opens it read-only. WAL journal mode allows concurrent
reads while the daemon writes.

There is one table, `devices`, keyed by MAC. All timestamps are **server-local naive
ISO-8601** to the second (e.g. `2026-09-20T10:57:37`).

## Table: `devices`

| Column | Type | Meaning |
|---|---|---|
| `mac` | TEXT (PK) | Device MAC address, lowercase colon form. |
| `ip` | TEXT | Most recently seen IPv4 address. |
| `vendor` | TEXT | Vendor name (OUI lookup or inferred). |
| `vendor_source` | TEXT | How `vendor` was derived; `inferred: ...` for guesses (e.g. on randomized MACs). |
| `first_seen` | TEXT | First time this MAC was ever recorded. |
| `last_seen` | TEXT | Most recent write of any kind for this device. |
| `status` | TEXT | `online` / `observed` / `offline` / `candidate` (see below). |
| `hostname` | TEXT | Observed hostname (mDNS/LLMNR/NetBIOS/DHCP), if any. |
| `device_type` | TEXT | Classified type, e.g. `Router`, `Mobile (Apple)`, `Smart TV / Media Device`. |
| `model` | TEXT | Model string when derived (e.g. mDNS model id, UPnP description). |
| `dhcp_signature` | TEXT | DHCP option-55 parameter-request-list signature (evidence needle). |
| `vendor_class` | TEXT | DHCP vendor-class string (evidence needle, e.g. `TL-SG105E`). |
| `upnp_location` | TEXT | UPnP device description URL observed for this device. |
| `class_score` | INTEGER | Weight of the winning device-type evidence. |
| `class_source` | TEXT | Reason for `device_type` (evidence needle, e.g. `default gateway`). |
| `model_score` | INTEGER | Weight of the winning model evidence. |
| `model_source` | TEXT | Reason for `model` (evidence needle). |
| `is_monitored` | INTEGER (0/1) | Marked as a monitored/known device. |
| `last_span_seen` | TEXT | Last time seen via mirrored (SPAN) traffic. |
| `session_seen` | INTEGER (0/1) | Seen with live traffic during the current daemon run. |
| `traffic_seen` | INTEGER (0/1) | Ever seen carrying traffic on the mirror. |
| `last_traffic_seen` | TEXT | Last time traffic was observed. |
| `is_ap_client` | INTEGER (0/1) | Seen as a client of the Assas-Test AP. |
| `ap_associated` | INTEGER (0/1) | Currently associated to the AP. |
| `last_ap_seen` | TEXT | Last time seen associated to the AP. |
| `membership_source` | TEXT | How AP association was determined. |
| `discovered_current` | INTEGER (0/1) | Currently present on the subnet (fresh ARP/discovery). |
| `last_discovery_seen` | TEXT | Last time confirmed present on the subnet. |

### Notes
- **Evidence needles**: `class_source`, `model_source`, `vendor_source`,
  `dhcp_signature`, `vendor_class`, `upnp_location` store only short matched tokens
  or reasons — never full query names or per-flow data.
- **Status derivation** (written by the daemon):
  - `online`   — `discovered_current=1` **or** `ap_associated=1`.
  - `observed` — seen via SPAN traffic but not currently on the subnet / AP.
  - `offline`  — neither present nor carrying live traffic.
  - `candidate`— inserted from a weak signal, never confirmed present.

See [API_CONTRACT.md](API_CONTRACT.md) for how these fields are exposed over HTTP.
