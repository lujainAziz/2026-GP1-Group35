# ASSAS

Passive network device inventory for a small LAN. A Raspberry Pi watches a mirrored
(SPAN) port, discovers devices, and classifies them from passive evidence
(ARP, mDNS, DHCP, UPnP, NetBIOS, TCP SYN fingerprints). A read-only HTTP API serves
the inventory to a Flutter app.

## Layout

```
appliance/   Backend that runs on the Pi
  discovery.py        capture + discovery daemon (writes assas.db)
  api.py              read-only FastAPI over assas.db
  test_discovery.py, test_api.py
  requirements.txt
  systemd/            copies of the installed systemd units + drop-ins
app/         Flutter app (device-inventory GUI)
docs/        API_CONTRACT.md, database-schema.md
```

`assas.db` and the Python virtualenv `.venv/` live at the repo root and are not moved
or tracked. The DB path defaults to `/home/assas/assas/assas.db` and can be overridden
with the `ASSAS_DB_PATH` environment variable.

## Components

- **Discovery daemon** (`appliance/discovery.py`) — runs as the `assas-discovery`
  systemd service (needs `CAP_NET_RAW`/`CAP_NET_ADMIN`). Captures on the mirror
  interface, refreshes subnet presence, runs optional light probes, and writes the
  `devices` table.
- **API** (`appliance/api.py`) — runs as the `assas-api` systemd service; FastAPI +
  uvicorn on `0.0.0.0:8000`, opening the DB read-only. Endpoints and polling guidance
  are in [docs/API_CONTRACT.md](docs/API_CONTRACT.md).

## Running the tests

The two suites use different interpreters by design:

```
# from appliance/
python3 -m unittest test_discovery          # system Python (has scapy)
../.venv/bin/python3 -m unittest test_api    # venv (has fastapi)
```

## Services

```
sudo systemctl restart assas-discovery
sudo systemctl restart assas-api
systemctl status assas-discovery assas-api
```

The installed unit files (and drop-ins) are mirrored under `appliance/systemd/`.

## Network setup

The Pi has three interfaces:

- **eth0** — cable to switch port 3, reachable at `assas-pi.local` (DHCP IP varies by
  network). The **only** management interface (SSH + the API).
- **eth1** — capture-only SPAN mirror, promisc, no IP. Discovery fingerprints on it.
- **wlan0** — manual fallback only, does **not** auto-connect (normally no IP).

eth0 and wlan0 share the subnet, so leaving wlan0 auto-connected dual-homes the Pi and
causes intermittent SSH drops. Pin management to eth0 and keep Wi-Fi as a manual fallback:

```
# Discovery scans/join-observes on eth0 (drop-in overrides the unit's default):
printf '[Service]\nEnvironment=ASSAS_DISCOVERY_IFACE=eth0\n' | \
  sudo tee /etc/systemd/system/assas-discovery.service.d/discovery-iface.conf
sudo systemctl daemon-reload
sudo systemctl restart assas-discovery

# Stop every saved Wi-Fi profile from auto-connecting (device-level autoconnect does
# not persist across reboot, so disable it per-profile). while-read, not for-in, so
# profile names with spaces (e.g. "Mama Noura 5G") are handled correctly:
nmcli -t -f NAME,TYPE connection show | grep 802-11-wireless | cut -d: -f1 | while read -r c; do
  sudo nmcli connection modify "$c" connection.autoconnect no
done
sudo nmcli device disconnect wlan0

# Verify: single default route via eth0, wlan0 has no IP.
ip route show default
ip -4 addr show wlan0 | grep inet || echo "wlan0 has no IP (good)"
```

Bring the fallback up by hand when needed: `sudo nmcli connection up "Assas-Test"`.

## Flutter app

Flutter is **not** installed on the Pi. On a machine with Flutter, run
`flutter pub get` inside `app/` before building.

## Docs

- [docs/API_CONTRACT.md](docs/API_CONTRACT.md) — HTTP API the app builds against.
- [docs/database-schema.md](docs/database-schema.md) — the `devices` table.
- [appliance/avahi/](appliance/avahi/) — mDNS (`_assas._tcp`) advertisement so the app
  finds the appliance without a hardcoded IP.
