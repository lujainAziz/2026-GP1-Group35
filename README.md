# ASSAS | عَسس

**Edge-Based Cybersecurity Monitoring for Home and Small Business Networks**

## Overview

ASSAS is an edge-based cybersecurity monitoring prototype designed to help home users and small business owners understand and monitor their local networks.

Built around a Raspberry Pi 5, ASSAS provides network visibility and automatic device discovery through local traffic monitoring. Its proposed security architecture combines signature-based threat detection, behavioral anomaly detection, explainability, and network risk assessment.

The system aims to make complex network security information understandable through a Flutter mobile application and a dedicated 7-inch on-device display.

## Core Capabilities

The ASSAS project is designed around the following capabilities:

- **Device Discovery & Classification:** Discover network devices and identify their available information using network observations and optional lightweight probes.
- **Signature-Based Detection:** Detect selected known threats using Suricata and security rules.
- **Behavioral Anomaly Detection:** Identify unusual activity using per-device behavioral baselines and Isolation Forest.
- **Explainable Security Alerts:** Use SHAP and a local rule-based explanation engine to provide understandable explanations and response guidance.
- **Network Risk Assessment:** Present the overall network risk level based on unresolved security alerts.
- **User Interfaces:** Provide network information through a Flutter mobile application and a read-only physical status display.

## Current Development Status

ASSAS is being developed incrementally. The repository currently includes work on:

- Raspberry Pi network monitoring and device discovery.
- Device fingerprinting and classification.
- SQLite-based local device inventory.
- FastAPI backend and device-management endpoints.
- Mobile-to-appliance pairing using a rotating QR code displayed on the appliance.
- Flutter mobile application and on-device display.
- Automated tests, systemd services, and local service discovery.

The broader cybersecurity components, including Suricata integration, Isolation Forest anomaly detection, SHAP explanations, alert management, and network risk assessment, are part of the planned system architecture and are not presented here as completed functionality.

## System Architecture

ASSAS uses a Raspberry Pi 5 connected to a managed switch configured for port mirroring (SPAN).

The appliance uses separate network interfaces for management and traffic capture.

**Current monitoring architecture:**

```text
Local Network
     |
Managed Switch (SPAN)
     |
Raspberry Pi 5
     |
Device Discovery & Classification
     |
SQLite Database
     |
FastAPI Backend
     |
Flutter User Interfaces
```

The complete architecture additionally includes two complementary security-detection paths:

- Suricata for signature-based detection.
- Isolation Forest for per-device behavioral anomaly detection, with SHAP for interpreting anomaly results.

Detection results will feed the local explanation, alert-management, and network risk components.

Core monitoring and security analysis are designed to run locally on the Raspberry Pi.

## Repository Structure

```text
ASSAS/
├── appliance/
│   ├── discovery.py
│   ├── classification.py
│   ├── api.py
│   ├── requirements.txt
│   ├── systemd/
│   ├── avahi/
│   └── test_*.py
│
├── app/
│   ├── mobile/
│   ├── display/
│   ├── packages/
│   └── SETUP.md
│
├── docs/
│   ├── API_CONTRACT.md
│   ├── database-schema.md
│   └── ...
│
└── README.md
```

- `appliance/` — Raspberry Pi backend, discovery, classification, API, and system services.
- `app/mobile/` — Flutter application for mobile devices.
- `app/display/` — Flutter-based on-device display for the Raspberry Pi.
- `app/packages/` — Shared Flutter packages.
- `docs/` — Technical specifications, integration notes, and development documentation.

## Device Discovery

ASSAS combines passive network observations with active local discovery mechanisms.

Passive analysis uses available protocol evidence, including ARP, DHCP, mDNS, SSDP/UPnP, NetBIOS, and TCP header characteristics.

Active discovery includes subnet ARP scanning and configurable lightweight identification probes.

Device information is stored locally in SQLite. Attributes that cannot be reliably identified remain Unknown or Unavailable rather than being guessed.

## Mobile Pairing

The ASSAS mobile application pairs with the Raspberry Pi appliance through a rotating QR code.

1. The appliance displays a temporary pairing QR code on its physical screen.
2. The user scans the QR code using the ASSAS mobile application.
3. The application submits the pairing code to the local backend.
4. After successful pairing, the application receives a session credential for authorized API access.

The pairing code expires and is replaced periodically.

## Network Configuration

The Raspberry Pi uses dedicated interfaces:

| Interface | Purpose |
|---|---|
| `eth0` | Management, API access, and local network discovery |
| `eth1` | Passive traffic capture from the SPAN mirror |
| `wlan0` | Manual fallback connection |

The capture interface operates without an IP address.

The appliance advertises its local API using Avahi (`_assas._tcp`) so the mobile application can discover it without relying on a fixed IP address.

## Backend Services

The backend runs through systemd services on the Raspberry Pi.

```bash
sudo systemctl restart assas-discovery
sudo systemctl restart assas-api
```

Check service status:

```bash
systemctl status assas-discovery assas-api
```

The corresponding systemd configuration files are maintained under `appliance/systemd/`.

### Optional AP association polling

`assas-discovery` can read the wireless-station list from the TP-Link access point. The AP takes its IP address by DHCP, so it changes with the upstream router; discovery therefore finds the AP by its MAC address.

| Variable | Default | Meaning |
|---|---|---|
| `ASSAS_AP_PASSWORD` | unset | AP admin password. Polling is enabled only when set. |
| `ASSAS_AP_MAC` | unset | AP MAC. When `ASSAS_AP_URL` is unset, the AP's current IPv4 is looked up by this MAC in the neighbour table (`/proc/net/arp`, `ip -4 neigh`, then the last IPv4 discovery recorded) on every poll. Also removed from the station list. |
| `ASSAS_AP_URL` | unset | Fixed AP address (for example `http://192.0.2.10`). Overrides the MAC lookup. |
| `ASSAS_AP_USER` | `admin` | AP admin user. |
| `ASSAS_AP_SSID` | `Assas-Test` | SSID name used in log messages. |
| `ASSAS_AP_POLL_SECONDS` | `5` | Poll interval (minimum 3). |
| `ASSAS_AP_AUTH_TTL_SECONDS` | `600` | How long a successful AP login is reused. |
| `ASSAS_AP_CLIENTS` | unset | Manual station MAC list, for tests or as a fallback. |

If polling is enabled but the AP address cannot be found, discovery logs one warning per poll, skips that poll, and keeps working normally.

The repository holds no real AP values. Put them in a device-only drop-in that is not committed:

```ini
# /etc/systemd/system/assas-discovery.service.d/ap.conf
[Service]
Environment=ASSAS_AP_MAC=02:00:00:00:00:01
Environment=ASSAS_AP_PASSWORD=change-me
```

Then run `sudo systemctl daemon-reload && sudo systemctl restart assas-discovery`.

## Running Tests

Discovery tests use the system Python environment, while API tests use the project virtual environment.

From `appliance/`:

```bash
python3 -m unittest test_discovery
../.venv/bin/python3 -m unittest test_api
```

Additional component tests are available under `appliance/`.

## Flutter Applications

The repository contains two Flutter applications.

**Mobile Application**

```bash
cd app/mobile
flutter pub get
flutter run
```

**On-Device Display**

```bash
cd app/display
flutter pub get
flutter run -d linux
```

The physical display runs on the Raspberry Pi as a fullscreen Linux application.

For build instructions, platform configuration, demo mode, and Raspberry Pi kiosk setup, see [app/SETUP.md](app/SETUP.md).

## Documentation

- [API Contract](docs/API_CONTRACT.md) — Backend endpoints and application integration.
- [Database Schema](docs/database-schema.md) — Local database structure.
- [Flutter Setup](app/SETUP.md) — Mobile and display setup instructions.
- [Avahi Configuration](appliance/avahi/) — Local appliance discovery.

## Project Scope

ASSAS is a monitoring and detection system, not a firewall or an intrusion prevention system.

It does not automatically block devices, terminate connections, quarantine network devices, or enforce firewall rules.

Its purpose is to improve local network visibility and help users understand potential security risks through clear information and practical response guidance.

---

**ASSAS | عَسس**  
Graduation Project — Department of Information Technology  
College of Computer and Information Sciences  
King Saud University
