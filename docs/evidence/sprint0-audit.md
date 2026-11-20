# Sprint 0 — Evidence-Based Audit

**Date:** 2026-09-20 · **Deadline:** 2026-09-27 · **Mode:** read-only (no code/config changed)
**System:** assas-pi, discovery PID 19954 / api PID 17453, DB `/home/assas/assas/assas.db`

Status key: **PASS** (met, evidenced) · **PARTIAL** (partly met) · **FAIL** (not met) · **NOT STARTED** · **N/V** (not verifiable from available evidence).

## Summary table

| # | Requirement | Status | Evidence (actual output) | Gap |
|---|---|---|---|---|
| A.1 | Hardware: eth1 promisc/no-IP/mirrored; eth0 sole mgmt + single default route; wlan0 no IP/no autoconnect; 3 units enabled+active; units match repo | **PASS** | `eth1 … PROMISC`, no IP, **rx 632 pkt/10s = 63 pkt/s**. `eth0` single `default via 192.168.100.1 dev eth0 metric 100`, IP .216. `wlan0 DORMANT` no IP; all 6 Wi-Fi profiles `AUTOCONNECT=no`. discovery/api/capture all `enabled/active`. All 7 unit+drop-in files `diff`-identical to `appliance/systemd/`; file-set parity confirmed. | — |
| A.2 | Network asset discovery: ARP scan + join observer on eth0; initial count > 0 | **PASS** | Journal (PID 19954): `ARP scan on eth0 …`, `Initial discovery found 11 device(s)`, `Passive ARP join observer on eth0`. | — |
| A.3 | Live inventory: DB fresh; online→offline transitions; 30-day retention + housekeeping | **PASS** | `max(last_seen)` age **1s**; status counts online=13/observed=3/offline=64. Real transition: `[OFFLINE] 02:5a:0f:00:1d:36 ip=192.168.100.207 no longer confirmed by subnet discovery`. `DELETE_AFTER_DAYS=30` (no env override), `housekeeping` thread started, age-out 120s. | — |
| A.4 | Fingerprinting & classification: classified/unknown; inferred-vendor integrity; 24h evidence sources | **PASS** | total 80, **classified 40 / unknown 40**. 4 rows with `vendor_source LIKE 'inferred%'`, **all on randomized MACs**; **0 real-OUI MACs carry an inferred vendor**. 24h journal tags: `MDNS-QUERY ×3795, TRAFFIC ×86, SYN-FP ×15, NBNS-PROBE ×14, MDNS-PROBE ×14, OFFLINE ×2`. Stored winning evidence also includes: mDNS model, SSDP advertisement, mDNS friendly name, UPnP device description, MAC vendor, stored hostname, device model identifier, default gateway, DHCP vendor class, Nmap services, Nmap OS fingerprint, NetBIOS responder, DHCP fingerprint, AP role. | Minor: SSDP/UPnP/DHCP/Nmap evidence is stored but does not emit a bracketed journal tag, so 24h "fired" list from logs is a subset of active sources. |
| A.5 | GUI "Live Device Inventory with Device Details" | **PARTIAL** | API: 4 endpoints live — `/healthz`, `/devices`, `/devices/{mac}`, `/summary`. Flutter screens exist (`mobile_dashboard.dart`, `screens/main_shell_screen.dart`, `screen_dashboard.dart`) and call HTTP. **But** app calls **`/api/devices`** and **`/api/system/health`** — endpoints that do **not** exist (real: `/devices`, `/healthz`) — against a hardcoded **`http://10.0.2.2:8000`** (Android-emulator loopback), not mDNS/`assas-pi.local`. No working device-detail screen wired to the real API. | GUI is non-functional against the live API: wrong paths, wrong base URL, no mDNS. Device-detail view not wired. |
| B / PBI-04 | Acceptance criteria (literal) | **N/V** | No PBI text found anywhere in the repo (`grep` for PBI-0?4/06/18/19/20 → none). Cannot check criteria literally. Observed related capability: subnet/passive asset discovery works (A.2). | PBIs are not version-controlled; acceptance criteria undocumented. |
| B / PBI-06 | Acceptance criteria (literal) | **N/V** | Same — no criteria in repo. Observed: classification pipeline active (A.4). | As above. |
| B / PBI-18 | Acceptance criteria (literal) | **N/V** | Same — no criteria in repo. | As above. |
| B / PBI-19 | Data persists across a service restart | **PASS** | DB is on-disk SQLite (`assas.db`, 32 KB, WAL). `oldest first_seen = 2026-09-11T14:06:39`; **79 of 80 rows have first_seen before today**; **6 daemon restarts today** (build banner ×6). Data survived every restart. | — |
| B / PBI-20 | Flow information for downstream components | **NOT STARTED** | No flow/export mechanism: `grep netflow|ipfix|flow|export` → only comments stating "*no per-flow data is read or stored*". System is device-inventory oriented; it emits no per-flow/connection records for downstream consumers. | Flow information does not exist yet. |
| C / NFR-02 | CPU & memory (now + 10-min avg/peak) | **PASS** | Now (idle): discovery 0% / 97.6 MiB, api 0% / 53.1 MiB. 10-min sample (40×15s): **discovery avg 2.22% CPU, peak 3.6%; RSS avg 95.7 MiB, peak 96.0 MiB. api avg 0.09% CPU, peak 0.1%; RSS 51.9 MiB.** 2-hour endurance test NOT run (command below). | Endurance (2h) not run — by request. |
| C / NFR-03 | Restart= / auto-recovery | **PARTIAL** | `assas-discovery` and `assas-api`: `Restart=on-failure`, `RestartUSec=5s`. `assas-capture`: `Restart=no` (correct — `Type=oneshot`, `RemainAfterExit=yes`). | Recovery test (kill → measure restart time) NOT run — awaiting your approval. |
| C / NFR-05 | No pcaps; no external raw-packet egress; DNS needles only; retention configured | **PASS** | `sniff(store=False)` at both capture call sites; **no `*.pcap` under /home/assas**; `.gitignore` has `*.pcap`. Probes are LAN-scoped only: SSDP mcast `239.255.255.250`, mDNS unicast to local `ip:5353`, NBNS `ip:137`, `arp-scan --localnet`; UPnP/AP `urllib` fetches target local device/AP IPs. DB scan: **0 full query-names stored**; needles only (e.g. `mDNS query (_companion-link._tcp)`). Retention 30d. | Disclosure: one pcap exists in the ephemeral session scratchpad (`/tmp/.../scratchpad/mdns.pcap`) — created by *this audit's* validation capture, not by the appliance. |
| C / NFR-07 | Docs cover setup/config/interfaces per component | **PARTIAL** | `README.md` (100 L: layout, components, tests, services, network setup), `docs/API_CONTRACT.md` (217 L: endpoints, mDNS, limitations), `docs/database-schema.md` (54 L: all 28 columns), `appliance/avahi/README.md` (30 L). | Backlog/PBIs undocumented; app↔API integration (base URL, endpoint paths, mDNS) not documented for the Flutter dev. |
| D | Docs vs live: README / API_CONTRACT / database-schema | **PASS** | `database-schema.md` **28/28 columns match** live `PRAGMA table_info` (no drift). `API_CONTRACT` endpoints exactly match live routes (`/healthz`,`/devices`,`/devices/{mac}`,`/summary`). README management=eth0, IPv4-only, mDNS all match live. | The three named docs are consistent with the live system. The inconsistency is in **app code** (`/api/*`, `10.0.2.2`) vs the contract — see A.5. |

## Prioritised gap list (with estimated effort)

1. **[HIGH] Flutter app ↔ live API is broken (A.5, D).** App calls non-existent `/api/devices` & `/api/system/health` on a hardcoded emulator IP `10.0.2.2:8000`; no mDNS. This is the single blocker for the Sprint 0 GUI deliverable. **Effort: M (~2–3 days)** — repoint to `/devices` + `/healthz`, resolve base URL via mDNS (`_assas._tcp`, fallback `assas-pi.local:8000`), wire device-list + device-detail screens to the real schema. Owned by the Flutter dev; backend already ready.
2. **[HIGH] PBI-20 flow information not started (B).** No flow/export exists. If in Sprint 0 scope, this is net-new. **Effort: L (design + build, multi-day)** — decide scope (per-connection records? export format?) before committing.
3. **[MED] PBIs not version-controlled (B, NFR-07).** PBI-04/06/18/19/20 acceptance criteria are nowhere in the repo, so 3 of 5 cannot be audited literally. **Effort: S (~0.5 day)** — add `docs/backlog.md` with each PBI's acceptance criteria; then re-audit 04/06/18.
4. **[MED] A.4 evidence-source observability.** Non-tagged sources (SSDP/UPnP/DHCP/Nmap) aren't visible in the journal "fired" list. **Effort: S** — add consistent `[EVIDENCE]` tags if journal-based audit is desired.
5. **[LOW] NFR-03 recovery test not run.** Config is correct (`on-failure`/5s). **Effort: XS (~15 min)** — needs your go-ahead to kill the service and measure restart time.
6. **[LOW] NFR-02 2-hour endurance not run.** 10-min sample is well within budget (peak 3.6% CPU). **Effort: XS (unattended 2h)** — command below.

## Considered and dropped

- **Passive DHCPv6 classification (UDP 546/547).** Implemented and unit-tested: Client FQDN
  (option 39) → hostname pipeline, Vendor Class (option 16) → `VENDOR_CLASS_HINTS`; DUID never
  read or stored. **Dropped** because home routers and phone hotspots hand out IPv6 via SLAAC,
  not DHCPv6 — our network advertises `RA M=0 O=0`, so **no device ever sends DHCPv6** and the
  code cannot be validated against real traffic. Not merged. **Recoverable** from tag
  `archive/dhcpv6` (`git checkout archive/dhcpv6`) if a DHCPv6-serving network appears.

## Still parked (not dropped)

- **Windows + Linux/Android TCP SYN fingerprint buckets** — branch `pending/syn-fp-windows-linux`.
  Kept for later: to be ported onto the `appliance/` + `classification.py` layout and validated
  live (the Dell's Windows SYNs never reached eth1, so only the Apple bucket is ground-truth).

## Commands to run the two deferred tests yourself

**NFR-02 — 2-hour CPU/mem endurance** (samples every 30s → `~/assas_nfr02_2h.txt`):
```bash
DPID=$(systemctl show assas-discovery -p MainPID --value); APID=$(systemctl show assas-api -p MainPID --value)
top -b -d 30 -n 240 -p "$DPID" -p "$APID" > ~/assas_nfr02_2h.txt 2>&1 &
```

**NFR-03 — recovery test** (⚠️ kills the running daemon; run only when you're ready):
```bash
sudo systemctl kill -s SIGKILL assas-discovery
sleep 8; systemctl show assas-discovery -p ActiveState,SubState,NRestarts,ExecMainStartTimestamp --no-pager
```
Restart time ≈ (new `ExecMainStartTimestamp`) − (kill time); config schedules retry after 5s.
