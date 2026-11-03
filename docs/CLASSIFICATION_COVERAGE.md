# Classification coverage expansion — 2026-10-16

## Research and chosen integration

- [Nmap repository](https://github.com/nmap/nmap): integrate the already-used
  executable's service fingerprinting through its
  [XML interface](https://nmap.org/book/output-formats-xml-output.html).
  [Version detection](https://nmap.org/book/man-version-detection.html) provides
  service-derived device classes beyond the old port-number guesses.
- [Satori](https://github.com/xnih/satori) and
  [p0f](https://github.com/p0f/p0f) were examined as passive fingerprint sources.
  Their OS fingerprints are not automatically phone/tablet/hardware identities.
  No code or fingerprint files from either project were imported.

Nmap stays an externally installed dependency; no Nmap code or database is
vendored. Its installed package supplies the fingerprints and their updates.
No fingerprint API, account, telemetry or cloud upload was added.

## Implemented behavior

- Unknown/general devices and devices with a below-service-strength guess now use `-sV --version-light` with XML output,
  numeric addresses, TCP connect scanning, 19 explicit TCP ports and a
  30-second host budget (60-second subprocess timeout).
- At most two Nmap subprocesses run concurrently. Existing three-attempt
  retry limit, cooldown, LAN scope, current-IP checks and persisted Active
  identification switch still apply. The target is checked again after waiting
  for a slot and after the scan. Turning the switch off rejects the result;
  it does not terminate an already-running Nmap subprocess mid-scan.
- Only `method=probed`, confidence 8–10, and an explicitly supported device
  class produce service evidence. Port-table names, OS names, generic products,
  unknown classes, closed/filtered ports and unrelated hosts do not.
- Fifteen external device classes map into existing ASSAS categories. Examples:
  printers, routers, access points, switches, storage, media devices, consoles,
  network infrastructure and power devices. Webcams use the broad surveillance
  label; they are not automatically security cameras.
- All candidates are merged; contradictory equal-strength results stay Unknown.
  The existing port fallback is retained below service evidence.
- Nmap's default exclusion of printer port 9100 from version probes remains:
  `--allports` is never used. No aggressive scan or script set is requested.
- Manufacturer lookup fills gaps in arp-scan's registry using installed
  `/usr/share/nmap/nmap-mac-prefixes` or its `/usr/local/share` equivalent.
  Primary entries and longest-prefix lookup are preserved; randomized MACs
  still do not acquire a manufacturer from their random prefix.
- The Pi's arp-scan registry (`/usr/share/arp-scan/ieee-oui.txt`) shipped with
  the OS was dated October 2024 and missed newer prefixes (for example
  `60:FF:9E`, AzureWave). On 24 Oct 2026 it was refreshed with `get-oui`
  (47,399 to 51,942 entries). On a new Pi: back up the file, run
  `cd /tmp && get-oui -v -f /tmp/ieee-oui-new.txt`, copy the result over
  `/usr/share/arp-scan/ieee-oui.txt`, then restart `assas-discovery`.

## Verification and deployment

368 backend tests passed, including XML parsing, all supported class mappings,
low-confidence/port-table rejection, contradictory evidence, stale-target and
disabled-setting rejection, DB integration and registry fallback.

The Nmap binary is not available on this Windows test host, so subprocess
results were fixture-based. Live Raspberry Pi network identification has not
been measured and no percentage coverage claim is made.

On the Pi, install/update the distribution's `nmap` package if missing and
check `nmap --version`, then restart discovery with this code. Enable Active
identification in ASSAS to use the optional probes. Devices need to expose
enough traffic or reachable services; a silent or filtered device can still
remain Unknown. Existing strongly classified devices are not rescanned by this
fallback. Vendor, hostname and port guesses below the service evidence score
remain eligible, so a weak specific label cannot block better identification. IPv6 active probing remains outside this change.

No GitHub push or Raspberry Pi deployment was performed.
