# Mobile UI screenshots (Part D) — pending capture on a dev machine

The Pi session is headless, so the three Sprint-2 screens are captured on a dev
machine/emulator and reviewed by the sprint owner before Part D is signed off.

Capture these from `app/mobile` (demo or paired to the live appliance):

1. **Alerts tab** — the Threat Alerts list: title, severity, affected device, last
   event time, occurrence count (`N×`), newest first. (No All/Open/Resolved tabs.)
2. **Alert details** — title, severity, device (tappable → device details), first &
   last seen, occurrences, source/destination address:port, rule ID. (No
   "What happened" explanation block; no Review/Resolve.)
3. **Device details → alerts** — the device's alerts in place of the old
   "Coming soon" section.

How:
```
cd app/mobile
flutter run            # on a connected device/emulator, or
flutter run -d chrome  # web
```
Save PNGs here as `alerts-tab.png`, `alert-details.png`, `device-alerts.png`.

## Supplying alert data for the screenshots — isolated, never touch live logs/DB
Do **not** write test data into the live pipeline. Specifically: do **not** run `suricata -r` into
`/var/log/suricata/eve.json`, and do **not** overwrite the live `eve.json`, rotated eve files, or
`assas.db`. Use one of:
- **Demo mode (simplest):** point the app at `DemoRepository` (the app's built-in sample alerts); no
  appliance data is touched.
- **Isolated test backend:** run a throwaway ingester + API against a separate DB and eve path, e.g.
  `suricata -r <pcap> -l <tmpdir>` → `tmpdir/eve.json`, then run `alerts.py`/`api.py` with
  `ASSAS_EVE_PATH=<tmpdir>/eve.json` and `ASSAS_DB_PATH=/tmp/assas-ui-test.db`. This leaves
  `/var/log/suricata/` and the production `assas.db` untouched.

Either way the live appliance services and logs are not modified for UI capture.

Status: **pending owner review** (do not mark the Mobile Alert Screens visually verified until then).
