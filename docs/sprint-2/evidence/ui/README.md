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

Status: **pending owner review** (do not mark Part D visually verified until then).
