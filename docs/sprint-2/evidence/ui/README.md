# Mobile UI — Sprint 2 screens (screenshots for review)

Screenshots generated headless via golden capture (`app/mobile/test/ui_goldens_test.dart`,
`flutter test --update-goldens --dart-define=GOLDENS=true`) at 390×844 @2x, default font:
- `alerts-tab.png` — Alerts list.
- `alert-details.png` — Alert details.
- `device-alerts.png` — Device details (incl. the device's alerts).

## UI changes in this pass (design/identity + texts preserved)
- **Alerts tab:** hero now shows the title **"Threat Alerts"** instead of a large open-alerts count.
- **Alert details:** Occurrences, First/Last seen, Rule ID and ports are **hidden** (kept in the DB
  and API); only the alert time (top), device (shown once as a tappable pill → device details), and
  **Source/Destination IP** remain. Source/Destination IP are **tap-to-copy**.
- **Device details:** IP, IPv6 and MAC are **tap-to-copy**; long IPv6 wraps at `:`/`.` groups (no
  clipping); rename preserved.
- **Titles resized** (device-details and alert-details) so long names/signatures are readable at the
  smallest font setting; **IP style** reduced so IPv6 fits.
- **Device display name:** an opaque machine-identifier hostname (UUID / long hex / long vowel-less
  token) shows **"Unknown device"** while the MAC and rename stay intact; real/user names unchanged.
- Later-sprint surfaces stay hidden (explanations, Review/Resolve, risk, home count, severity
  badges, 7″ display count).

## Tests (`flutter test`, `flutter analyze` clean)
- `test/detail_overflow_test.dart` — Alerts list, alert details, device details, device list,
  settings: **no overflow at smallest / default / largest font** (0.85 / 1.0 / 1.3) and widths
  320/400, with long names + full IPv6; hidden fields asserted absent; device-name heuristic.
- Accessibility preserved: screens use `MediaQuery.textScaler` (no fixed text-scale override) and
  scroll; nothing disables font scaling.

**Status: owner visual sign-off still required** before the Mobile Alert Screens are marked
visually verified.
