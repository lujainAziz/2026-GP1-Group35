# Mobile UI — Sprint 2 screens (screenshots for review)

These screenshots show the Sprint 2 interface; later interface changes are shown in the project report.

Screenshots generated headless via golden capture (`app/mobile/test/ui_goldens_test.dart`,
`flutter test --update-goldens --dart-define=GOLDENS=true`). Default-font set at 390×844 @2x:
- `alerts-tab.png` — Alerts list.
- `alert-details.png` — Alert details.
- `device-alerts.png` — Device details (incl. the device's alerts).

Stress captures at the **true maximum font** (app Text-size zoom 1.2 × system scale 1.3) on the
**narrowest** canvas (320 wide), to confirm big titles reflow without clipping or mid-word breaks:
- `settings-narrow.png` — Settings ("Control center." two-line title; Aa text-size chips; cards).
- `pairing-narrow.png` — Pairing hero ("Let ASSAS / watch your / network." — wraps on spaces only).
- `splash-narrow.png` — Splash (eye + wordmark; wordmark fades in after ~950 ms, so the capture at
  360 ms shows the eye — the wordmark/tagline bounds are covered by the overflow test below).

## Whole-app review — screens checked and limitations
Reviewed for font sizing, long titles, wrapping, spacing, alignment and overflow at the full
supported range (app zoom 1.0–1.2 × system scale 0.85–1.3, widths 320/400):
- **Checked headlessly (overflow test + goldens):** Alerts list, Alert details, Device details,
  Device list, Settings, Pairing, Splash.
- **Settings title fix:** "Control center." is wrapped in a `FittedBox(scaleDown)` so it shrinks to
  fit at max zoom instead of breaking mid-word.
- **Reviewed statically (not headless-pumpable):** **QR scan screen** uses the `mobile_scanner`
  camera plugin (no camera in a headless test). Its layout is a `BackPill` + short kicker title and a
  fixed 240 px frame centered on a canvas that is ≥296 px at the smallest supported width, so it
  cannot overflow; verified by inspection of `qr_scan_screen.dart`.
- **Dashboard / Home summaries, severity badges, risk, 7″ display count:** intentionally remain
  **hidden** (later-sprint flags), so not part of this Sprint-2 visual pass.

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
  settings, **pairing, splash**: **no overflow across the full range** — app Text-size zoom
  {1.0, 1.2} × system scale {0.85, 1.0, 1.3} × widths {320, 400}, i.e. the true maximum 1.2×1.3 at
  the narrowest width (not assuming 1.3 is the ceiling). Long names + full IPv6; hidden fields
  asserted absent; device-name heuristic. Each combo is an independent first build (the loop disposes
  the subtree between combos) so no implicit animation carries over from a previous, wider canvas.
- Accessibility preserved: screens use `MediaQuery.textScaler` (no fixed text-scale override) and
  scroll; nothing disables font scaling.

**Status: owner visual sign-off still required** before the Mobile Alert Screens are marked
visually verified.
