# Assas app — setup

## Structure
```
app/
  packages/assas_core/   shared: theme, models, demo + real data layer
  mobile/                phone app (Android / iOS)
  display/               7-inch screen on the Pi (Linux)
```

## Demo <-> real backend
One file per app:
- `mobile/lib/config/data_source.dart`
- `display/lib/config/data_source.dart`

Both apps use the real backend by default. For a demo build, pass
`--dart-define=ASSAS_DEMO=true`; no source edits are needed.
The list of endpoints the app expects is at the top of
`packages/assas_core/lib/data/api_repository.dart`.

## First time
Platform folders and assets are already committed. Run `flutter pub get` in
`mobile/` and `display/`, then `flutter analyze` and `flutter test` in each app.
Do not regenerate platform folders as an installation step: they contain the
network permissions, secure-storage configuration and Linux kiosk setup.

## Phone permissions (needed for the real backend + QR)
- iOS `ios/Runner/Info.plist`:
  - `NSCameraUsageDescription` = "Used to scan the pairing QR code on your Assas device."
  - `NSLocalNetworkUsageDescription` = "Used to connect to your Assas device on your network."
  - `NSAppTransportSecurity` > `NSAllowsLocalNetworking` = YES
- Android `android/app/src/main/AndroidManifest.xml`:
  - inside `<application ...>` add `android:usesCleartextTraffic="true"` (the Pi API is http on the LAN)
  - `<uses-permission android:name="android.permission.INTERNET"/>`

## Run
```
cd app/mobile  && flutter run
cd app/display && flutter run -d linux
```

## Raspberry Pi kiosk (on-device 7-inch display)

The `display/` app runs natively on the Pi as a fullscreen Linux kiosk, launched
automatically by the existing labwc graphical session after autologin. It stays a
status screen. The default data source is the local API at
`http://127.0.0.1:8000`. Demo mode requires `--dart-define=ASSAS_DEMO=true`.

### Fullscreen
`display/linux/runner/my_application.cc` is committed to open fullscreen with no
window decorations: the header-bar branch is removed and the window uses
`gtk_window_set_decorated(window, FALSE)` + `gtk_window_fullscreen(window)`
(no title bar, no close control).

### Build on the Pi (one time)
- Flutter SDK lives at `/home/assas/flutter` (add `/home/assas/flutter/bin` to PATH
  or call the binary by full path).
- Linux build prerequisites (apt): `cmake`, `clang`, `libgtk-3-dev`
  (`ninja-build` + `pkg-config` are already present on Raspberry Pi OS).
- Then:
  ```
  cd /home/assas/assas/app/display
  /home/assas/flutter/bin/flutter pub get
  /home/assas/flutter/bin/flutter analyze
  /home/assas/flutter/bin/flutter build linux --release
  ```
- Release binary:
  `/home/assas/assas/app/display/build/linux/arm64/release/bundle/assas_app`

### Autostart and auto-restart (labwc, NFR-03)
The labwc session runs `~/.config/labwc/autostart` on login. It contains exactly
one line that launches the release binary through `lwrespawn` (`<repo>` is the
repository checkout on the Pi):
```
lwrespawn <repo>/app/display/build/linux/arm64/release/bundle/assas_app
```
`lwrespawn` restarts the app whenever it exits, so a crash brings the display
back without a manual step. No systemd service is used. After reboot: autologin
-> labwc session -> this line opens the display fullscreen. The physical HDMI
panel must be connected and active.

### Stop the display app on purpose
Killing only `assas_app` is not enough: `lwrespawn` starts it again. Stop
`lwrespawn` first, then the app:
```
pkill -f "lwrespawn.*assas_app"
pkill -x assas_app
```
The app comes back at the next login or reboot. To start it again in the
current session, run the autostart line from the graphical session.

### Auto-restart verification (2026-11-23, on the device)
- **Reboot test:** after `sudo reboot`, with no manual step, `lwrespawn` and
  `assas_app` were running and `assas-suricata` and `assas-discovery` were
  active. Pass.
- **Crash test:** `pkill -x assas_app` killed the app; 5 seconds later
  `assas_app` was running again with a new process ID. Pass.
- **Service kill test:** `assas-alerts`, `assas-api`, `assas-discovery` and
  `assas-suricata` had `Restart=on-failure` at the time of this test (now
  `Restart=always`, see below). `kill -9` of each service's
  MainPID: 60 seconds later all four were active again, `NRestarts` 0 -> 1 for
  each, all four back active in the same second, so back within seconds (the
  exact restart time was not measured). `assas-capture` has `Restart=no`, which
  is correct: it is `Type=oneshot` with `RemainAfterExit=yes` and no main
  process, and only sets the capture interface to promiscuous mode at boot. It
  was not part of the kill test and stayed active. Pass.
- **Change 2026-11-24:** `assas-alerts`, `assas-api`, `assas-discovery` and
  `assas-suricata` now use `Restart=always` (`RestartSec=5` unchanged). With
  `on-failure`, a service that exits with code 0, or is stopped by `SIGTERM`
  outside `systemctl`, is not restarted; an earlier test saw `assas-discovery`
  exit after a socket warning and stay down. `sudo systemctl stop <unit>` still
  stops the service. `assas-capture` and `assas-suricata-rotate`
  (`Type=oneshot`) are unchanged.

NFR-03 (display app and service auto-restart): verified.

### Temporarily disable autostart (troubleshooting)
Comment the line out (prefix with `#`) or rename the file, then restart the
session / reboot:
```
mv ~/.config/labwc/autostart ~/.config/labwc/autostart.disabled
```
Restore by moving it back. To run the kiosk by hand instead, launch the release
binary directly from the graphical session.
