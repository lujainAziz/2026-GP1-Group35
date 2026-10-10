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

Comment the DEMO block, uncomment the REAL BACKEND block. Nothing else changes.
The list of endpoints the app expects is at the top of
`packages/assas_core/lib/data/api_repository.dart`.

## First time
1. Copy the old images: `app/assets/images/` -> `app/mobile/assets/images/` and `app/display/assets/images/`
   (uses `logo_eye.png`).
2. Generate the platform folders:
   ```
   cd app/mobile  && flutter create --platforms=android,ios .  && rm -f test/widget_test.dart
   cd app/display && flutter create --platforms=linux .        && rm -f test/widget_test.dart
   ```
3. `flutter pub get` in `mobile/` and in `display/`, then `flutter analyze`.

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
read-only status screen; **DEMO is the active data source** (the real-backend
switch in `display/lib/config/data_source.dart` is intentionally left for later —
not enabled here).

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

### Autostart (labwc)
The labwc session runs `~/.config/labwc/autostart` on login. It contains exactly
one line that launches the release binary:
```
/home/assas/assas/app/display/build/linux/arm64/release/bundle/assas_app &
```
No systemd service is used. After reboot: autologin -> labwc session -> this line
opens the display fullscreen. The physical HDMI panel must be connected and active.

### Temporarily disable autostart (troubleshooting)
Comment the line out (prefix with `#`) or rename the file, then restart the
session / reboot:
```
mv ~/.config/labwc/autostart ~/.config/labwc/autostart.disabled
```
Restore by moving it back. To run the kiosk by hand instead, launch the release
binary directly from the graphical session.
