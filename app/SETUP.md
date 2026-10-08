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

## Display full screen on the Pi
In `display/linux/runner/my_application.cc` replace
`gtk_window_set_default_size(window, 1280, 720);`
with
`gtk_window_fullscreen(window);`
