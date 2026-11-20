// Sprint 2 UI review: the alert-details and device-details screens must stay
// readable — no overflow/clipping — at the smallest, default, and largest
// supported font sizes, with long device names and full IPv6 addresses.
// Also checks the opaque-hostname -> "Unknown device" display rule, the
// repeated-detection rows (count, first/last detected) and that the rule ID
// and ports stay hidden.
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/alerts/alert_details_screen.dart';
import 'package:assas_mobile/screens/alerts/alert_list_screen.dart';
import 'package:assas_mobile/screens/devices/device_details_screen.dart';
import 'package:assas_mobile/screens/devices/device_list_screen.dart';
import 'package:assas_mobile/screens/pairing/pairing_screen.dart';
import 'package:assas_mobile/screens/settings/settings_screen.dart';
import 'package:assas_mobile/widgets/splash_gate.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:assas_mobile/widgets/design_scale.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

const _mac = 'e6:42:65:03:0d:8f';
const _ipv6 = '2001:16a2:dea6:2200:79ee:14d2:e191:965e';
const _opaqueHost = 'a7f3e9c1b2d84f60a7f3e9c1b2d84f60'; // 32 hex -> machine id
const _longTitle =
    'ET FILE_SHARING Commonly Abused File Sharing Domain (wasabisys .com) in TLS SNI';
// Longest reviewed explanation (policy-violation) to exercise wrapping.
const _longExplanation =
    'Activity that puts privacy or security at serious risk, such as sending a password '
    'without encryption or using anonymity networks. It is not always an attack, but it '
    'should not happen without a reason. Check whether this activity is expected on this device.';

class _FixtureRepo extends DemoRepository {
  final Device _dev = const Device(
    mac: _mac, ip: '192.168.100.238', ipv6: [_ipv6], hostname: _opaqueHost,
    vendor: 'A Rather Long Vendor Name Incorporated', deviceType: 'Computer',
    presence: Presence.online, trusted: true, monitored: true,
  );
  @override
  Future<List<Device>> getDevices() async => [_dev];
  @override
  Future<Device> getDevice(String mac) async => _dev;
  @override
  Future<List<SecurityAlert>?> getAlerts({int? limit}) async => [
        SecurityAlert.fromApi({
          'id': '1', 'kind': 'threat', 'title': _longTitle,
          'display_title': 'Unsafe activity', 'explanation': _longExplanation,
          'classtype': 'policy-violation', 'device_role': 'source',
          'device_mac': _mac, 'device_name': 'Unknown device',
          'time': '2026-11-04T10:00:00', 'severity': 'medium', 'state': 'new',
          'source_ip': '192.168.100.238', 'destination_ip': _ipv6,
          'src_port': 443, 'dst_port': 51000, 'rule_id': '2046657',
          'occurrence_count': 40,
          'first_event_time': '2026-11-04T09:00:00',
          'last_event_time': '2026-11-04T10:00:00',
        }),
      ];
}

Future<void> _loadFonts() async {
  for (final f in ['BricolageGrotesque', 'JetBrainsMono']) {
    final loader = FontLoader(f == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
    loader.addFont(rootBundle.load('assets/fonts/$f.ttf'));
    await loader.load();
  }
}

Future<AppState> _state(WidgetTester tester) async {
  final s = AppState(_FixtureRepo());
  addTearDown(s.dispose);
  await tester.runAsync(s.refresh);
  return s;
}

// Exercises the app's real font-scaling range: the app "Text size" setting
// (DesignScale zoom, max 1.2) combined with the system font scale (textScaler,
// clamped to 0.85..1.3 in main.dart). The true maximum is zoom 1.2 × scale 1.3
// at the narrowest width.
Future<void> _pumpAll(WidgetTester tester, Widget Function() build) async {
  addTearDown(tester.view.reset);
  for (final zoom in [1.0, 1.2]) {                 // app Text-size setting (min..max)
    for (final scale in [0.85, 1.0, 1.3]) {        // system font scale (clamped range)
      for (final width in [320.0, 400.0]) {
        tester.view.devicePixelRatio = 1;
        tester.view.physicalSize = Size(width, 900);
        await tester.pumpWidget(MaterialApp(
          theme: MobileTheme.light,
          home: Builder(builder: (context) => MediaQuery(
                data: MediaQuery.of(context).copyWith(textScaler: TextScaler.linear(scale)),
                // Material ancestor for screens normally hosted in the shell
                // Scaffold (e.g. the device list); detail screens bring their own.
                child: DesignScale(zoom: zoom, child: Material(color: Ui.bg, child: build())),
              )),
        ));
        await tester.pump(const Duration(milliseconds: 60));
        expect(tester.takeException(), isNull, reason: 'first build zoom=$zoom scale=$scale width=$width');
        // Settle the async settings load (DemoRepository delays ~250ms) and any
        // implicit animations, then check the resting layout too.
        await tester.pump(const Duration(milliseconds: 300));
        expect(tester.takeException(), isNull, reason: 'settled zoom=$zoom scale=$scale width=$width');
        // Dispose the subtree so each combo is an independent first build. Without
        // this the loop reuses the same element and implicit (AnimatedContainer)
        // width animations carry over from the previous, wider canvas — a mid-
        // animation overflow that no real first-display or text-size change can
        // produce (box widths depend on canvas width, not on the selected size).
        await tester.pumpWidget(const SizedBox());
      }
    }
  }
}

void main() {
  testWidgets('Alerts list: no overflow at all font sizes', (tester) async {
    await _loadFonts();
    final s = await _state(tester);
    await _pumpAll(tester, () => AlertListScreen(state: s));
  });

  testWidgets('Alert details: no overflow; detection rows shown; ports hidden; device line once', (tester) async {
    await _loadFonts();
    final s = await _state(tester);
    // Both states of the Signal details section (collapsed by default).
    await _pumpAll(tester, () => AlertDetailsScreen(state: s, alertId: '1'));
    await _pumpAll(tester, () => AlertDetailsScreen(state: s, alertId: '1', signalDetailsOpen: true));
    // re-pump once at default to assert content
    tester.view.physicalSize = const Size(400, 900);
    await tester.pumpWidget(MaterialApp(theme: MobileTheme.light,
        home: DesignScale(zoom: 1, child: AlertDetailsScreen(state: s, alertId: '1', signalDetailsOpen: true))));
    await tester.pump(const Duration(milliseconds: 60));
    // SpecList uppercases labels. Repeated detections: count + first/last.
    for (final f in ['DETECTIONS', 'FIRST DETECTED', 'LAST DETECTED']) {
      expect(find.text(f), findsOneWidget, reason: '$f should be shown');
    }
    for (final f in ['RULE ID', 'OCCURRENCES', 'FIRST SEEN', 'LAST SEEN', 'DEVICE']) {
      expect(find.text(f), findsNothing, reason: '$f should not be shown');
    }
    expect(find.text('40'), findsOneWidget); // occurrence_count
    // "{device} · {first detection time}" under the title (first = 09:00).
    expect(find.textContaining('· 4 Nov, 9:00 AM'), findsOneWidget);
    // ports hidden: value shows IP only, never ip:port
    expect(find.textContaining(':51000'), findsNothing);
    expect(find.textContaining(':443'), findsNothing);
    expect(find.text('SOURCE IP'), findsOneWidget);
    expect(find.text('DESTINATION IP'), findsOneWidget);
    // Plain title as heading; original rule name in the details; the rule ID
    // is never shown (team decision).
    expect(find.text('Unsafe activity'), findsOneWidget);
    expect(find.text('RULE'), findsOneWidget);
    expect(find.text(_longTitle), findsOneWidget);
    expect(find.textContaining('2046657'), findsNothing);
    // Explanation + device role line.
    expect(find.text(_longExplanation), findsOneWidget);
    expect(find.text('This device started the activity.'), findsOneWidget);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('Device details: no overflow with IPv6 + opaque hostname', (tester) async {
    await _loadFonts();
    final s = await _state(tester);
    await _pumpAll(tester, () => DeviceDetailsScreen(state: s, mac: _mac));
  });

  testWidgets('Device list: no overflow at all font sizes', (tester) async {
    await _loadFonts();
    final s = await _state(tester);
    await _pumpAll(tester, () => DeviceListScreen(state: s));
  });

  testWidgets('Settings: no overflow at all font sizes', (tester) async {
    await _loadFonts();
    final s = await _state(tester);
    await _pumpAll(tester, () => SettingsScreen(state: s));
  });

  // Pairing screen (QR scan screen itself needs the camera plugin, so it is
  // reviewed statically; its layout is just a BackPill + kicker title + a fixed
  // 240px frame that fits the min canvas).
  testWidgets('Pairing: no overflow at all font sizes', (tester) async {
    await _loadFonts();
    await _pumpAll(tester, () => const PairingScreen());
  });

  testWidgets('Splash: no overflow at all font sizes', (tester) async {
    await _loadFonts();
    await _pumpAll(tester, () => const SplashGate(child: SizedBox()));
  });

  test('opaque hostname falls back to Unknown device (MAC + rename unaffected)', () {
    const d = Device(mac: _mac, hostname: _opaqueHost, presence: Presence.online, trusted: true);
    expect(d.displayName, 'Unknown device');
    expect(d.macLabel, _mac.toUpperCase());
    const named = Device(mac: _mac, hostname: _opaqueHost, userName: 'Dad laptop',
        presence: Presence.online, trusted: true);
    expect(named.displayName, 'Dad laptop'); // user name always wins
    const real = Device(mac: _mac, hostname: 'Living-Room-TV', presence: Presence.online, trusted: true);
    expect(real.displayName, 'Living-Room-TV'); // real names kept
  });
}
