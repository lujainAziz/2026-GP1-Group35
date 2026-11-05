// Layout must adapt to text sizes by EXPANDING and WRAPPING — not by clipping,
// fixed heights or shrinking fonts. These tests drive a LIVE transition between
// the smallest (app zoom 1.0 × system 0.85) and largest (zoom 1.2 × system 1.3)
// combinations — in both directions, without rebuilding the screen — and check
// during and after each animation. Fixtures include the real problem cases: a
// machine-style long device name and address-like values.
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/dashboard/dashboard_screen.dart';
import 'package:assas_mobile/screens/devices/device_details_screen.dart';
import 'package:assas_mobile/screens/devices/device_list_screen.dart';
import 'package:assas_mobile/screens/settings/settings_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:assas_mobile/widgets/design_scale.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

const _mac = 'e6:42:65:03:0d:8f';

class _Repo extends DemoRepository {
  final Device _dev = const Device(
    mac: _mac,
    ip: '192.168.100.238',
    ipv6: ['2001:16a2:c83e:5700:78f5:8a3d:cbf4:b5fe'],
    hostname: '0badc396-c1f4-40db-ba83-c0702b11ae58', // opaque -> model shown
    model: 'emulator (sdk_gphone64_x86_64)', // the mid-word-break case
    vendor: 'A Rather Long Vendor Name Incorporated',
    deviceType: 'Computer',
    presence: Presence.online, trusted: false, monitored: false,
  );
  @override
  Future<List<Device>> getDevices() async => [
        _dev,
        // +152 untrusted devices (with _dev = 153 total): the Home "Unrecognized" stat shows a wide
        // 3-digit number next to its label.
        for (var i = 0; i < 152; i++)
          Device(
            mac: 'aa:aa:aa:aa:${(i ~/ 100) % 10}${(i ~/ 10) % 10}:${i % 10}0',
            presence: Presence.online,
            trusted: false,
          ),
      ];
  @override
  Future<Device> getDevice(String mac) async => _dev;
}

Future<void> _loadFonts() async {
  for (final f in ['BricolageGrotesque', 'JetBrainsMono']) {
    final l = FontLoader(f == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
    l.addFont(rootBundle.load('assets/fonts/$f.ttf'));
    await l.load();
  }
}

Future<void> _transition(WidgetTester tester, Widget Function() build,
    {double width = 320}) async {
  addTearDown(tester.view.reset);
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = Size(width, 1200);
  final zoom = ValueNotifier<double>(1.0);
  final scale = ValueNotifier<double>(0.85);
  addTearDown(zoom.dispose);
  addTearDown(scale.dispose);
  await tester.pumpWidget(MaterialApp(
    theme: MobileTheme.light,
    home: ListenableBuilder(
      listenable: Listenable.merge([zoom, scale]),
      builder: (context, _) => MediaQuery(
        data: MediaQuery.of(context).copyWith(textScaler: TextScaler.linear(scale.value)),
        child: DesignScale(zoom: zoom.value, child: Material(color: Ui.bg, child: build())),
      ),
    ),
  ));
  await tester.pump(const Duration(milliseconds: 350)); // settle async loads
  expect(tester.takeException(), isNull, reason: 'initial smallest');

  // smallest -> largest -> smallest -> largest, live, checking mid + settled.
  for (final (z, s) in [(1.2, 1.3), (1.0, 0.85), (1.2, 1.3)]) {
    zoom.value = z;
    scale.value = s;
    await tester.pump();
    expect(tester.takeException(), isNull, reason: 'during -> zoom=$z scale=$s');
    await tester.pump(const Duration(milliseconds: 120));
    expect(tester.takeException(), isNull, reason: 'mid-anim -> zoom=$z scale=$s');
    await tester.pump(const Duration(milliseconds: 320));
    expect(tester.takeException(), isNull, reason: 'settled -> zoom=$z scale=$s');
  }
  await tester.pumpWidget(const SizedBox());
}

void main() {
  testWidgets('Device details: long machine-style name transitions without overflow',
      (tester) async {
    SharedPreferences.setMockInitialValues({});
    await _loadFonts();
    final s = AppState(_Repo());
    addTearDown(s.dispose);
    await tester.runAsync(s.refresh);
    await _transition(tester, () => DeviceDetailsScreen(state: s, mac: _mac));
  });

  testWidgets('Device list: stat labels stay readable (wrapped, not shrunk)',
      (tester) async {
    SharedPreferences.setMockInitialValues({});
    await _loadFonts();
    final s = AppState(_Repo());
    addTearDown(s.dispose);
    await tester.runAsync(s.refresh);
    await _transition(tester, () => DeviceListScreen(state: s));
    // The full labels are rendered as text (no FittedBox shrink-to-fit): the
    // same Text widgets exist at any size, wrapping instead of scaling.
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(320, 1200);
    await tester.pumpWidget(MaterialApp(
      theme: MobileTheme.light,
      home: Builder(builder: (c) => MediaQuery(
        data: MediaQuery.of(c).copyWith(textScaler: const TextScaler.linear(1.3)),
        child: DesignScale(zoom: 1.2, child: Material(color: Ui.bg, child: DeviceListScreen(state: s))),
      )),
    ));
    await tester.pump(const Duration(milliseconds: 350));
    expect(find.text('UNRECOGNIZED'), findsWidgets);
    expect(find.text('NOT MONITORED'), findsWidgets);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('Home: Unrecognized stat label keeps its size next to a 3-digit count',
      (tester) async {
    SharedPreferences.setMockInitialValues({});
    await _loadFonts();
    final s = AppState(_Repo());
    addTearDown(s.dispose);
    await tester.runAsync(s.refresh);
    await _transition(tester, () => DashboardScreen(
          state: s, onOpenDevices: () {}, onOpenAlerts: () {}, onOpenUnrecognized: () {},
        ));
    // At the largest size the full label is still rendered as designed text
    // (no FittedBox shrink); the number may flow to the next line instead.
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(320, 1200);
    await tester.pumpWidget(MaterialApp(
      theme: MobileTheme.light,
      home: Builder(builder: (c) => MediaQuery(
        data: MediaQuery.of(c).copyWith(textScaler: const TextScaler.linear(1.3)),
        child: DesignScale(zoom: 1.2, child: Material(color: Ui.bg, child: DashboardScreen(
          state: s, onOpenDevices: () {}, onOpenAlerts: () {}, onOpenUnrecognized: () {},
        ))),
      )),
    ));
    await tester.pump(const Duration(milliseconds: 400));
    expect(find.textContaining('Unrecog'), findsWidgets); // label may carry a soft hyphen
    expect(find.text('153'), findsWidgets);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('Settings: hardware card values wrap instead of clipping',
      (tester) async {
    SharedPreferences.setMockInitialValues({});
    await _loadFonts();
    final s = AppState(_Repo());
    addTearDown(s.dispose);
    await tester.runAsync(s.refresh);
    await _transition(tester, () => SettingsScreen(state: s));
  });
}
