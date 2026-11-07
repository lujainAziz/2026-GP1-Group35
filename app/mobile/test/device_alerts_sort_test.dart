// Device details: toggle this device's alerts between newest and most-severe.
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/devices/device_details_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:assas_mobile/widgets/ui_kit.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

const _mac = 'aa:bb:cc:dd:ee:ff';

SecurityAlert _mk(String id, Severity sev, int sec) => SecurityAlert(
      id: id,
      kind: AlertKind.threat,
      title: 'sig $id',
      deviceMac: _mac,
      deviceName: 'dev',
      time: DateTime(2026, 11, 7, 10).add(Duration(seconds: sec)),
      severity: sev,
      state: AlertState.newAlert,
    );

class _Repo extends DemoRepository {
  _Repo(this._list);
  final List<SecurityAlert> _list;
  @override
  Future<Device> getDevice(String mac) async => const Device(
        mac: _mac,
        ip: '192.168.1.5',
        hostname: 'thing',
        presence: Presence.online,
        trusted: false,
        monitored: false,
      );
  @override
  Future<List<SecurityAlert>?> getDeviceAlerts(String mac, {int? limit}) async =>
      _list.where((a) => a.deviceMac == mac).toList()
        ..sort((a, b) => b.time.compareTo(a.time));
}

Future<void> _loadFonts() async {
  for (final f in ['BricolageGrotesque', 'JetBrainsMono']) {
    final l = FontLoader(f == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
    l.addFont(rootBundle.load('assets/fonts/$f.ttf'));
    await l.load();
  }
}

List<String> _order(WidgetTester tester) =>
    tester.widgetList<TimelineAlertCard>(find.byType(TimelineAlertCard)).map((c) => c.alert.id).toList();

void main() {
  testWidgets('device alerts toggle newest <-> most severe', (tester) async {
    SharedPreferences.setMockInitialValues({});
    await _loadFonts();
    final state = AppState(_Repo([
      _mk('crit', Severity.critical, 0), // oldest
      _mk('low', Severity.low, 30),
      _mk('high', Severity.high, 60), // newest
    ]));
    addTearDown(state.dispose);
    addTearDown(tester.view.reset);
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(390, 1600);
    await tester.pumpWidget(MaterialApp(
      theme: MobileTheme.light,
      home: DeviceDetailsScreen(state: state, mac: _mac),
    ));
    // The screen has continuous animations (radar/pulse), so advance with
    // pump(duration) rather than pumpAndSettle.
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 500));

    // Newest first by default; the control sits inside the header row and is
    // neutral-coloured.
    expect(_order(tester), ['high', 'low', 'crit']);
    expect(
      find.descendant(
        of: find.widgetWithText(SectionHeader, 'Alerts for this device'),
        matching: find.text('Newest'),
      ),
      findsOneWidget,
    );
    expect(tester.widget<Text>(find.text('Newest')).style?.color, Ui.mute);

    // The pill is fixed to the wider option, so its width does not change on
    // toggle.
    final stack = find.descendant(
      of: find.widgetWithText(SectionHeader, 'Alerts for this device'),
      matching: find.byType(IndexedStack),
    );
    final widthNewest = tester.getSize(stack).width;

    await tester.tap(find.text('Newest'));
    await tester.pump(const Duration(milliseconds: 300));
    // Now Most severe: text switches and turns the active purple (Ui.acc).
    expect(find.text('Most severe'), findsOneWidget);
    expect(tester.widget<Text>(find.text('Most severe')).style?.color, Ui.acc);
    expect(_order(tester), ['crit', 'high', 'low']);
    expect(tester.getSize(stack).width, widthNewest); // same size both ways
    await tester.pumpWidget(const SizedBox());
  });
}
