// Screenshot generator for review (not a pixel-regression gate): run with
//   flutter test test/ui_goldens_test.dart --update-goldens --dart-define=GOLDENS=true
// which writes PNGs under test/goldens/. Skipped in normal runs so CI is not
// coupled to platform font rendering.
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/alerts/alert_details_screen.dart';
import 'package:assas_mobile/screens/alerts/alert_list_screen.dart';
import 'package:assas_mobile/screens/dashboard/dashboard_screen.dart';
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
import 'package:shared_preferences/shared_preferences.dart';

const _mac = '02:5a:01:00:0e:8f';
const _ipv6 = '2001:0db8:dea6:2200:79ee:14d2:e191:965e';

class _Repo extends DemoRepository {
  final Device _dev = const Device(
    mac: _mac, ip: '192.168.100.238', ipv6: [_ipv6], hostname: 'Living-Room-TV',
    vendor: 'Samsung', deviceType: 'Smart TV / Media Device',
    presence: Presence.online, trusted: true, monitored: true);
  final List<SecurityAlert> _list = [
    SecurityAlert.fromApi({
      'id':'1','kind':'threat','title':'ET FILE_SHARING Commonly Abused File Sharing Domain in TLS SNI',
      'display_title':'Notable activity (usually harmless)','classtype':'misc-activity','device_role':'source',
      'explanation':'Activity that is not normally harmful but is worth noting. Usually no action is needed unless it repeats often.',
      'device_mac':_mac,'device_name':'Living-Room-TV','time':'2026-11-04T10:04:00',
      'severity':'medium','state':'new','source_ip':'192.168.100.238','destination_ip':_ipv6,
      'src_port':443,'dst_port':51000,'rule_id':'2046657','occurrence_count':40,
      'first_event_time':'2026-11-04T09:00:00','last_event_time':'2026-11-04T10:04:00'}),
    SecurityAlert.fromApi({
      'id':'2','kind':'threat','title':'SURICATA STREAM excessive retransmissions',
      'display_title':'Unusual communication pattern','classtype':'protocol-command-decode','device_role':'target',
      'explanation':'Devices communicated in an unusual way. Often harmless, but can be part of an attack.',
      'device_mac':_mac,'device_name':'Living-Room-TV','time':'2026-11-04T09:40:00',
      'severity':'medium','state':'new','source_ip':_ipv6,'destination_ip':'192.168.100.238',
      'rule_id':'2210054','occurrence_count':4,
      'first_event_time':'2026-11-04T09:38:00','last_event_time':'2026-11-04T09:40:00'}),
  ];
  @override Future<List<Device>> getDevices() async => [_dev];
  @override Future<Device> getDevice(String mac) async => _dev;
  @override Future<List<SecurityAlert>?> getAlerts({int? limit}) async => _list;
  @override Future<int?> getOpenAlertCount() async => _list.where((a) => a.isUnresolved).length;
  @override Future<List<SecurityAlert>?> getDeviceAlerts(String mac, {int? limit}) async =>
      _list.where((a) => a.deviceMac == mac).toList();
  @override Future<SecurityAlert?> getAlertById(String id) async {
    for (final a in _list) {
      if (a.id == id) return a;
    }
    return null;
  }
}

Future<void> _shot(WidgetTester tester, String name, Widget Function(AppState) build) async {
  SharedPreferences.setMockInitialValues({}); // Alerts list reads a saved tab in initState
  for (final f in ['BricolageGrotesque', 'JetBrainsMono']) {
    final l = FontLoader(f == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
    l.addFont(rootBundle.load('assets/fonts/$f.ttf'));
    await l.load();
  }
  final s = AppState(_Repo());
  addTearDown(s.dispose);
  await tester.runAsync(s.refresh);
  addTearDown(tester.view.reset);
  tester.view.devicePixelRatio = 2;
  tester.view.physicalSize = const Size(390 * 2, 844 * 2);
  await tester.pumpWidget(MaterialApp(
    theme: MobileTheme.light,
    home: DesignScale(zoom: 1, child: Material(color: Ui.bg, child: build(s))),
  ));
  await tester.pump(const Duration(milliseconds: 400));
  await expectLater(find.byType(MaterialApp), matchesGoldenFile('goldens/$name.png'));
  await tester.pumpWidget(const SizedBox());
}

void main() {
  const gen = bool.fromEnvironment('GOLDENS');
  testWidgets('alerts-tab', (t) => _shot(t, 'alerts-tab', (s) => AlertListScreen(state: s)), skip: !gen);
  testWidgets('alert-details', (t) => _shot(t, 'alert-details', (s) => AlertDetailsScreen(state: s, alertId: '1')), skip: !gen);
  testWidgets('device-alerts', (t) => _shot(t, 'device-alerts', (s) => DeviceDetailsScreen(state: s, mac: _mac)), skip: !gen);
  testWidgets('device-list', (t) => _shot(t, 'device-list', (s) => DeviceListScreen(state: s)), skip: !gen);

  testWidgets('settings-narrow-maxzoom', (tester) async {
    SharedPreferences.setMockInitialValues({});
    for (final f in ['BricolageGrotesque', 'JetBrainsMono']) {
      final l = FontLoader(f == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
      l.addFont(rootBundle.load('assets/fonts/$f.ttf'));
      await l.load();
    }
    final s = AppState(_Repo());
    addTearDown(s.dispose);
    await tester.runAsync(s.refresh);
    addTearDown(tester.view.reset);
    tester.view.devicePixelRatio = 2;
    tester.view.physicalSize = const Size(320 * 2, 1100 * 2);
    await tester.pumpWidget(MaterialApp(theme: MobileTheme.light,
      home: DesignScale(zoom: 1.2, child: Material(color: Ui.bg, child: SettingsScreen(state: s)))));
    await tester.pump(const Duration(milliseconds: 60));
    await tester.pump(const Duration(milliseconds: 300)); // settle async settings load
    await expectLater(find.byType(MaterialApp), matchesGoldenFile('goldens/settings-narrow.png'));
    await tester.pumpWidget(const SizedBox());
  }, skip: !gen);

  // Hero-title screens at the narrowest width and max app zoom — verifies the
  // big multi-line titles reflow cleanly (no mid-word break) at the true max.
  Future<void> narrow(WidgetTester tester, String name, Widget child) async {
    SharedPreferences.setMockInitialValues({});
    for (final f in ['BricolageGrotesque', 'JetBrainsMono']) {
      final l = FontLoader(f == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
      l.addFont(rootBundle.load('assets/fonts/$f.ttf'));
      await l.load();
    }
    addTearDown(tester.view.reset);
    tester.view.devicePixelRatio = 2;
    tester.view.physicalSize = const Size(320 * 2, 844 * 2);
    await tester.pumpWidget(MaterialApp(theme: MobileTheme.light,
      home: Builder(builder: (ctx) => MediaQuery(
        data: MediaQuery.of(ctx).copyWith(textScaler: const TextScaler.linear(1.3)),
        child: DesignScale(zoom: 1.2, child: Material(color: Ui.bg, child: child))))));
    await tester.pump(const Duration(milliseconds: 60));
    await tester.pump(const Duration(milliseconds: 300));
    await expectLater(find.byType(MaterialApp), matchesGoldenFile('goldens/$name.png'));
    await tester.pumpWidget(const SizedBox());
  }

  testWidgets('pairing-narrow-maxzoom', (t) => narrow(t, 'pairing-narrow', const PairingScreen()), skip: !gen);
  testWidgets('splash-narrow-maxzoom', (t) => narrow(t, 'splash-narrow', const SplashGate(child: SizedBox())), skip: !gen);

  // Scaling comparison pairs (smallest vs largest supported text) with the
  // layout-adaptation problem cases: a machine-style long device name, an
  // address value in the settings hardware card, and the stat labels.
  Future<void> scalePair(WidgetTester tester, String name,
      Widget Function(AppState) build) async {
    for (final (tag, zoom, scale) in [('small', 1.0, 0.85), ('large', 1.2, 1.3)]) {
      SharedPreferences.setMockInitialValues({});
      for (final f in ['BricolageGrotesque', 'JetBrainsMono']) {
        final l = FontLoader(f == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
        l.addFont(rootBundle.load('assets/fonts/$f.ttf'));
        await l.load();
      }
      final s = AppState(_ScaleRepo());
      addTearDown(s.dispose);
      await tester.runAsync(s.refresh);
      addTearDown(tester.view.reset);
      tester.view.devicePixelRatio = 2;
      tester.view.physicalSize = const Size(390 * 2, 1000 * 2);
      await tester.pumpWidget(MaterialApp(
        theme: MobileTheme.light,
        home: Builder(builder: (c) => MediaQuery(
          data: MediaQuery.of(c).copyWith(textScaler: TextScaler.linear(scale)),
          child: DesignScale(zoom: zoom, child: Material(color: Ui.bg, child: build(s))),
        )),
      ));
      await tester.pump(const Duration(milliseconds: 400));
      await expectLater(find.byType(MaterialApp), matchesGoldenFile('goldens/$name-$tag.png'));
      await tester.pumpWidget(const SizedBox());
    }
  }

  testWidgets('scale-device-details', (t) => scalePair(t, 'scale-device-details',
      (s) => DeviceDetailsScreen(state: s, mac: _mac)), skip: !gen);
  testWidgets('scale-device-list', (t) => scalePair(t, 'scale-device-list',
      (s) => DeviceListScreen(state: s)), skip: !gen);
  testWidgets('scale-settings', (t) => scalePair(t, 'scale-settings',
      (s) => SettingsScreen(state: s)), skip: !gen);

  // Home stat card: the Unrecognized label next to a 3-digit count.
  Future<void> homePair(WidgetTester tester) async {
    for (final (tag, zoom, scale) in [('small', 1.0, 0.85), ('large', 1.2, 1.3)]) {
      SharedPreferences.setMockInitialValues({});
      for (final f in ['BricolageGrotesque', 'JetBrainsMono']) {
        final l = FontLoader(f == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
        l.addFont(rootBundle.load('assets/fonts/$f.ttf'));
        await l.load();
      }
      final s = AppState(_HomeScaleRepo());
      addTearDown(s.dispose);
      await tester.runAsync(s.refresh);
      addTearDown(tester.view.reset);
      tester.view.devicePixelRatio = 2;
      tester.view.physicalSize = const Size(390 * 2, 1000 * 2);
      await tester.pumpWidget(MaterialApp(
        theme: MobileTheme.light,
        home: Builder(builder: (c) => MediaQuery(
          data: MediaQuery.of(c).copyWith(textScaler: TextScaler.linear(scale)),
          child: DesignScale(zoom: zoom, child: Material(color: Ui.bg, child: DashboardScreen(
            state: s, onOpenDevices: () {}, onOpenAlerts: () {}, onOpenUnrecognized: () {},
          ))),
        )),
      ));
      await tester.pump(const Duration(milliseconds: 400));
      await expectLater(find.byType(MaterialApp), matchesGoldenFile('goldens/scale-home-$tag.png'));
      await tester.pumpWidget(const SizedBox());
    }
  }

  testWidgets('scale-home', homePair, skip: !gen);

  // Alerts tabs+filter header at the largest system font, filter inactive vs
  // active, 3-digit counts (like All 281 / Open 280 / Resolved 1).
  Future<void> alertsHeaderShot(WidgetTester tester, String name, {required bool active}) async {
    SharedPreferences.setMockInitialValues(
        active ? {'ui.alertSeverities': ['low', 'medium', 'high']} : {});
    for (final f in ['BricolageGrotesque', 'JetBrainsMono']) {
      final l = FontLoader(f == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
      l.addFont(rootBundle.load('assets/fonts/$f.ttf'));
      await l.load();
    }
    final s = AppState(_AlertsBulkRepo());
    addTearDown(s.dispose);
    await tester.runAsync(s.refresh);
    addTearDown(tester.view.reset);
    tester.view.devicePixelRatio = 2;
    tester.view.physicalSize = const Size(390 * 2, 430 * 2); // just the top of the screen
    await tester.pumpWidget(MaterialApp(
      theme: MobileTheme.light,
      home: Builder(
        builder: (ctx) => MediaQuery(
          data: MediaQuery.of(ctx).copyWith(textScaler: const TextScaler.linear(1.3)),
          child: DesignScale(zoom: 1.2, child: Material(color: Ui.bg, child: AlertListScreen(state: s))),
        ),
      ),
    ));
    await tester.pump(const Duration(milliseconds: 400));
    await expectLater(find.byType(MaterialApp), matchesGoldenFile('goldens/$name.png'));
    await tester.pumpWidget(const SizedBox());
  }

  testWidgets('alerts-filter-idle-large', (t) => alertsHeaderShot(t, 'alerts-filter-idle-large', active: false), skip: !gen);
  testWidgets('alerts-filter-active-large', (t) => alertsHeaderShot(t, 'alerts-filter-active-large', active: true), skip: !gen);
}

/// 288 alerts: 287 open (mostly Low, a couple High) + 1 resolved High, so
/// the tabs read All 288 / Open 287 / Resolved 1.
class _AlertsBulkRepo extends DemoRepository {
  final List<SecurityAlert> _list = [
    for (var i = 0; i < 285; i++)
      SecurityAlert(id: 'l$i', kind: AlertKind.threat, title: 'sig l$i', deviceName: 'dev',
          time: DateTime(2026, 11, 7, 10).add(Duration(seconds: 1000 - i)),
          severity: Severity.low, state: AlertState.newAlert),
    for (var i = 0; i < 2; i++)
      SecurityAlert(id: 'h$i', kind: AlertKind.threat, title: 'sig h$i', deviceName: 'dev',
          time: DateTime(2026, 11, 7, 11).add(Duration(seconds: i)),
          severity: Severity.high, state: AlertState.newAlert),
    SecurityAlert(id: 'done', kind: AlertKind.threat, title: 'sig done', deviceName: 'dev',
        time: DateTime(2026, 11, 7, 9), severity: Severity.high, state: AlertState.resolved),
  ];
  @override
  Future<List<SecurityAlert>?> getAlerts({int? limit}) async =>
      limit != null && _list.length > limit ? _list.sublist(0, limit) : _list;
  @override
  Future<int?> getOpenAlertCount() async => _list.where((a) => a.isUnresolved).length;
}

class _HomeScaleRepo extends DemoRepository {
  @override
  Future<List<Device>> getDevices() async => [
        for (var i = 0; i < 153; i++)
          Device(
            mac: 'aa:aa:aa:aa:${(i ~/ 100) % 10}${(i ~/ 10) % 10}:${i % 10}0',
            presence: Presence.online,
            trusted: false,
          ),
      ];
}

class _ScaleRepo extends DemoRepository {
  final Device _dev = const Device(
    mac: _mac,
    ip: '192.168.100.238',
    ipv6: ['2001:0db8:c83e:5700:78f5:8a3d:cbf4:b5fe'],
    hostname: '0badc396-c1f4-40db-ba83-c0702b11ae58', // opaque -> model shown
    model: 'emulator (sdk_gphone64_x86_64)',
    vendor: 'Google', deviceType: 'Computer',
    presence: Presence.online, trusted: false, monitored: false,
  );
  @override Future<List<Device>> getDevices() async => [_dev];
  @override Future<Device> getDevice(String mac) async => _dev;
}
