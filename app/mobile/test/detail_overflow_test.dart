// Sprint 2 UI review: the alert-details and device-details screens must stay
// readable — no overflow/clipping — at the smallest, default, and largest
// supported font sizes, with long device names and full IPv6 addresses.
// Also checks the opaque-hostname -> "Unknown device" display rule and that
// the hidden alert fields (occurrences, first/last, rule id, ports) are absent.
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/alerts/alert_details_screen.dart';
import 'package:assas_mobile/screens/alerts/alert_list_screen.dart';
import 'package:assas_mobile/screens/devices/device_details_screen.dart';
import 'package:assas_mobile/screens/devices/device_list_screen.dart';
import 'package:assas_mobile/screens/settings/settings_screen.dart';
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
  Future<List<SecurityAlert>?> getAlerts() async => [
        SecurityAlert.fromApi({
          'id': '1', 'kind': 'threat', 'title': _longTitle,
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

Future<void> _pumpAll(WidgetTester tester, Widget Function() build) async {
  addTearDown(tester.view.reset);
  for (final scale in [0.85, 1.0, 1.3]) {        // smallest, default, largest
    for (final width in [320.0, 400.0]) {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = Size(width, 900);
      await tester.pumpWidget(MaterialApp(
        theme: MobileTheme.light,
        home: Builder(builder: (context) => MediaQuery(
              data: MediaQuery.of(context).copyWith(textScaler: TextScaler.linear(scale)),
              // Material ancestor for screens normally hosted in the shell
              // Scaffold (e.g. the device list); detail screens bring their own.
              child: DesignScale(zoom: 1, child: Material(color: Ui.bg, child: build())),
            )),
      ));
      await tester.pump(const Duration(milliseconds: 60));
      expect(tester.takeException(), isNull, reason: 'scale=$scale width=$width');
    }
  }
  await tester.pumpWidget(const SizedBox());
}

void main() {
  testWidgets('Alerts list: no overflow at all font sizes', (tester) async {
    await _loadFonts();
    final s = await _state(tester);
    await _pumpAll(tester, () => AlertListScreen(state: s));
  });

  testWidgets('Alert details: no overflow; hidden fields absent; device name once', (tester) async {
    await _loadFonts();
    final s = await _state(tester);
    await _pumpAll(tester, () => AlertDetailsScreen(state: s, alertId: '1'));
    // re-pump once at default to assert content
    tester.view.physicalSize = const Size(400, 900);
    await tester.pumpWidget(MaterialApp(theme: MobileTheme.light,
        home: DesignScale(zoom: 1, child: AlertDetailsScreen(state: s, alertId: '1'))));
    await tester.pump(const Duration(milliseconds: 60));
    // SpecList uppercases labels; hidden fields must be absent in any case
    for (final f in ['OCCURRENCES', 'FIRST SEEN', 'LAST SEEN', 'RULE ID', 'DEVICE']) {
      expect(find.text(f), findsNothing, reason: '$f should be hidden');
    }
    // ports hidden: value shows IP only, never ip:port
    expect(find.textContaining(':51000'), findsNothing);
    expect(find.textContaining(':443'), findsNothing);
    expect(find.text('SOURCE IP'), findsOneWidget);
    expect(find.text('DESTINATION IP'), findsOneWidget);
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
