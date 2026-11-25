// The trust button keeps one width when it toggles between "Mark as trusted"
// and "Remove trust", at normal and large font.
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

class _Repo extends DemoRepository {
  _Repo({required this.trusted});
  final bool trusted;
  @override
  Future<Device> getDevice(String mac) async => Device(
        mac: _mac, ip: '192.168.1.5', hostname: 'thing',
        presence: Presence.online, trusted: trusted, monitored: false,
      );
  @override
  Future<List<SecurityAlert>?> getDeviceAlerts(String mac, {int? limit}) async => const [];
}

Future<void> _loadFonts() async {
  for (final f in ['BricolageGrotesque', 'JetBrainsMono']) {
    final l = FontLoader(f == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
    l.addFont(rootBundle.load('assets/fonts/$f.ttf'));
    await l.load();
  }
}

Future<double> _trustButtonWidth(WidgetTester tester, {required bool trusted, required double scale}) async {
  SharedPreferences.setMockInitialValues({});
  await _loadFonts();
  final state = AppState(_Repo(trusted: trusted));
  addTearDown(state.dispose);
  addTearDown(tester.view.reset);
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = const Size(390, 1800);
  await tester.pumpWidget(MaterialApp(
    theme: MobileTheme.light,
    home: Builder(
      builder: (c) => MediaQuery(
        data: MediaQuery.of(c).copyWith(textScaler: TextScaler.linear(scale)),
        child: DeviceDetailsScreen(state: state, mac: _mac),
      ),
    ),
  ));
  await tester.pump(); // build
  await tester.pump(const Duration(milliseconds: 500)); // async load + animations (no settle: radar loops)
  final label = trusted ? 'Remove trust' : 'Mark as trusted';
  expect(find.text(label), findsOneWidget);
  final w = tester.getSize(find.byType(PillButton)).width;
  await tester.pumpWidget(const SizedBox());
  return w;
}

void main() {
  testWidgets('trust button keeps one width in both states (normal + large font)', (tester) async {
    for (final scale in [1.0, 1.4]) {
      final untrusted = await _trustButtonWidth(tester, trusted: false, scale: scale);
      final trusted = await _trustButtonWidth(tester, trusted: true, scale: scale);
      expect(trusted, moreOrLessEquals(untrusted, epsilon: 0.5),
          reason: 'scale=$scale: trust button width must not change with state');
    }
  });
}
