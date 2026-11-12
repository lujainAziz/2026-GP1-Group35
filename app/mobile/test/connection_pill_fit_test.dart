import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/dashboard/dashboard_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:assas_mobile/widgets/device_signals.dart';
import 'package:assas_mobile/widgets/ui_kit.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

/// Demo data with a fixed appliance connection status.
class _HealthRepository extends DemoRepository {
  _HealthRepository(this.status);

  final ConnectionStatus status;

  @override
  Future<ConnectionStatus> checkHealth() async => status;
}

void main() {
  // The home connection pill says CONNECTED / DISCONNECTED (not Online/Offline,
  // which is device presence). The longer words must fit on narrow phones.
  for (final (status, label) in [
    (ConnectionStatus.live, 'CONNECTED'),
    (ConnectionStatus.unreachable, 'DISCONNECTED'),
  ]) {
    testWidgets('home connection pill fits "$label" at 320, 375 and 390', (tester) async {
      // Real fonts: the default test font is much wider than the app's fonts.
      for (final font in ['BricolageGrotesque', 'JetBrainsMono']) {
        final loader = FontLoader(font == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
        loader.addFont(rootBundle.load('assets/fonts/$font.ttf'));
        await loader.load();
      }
      final state = AppState(_HealthRepository(status));
      addTearDown(state.dispose);
      addTearDown(tester.view.reset);
      await tester.runAsync(state.refresh);
      expect(state.connection, status);

      for (final width in [320.0, 375.0, 390.0]) {
        for (final scale in [1.0, 1.3]) {
          tester.view.devicePixelRatio = 1;
          tester.view.physicalSize = Size(width, 800);
          await tester.pumpWidget(MaterialApp(
            theme: MobileTheme.light,
            home: Builder(
              builder: (context) => MediaQuery(
                data: MediaQuery.of(context).copyWith(textScaler: TextScaler.linear(scale)),
                child: Scaffold(
                  body: DashboardScreen(state: state, onOpenDevices: () {}, onOpenAlerts: () {}),
                ),
              ),
            ),
          ));
          await tester.pump(const Duration(milliseconds: 100));
          final reason = 'width=$width, textScale=$scale';
          expect(tester.takeException(), isNull, reason: reason);

          final text = find.text(label);
          expect(text, findsOneWidget, reason: reason);
          final pill = tester.getRect(find.ancestor(of: text, matching: find.byType(Glass)).first);
          final word = tester.getRect(text);
          final synced = tester.getRect(find.text(ConnectionLook.synced(status, state.lastSync)));
          final wordmark = tester.getRect(find.text('ASSAS'));

          // Whole label and sync line inside the pill, pill inside the screen.
          expect(pill.left, greaterThanOrEqualTo(0), reason: reason);
          expect(pill.right, lessThanOrEqualTo(width), reason: reason);
          for (final r in [word, synced]) {
            expect(r.left, greaterThanOrEqualTo(pill.left), reason: reason);
            expect(r.right, lessThanOrEqualTo(pill.right), reason: reason);
            expect(r.top, greaterThanOrEqualTo(pill.top), reason: reason);
            expect(r.bottom, lessThanOrEqualTo(pill.bottom), reason: reason);
          }
          // Does not run into the ASSAS wordmark on the same row.
          expect(pill.left, greaterThan(wordmark.right), reason: reason);
        }
      }
      await tester.pumpWidget(const SizedBox());
    });
  }
}
