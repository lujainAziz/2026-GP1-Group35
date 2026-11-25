import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/dashboard/dashboard_screen.dart';
import 'package:assas_mobile/screens/settings/settings_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:assas_mobile/widgets/device_signals.dart';
import 'package:assas_mobile/widgets/ui_kit.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

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
  // Stale data still reads CONNECTED on line 1 (only line 2 says OUTDATED).
  for (final (status, label) in [
    (ConnectionStatus.live, 'CONNECTED'),
    (ConnectionStatus.stale, 'CONNECTED'),
    (ConnectionStatus.unreachable, 'DISCONNECTED'),
  ]) {
    testWidgets('home connection pill fits "$label" (${status.name}) at 320, 375 and 390', (tester) async {
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

  _staleTests();
  _settingsStaleTests();
}

Future<void> _loadFonts() async {
  for (final font in ['BricolageGrotesque', 'JetBrainsMono']) {
    final loader = FontLoader(font == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
    loader.addFont(rootBundle.load('assets/fonts/$font.ttf'));
    await loader.load();
  }
}

/// Pumps Home for [status] and returns the connection pill's rect.
Future<Rect> _pumpHome(WidgetTester tester, ConnectionStatus status, double width, double scale) async {
  final state = AppState(_HealthRepository(status));
  addTearDown(state.dispose);
  await tester.runAsync(state.refresh);
  expect(state.connection, status);
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
  return tester.getRect(find.ancestor(of: find.text('CONNECTED'), matching: find.byType(Glass)).first);
}

void _staleTests() {
  testWidgets('stale pill: line 1 CONNECTED as when live, line 2 OUTDATED in the warning colour, '
      'same size as live', (tester) async {
    await _loadFonts();
    addTearDown(tester.view.reset);
    for (final width in [320.0, 375.0, 390.0]) {
      for (final scale in [1.0, 1.3]) {
        final reason = 'width=$width, textScale=$scale';
        final live = await _pumpHome(tester, ConnectionStatus.live, width, scale);
        final liveLine1 = tester.widget<Text>(find.text('CONNECTED')).style;
        expect(find.bySemanticsLabel('Connection: CONNECTED. Tap to refresh'), findsOneWidget, reason: reason);
        await tester.pumpWidget(const SizedBox());

        final stale = await _pumpHome(tester, ConnectionStatus.stale, width, scale);
        // Line 1: CONNECTED, styled exactly as live.
        expect(find.text('CONNECTED'), findsOneWidget, reason: reason);
        expect(tester.widget<Text>(find.text('CONNECTED')).style, liveLine1, reason: reason);
        expect(liveLine1!.color, ConnectionLook.color(ConnectionStatus.live), reason: reason);
        // Line 2: OUTDATED once (no doubled word), in the warning colour.
        expect(find.text('OUTDATED'), findsOneWidget, reason: reason);
        expect(tester.widget<Text>(find.text('OUTDATED')).style!.color,
            ConnectionLook.color(ConnectionStatus.stale), reason: reason);
        expect(find.text('SYNCED NOW'), findsNothing, reason: reason);
        // Screen reader: connected, data outdated.
        expect(find.bySemanticsLabel('Connection: Connected, but the data is outdated. Tap to refresh'),
            findsOneWidget, reason: reason);
        // Same size as the live pill, so nothing shifts.
        expect(stale.size, live.size, reason: reason);
        expect(tester.takeException(), isNull, reason: reason);
        await tester.pumpWidget(const SizedBox());
      }
    }
  });
}

// Settings' hardware card had the same doubled wording ("● OUTDATED / PAIRED"
// and LAST SYNC "OUTDATED"); it now matches the Home pill.
void _settingsStaleTests() {
  testWidgets('settings hardware card when stale: CONNECTED / PAIRED, LAST SYNC OUTDATED once',
      (tester) async {
    SharedPreferences.setMockInitialValues({});
    final state = AppState(_HealthRepository(ConnectionStatus.stale));
    addTearDown(state.dispose);
    await tester.runAsync(state.refresh);
    expect(state.connection, ConnectionStatus.stale);
    await tester.binding.setSurfaceSize(const Size(600, 1400));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(MaterialApp(theme: MobileTheme.light,
      home: Scaffold(body: SettingsScreen(state: state))));
    await tester.pump();

    final status = find.text('● CONNECTED / PAIRED');
    expect(status, findsOneWidget);
    expect(tester.widget<Text>(status).style!.color, ConnectionLook.color(ConnectionStatus.live));
    expect(find.textContaining('OUTDATED /'), findsNothing);
    expect(find.text('OUTDATED'), findsOneWidget);
    expect(tester.widget<Text>(find.text('OUTDATED')).style!.color,
        ConnectionLook.color(ConnectionStatus.stale));
    // Let the screen's pending one-shot timers finish (as settings_recovery_test does).
    await tester.pump(const Duration(seconds: 2));
    await tester.pumpWidget(const SizedBox());
  });
}
