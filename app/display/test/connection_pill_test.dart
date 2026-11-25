import 'package:assas_core/assas_core.dart';
import 'package:assas_design/widgets/device_signals.dart';
import 'package:assas_display/display_ui.dart';
import 'package:assas_display/screens/status_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

/// Demo data with a fixed appliance connection status.
class _HealthRepository extends DemoRepository {
  _HealthRepository(this.status);

  final ConnectionStatus status;

  @override
  Future<ConnectionStatus> checkHealth() async => status;

  @override
  Future<List<PairedPhone>?> getPairedPhones() async => [];
}

Future<void> _loadFonts() async {
  for (final font in ['BricolageGrotesque', 'JetBrainsMono']) {
    final loader = FontLoader(font == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
    loader.addFont(rootBundle.load('assets/fonts/$font.ttf'));
    await loader.load();
  }
}

// The top-right connection pill (the only Container with this padding).
final _pill = find.byWidgetPredicate((w) =>
    w is Container && w.padding == const EdgeInsets.symmetric(horizontal: 16, vertical: 10));

/// Pumps the status screen for [status] and returns the pill's rect.
Future<Rect> _pumpStatus(WidgetTester tester, ConnectionStatus status) async {
  await tester.pumpWidget(MaterialApp(
    theme: DisplayUi.theme,
    home: StatusScreen(repo: _HealthRepository(status)),
  ));
  for (var i = 0; i < 3; i++) {
    await tester.pump(const Duration(milliseconds: 200));
  }
  expect(_pill, findsOneWidget);
  return tester.getRect(_pill);
}

Future<void> _unmount(WidgetTester tester) async {
  await tester.pumpWidget(const SizedBox());
  await tester.pump(const Duration(seconds: 3));
}

void main() {
  testWidgets('stale pill: line 1 CONNECTED as when live, line 2 OUTDATED once in the warning '
      'colour, same size as live', (tester) async {
    await tester.binding.setSurfaceSize(const Size(1024, 600));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await _loadFonts();

    final live = await _pumpStatus(tester, ConnectionStatus.live);
    final connected = find.descendant(of: _pill, matching: find.text('CONNECTED'));
    expect(connected, findsOneWidget);
    final liveLine1 = tester.widget<Text>(connected).style;
    expect(liveLine1!.color, ConnectionLook.color(ConnectionStatus.live));
    final liveLine2 = find.descendant(of: _pill, matching: find.text('SYNCED NOW'));
    expect(liveLine2, findsOneWidget);
    final liveLine2Size = tester.getSize(liveLine2);
    await _unmount(tester);

    final stale = await _pumpStatus(tester, ConnectionStatus.stale);
    // Line 1: CONNECTED, styled exactly as live.
    expect(connected, findsOneWidget);
    expect(tester.widget<Text>(connected).style, liveLine1);
    // Line 2: OUTDATED once (no doubled word), in the warning colour.
    final outdated = find.descendant(of: _pill, matching: find.text('OUTDATED'));
    expect(outdated, findsOneWidget);
    expect(find.text('OUTDATED'), findsOneWidget);
    expect(tester.widget<Text>(outdated).style!.color, ConnectionLook.color(ConnectionStatus.stale));
    expect(find.text('SYNCED NOW'), findsNothing);
    // Same size as live: line 2 is narrower than SYNCED NOW, and the pill's
    // width is set by line 1 (CONNECTED) in both states.
    expect(tester.getSize(outdated).width, lessThanOrEqualTo(liveLine2Size.width));
    expect(stale.size, live.size);
    expect(tester.takeException(), isNull);
    await _unmount(tester);
  });

  testWidgets('live and disconnected pills are unchanged', (tester) async {
    await tester.binding.setSurfaceSize(const Size(1024, 600));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await _loadFonts();

    await _pumpStatus(tester, ConnectionStatus.live);
    expect(find.descendant(of: _pill, matching: find.text('CONNECTED')), findsOneWidget);
    expect(find.descendant(of: _pill, matching: find.text('SYNCED NOW')), findsOneWidget);
    expect(find.text('OUTDATED'), findsNothing);
    await _unmount(tester);

    await _pumpStatus(tester, ConnectionStatus.unreachable);
    final line1 = find.descendant(of: _pill, matching: find.text('DISCONNECTED'));
    expect(line1, findsOneWidget);
    expect(tester.widget<Text>(line1).style!.color, ConnectionLook.color(ConnectionStatus.unreachable));
    expect(find.text('CONNECTED'), findsNothing);
    expect(find.text('OUTDATED'), findsNothing);
    await _unmount(tester);
  });
}
