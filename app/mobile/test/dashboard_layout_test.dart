import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/dashboard/dashboard_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:assas_mobile/widgets/design_scale.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('dashboard has no overflow at every text size; Open alerts shows SOON', (tester) async {
    // Real fonts: the default test font is much wider than the app's fonts.
    for (final font in ['BricolageGrotesque', 'JetBrainsMono']) {
      final loader = FontLoader(font == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
      loader.addFont(rootBundle.load('assets/fonts/$font.ttf'));
      await loader.load();
    }
    final state = AppState(DemoRepository());
    addTearDown(state.dispose);
    addTearDown(tester.view.reset);
    // Narrow to large phones, every Text size step, and the max phone text scale.
    for (final width in [320.0, 360.0, 390.0, 430.0]) {
      for (final zoom in [1.0, 1.06, 1.12, 1.2]) {
        tester.view.devicePixelRatio = 1;
        tester.view.physicalSize = Size(width, 800);
        await tester.pumpWidget(MaterialApp(
          theme: MobileTheme.light,
          home: DesignScale(
            zoom: zoom,
            child: Builder(
              builder: (context) => MediaQuery(
                data: MediaQuery.of(context).copyWith(textScaler: const TextScaler.linear(1.3)),
                child: Scaffold(
                  body: DashboardScreen(state: state, onOpenDevices: () {}, onOpenAlerts: () {}),
                ),
              ),
            ),
          ),
        ));
        await tester.pump(const Duration(milliseconds: 100));
        final label = find.text('Open\nalerts');
        await tester.scrollUntilVisible(label, 200, scrollable: find.byType(Scrollable).first);
        await tester.pump(const Duration(milliseconds: 100));
        expect(tester.takeException(), isNull, reason: 'width=$width, zoom=$zoom');
        final card = find.ancestor(of: label, matching: find.byType(Row)).first;
        expect(find.descendant(of: card, matching: find.text('SOON')), findsOneWidget,
            reason: 'width=$width, zoom=$zoom');
      }
    }
    await tester.pumpWidget(const SizedBox());
  });
}
