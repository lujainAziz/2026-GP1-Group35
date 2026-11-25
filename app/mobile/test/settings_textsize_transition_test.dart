// Live Text-size switching must not overflow DURING the transition, not just
// when the screen is opened fresh at each size. Changing the app text size
// changes the DesignScale zoom, which shrinks this canvas; the Aa box widths
// must follow instantly (not animate down over 220 ms) or the row overflows
// mid-transition. This test taps the four sizes in sequence (forward + back)
// with the screen staying open, and checks during AND after each animation,
// across the supported system font scales. It does NOT rebuild the screen from
// scratch between taps.
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/settings/settings_screen.dart';
import 'package:assas_mobile/state/app_settings.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:assas_mobile/widgets/design_scale.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

Future<void> _loadFonts() async {
  for (final f in ['BricolageGrotesque', 'JetBrainsMono']) {
    final l = FontLoader(f == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
    l.addFont(rootBundle.load('assets/fonts/$f.ttf'));
    await l.load();
  }
}

void main() {
  testWidgets('Text-size row: no overflow while switching sizes live', (tester) async {
    SharedPreferences.setMockInitialValues({});
    await AppSettings.instance.load();
    await AppSettings.instance.setTextScaleIndex(0);
    await _loadFonts();
    final state = AppState(DemoRepository());
    addTearDown(state.dispose);
    await tester.runAsync(state.refresh);
    addTearDown(tester.view.reset);
    addTearDown(() => AppSettings.instance.setTextScaleIndex(0));

    for (final sysScale in [0.85, 1.0, 1.3]) {
      for (final width in [320.0, 400.0]) {
        tester.view.devicePixelRatio = 1;
        tester.view.physicalSize = Size(width, 1200);
        // Mirror main.dart: DesignScale zoom is bound to the app Text-size
        // setting and rebuilds when it changes.
        await tester.pumpWidget(MaterialApp(
          theme: MobileTheme.light,
          home: ListenableBuilder(
            listenable: AppSettings.instance,
            builder: (context, _) => MediaQuery(
              data: MediaQuery.of(context).copyWith(textScaler: TextScaler.linear(sysScale)),
              child: DesignScale(
                zoom: AppSettings.instance.textScale,
                child: Material(color: Ui.bg, child: SettingsScreen(state: state)),
              ),
            ),
          ),
        ));
        await tester.pump(const Duration(milliseconds: 60));
        await tester.pump(const Duration(milliseconds: 300)); // settle settings load

        // Press the four sizes in sequence, forward then back, screen open.
        for (final idx in [1, 2, 3, 2, 1, 0, 3, 0, 1, 3]) {
          // Anchor so "Large" doesn't also match "Largest"; the label may have a
          // ", selected" suffix.
          final finder = find.bySemanticsLabel(
            RegExp('^Text size ${AppSettings.textScaleLabels[idx]}(,|\$)'),
          );
          expect(finder, findsOneWidget, reason: 'size chip $idx not found');
          await tester.tap(finder, warnIfMissed: false);
          // Check DURING the transition (canvas resizes + color animates).
          await tester.pump();
          await tester.pump(const Duration(milliseconds: 40));
          expect(tester.takeException(), isNull,
              reason: 'mid-transition → $idx (sys=$sysScale w=$width)');
          await tester.pump(const Duration(milliseconds: 120));
          expect(tester.takeException(), isNull,
              reason: 'mid-transition2 → $idx (sys=$sysScale w=$width)');
          // And AFTER it settles.
          await tester.pump(const Duration(milliseconds: 260));
          expect(tester.takeException(), isNull,
              reason: 'settled → $idx (sys=$sysScale w=$width)');
        }
        await tester.pumpWidget(const SizedBox());
        await AppSettings.instance.setTextScaleIndex(0);
      }
    }
  });
}
