import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/dashboard/dashboard_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:assas_mobile/widgets/design_scale.dart';
import 'package:assas_mobile/widgets/ui_kit.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

/// 170 devices, like the real appliance (167, old ones included):
/// 128 online and 114 unrecognized, so every count has 3 digits.
class _ManyDevicesRepository extends DemoRepository {
  _ManyDevicesRepository() {
    final now = DateTime.now();
    devices = [
      for (var i = 1; i <= 170; i++)
        Device(
          mac: '5b:8c:da:4d:${(i ~/ 256).toRadixString(16).padLeft(2, '0')}:${(i % 256).toRadixString(16).padLeft(2, '0')}',
          ip: '192.168.1.$i',
          hostname: 'Device $i',
          vendor: 'TP-Link',
          deviceType: 'Smart plug',
          presence: i % 4 == 0 ? Presence.offline : Presence.online,
          trusted: i % 3 == 0,
          monitored: true,
          lastSeen: now.subtract(Duration(hours: i)),
        ),
    ];
  }

  late List<Device> devices;

  @override
  Future<List<Device>> getDevices() async => List.unmodifiable(devices);
}

/// Pumps the dashboard at narrow to large phones, every Text size step, and the
/// max phone text scale; [check] runs with the stat cards scrolled into view.
Future<void> _eachLayout(
  WidgetTester tester,
  AssasRepository repository,
  void Function(String reason) check,
) async {
  // Real fonts: the default test font is much wider than the app's fonts.
  for (final font in ['BricolageGrotesque', 'JetBrainsMono']) {
    final loader = FontLoader(font == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
    loader.addFont(rootBundle.load('assets/fonts/$font.ttf'));
    await loader.load();
  }
  final state = AppState(repository);
  addTearDown(state.dispose);
  addTearDown(tester.view.reset);
  // AppState starts empty: load the devices once (no polling timer).
  await tester.runAsync(state.refresh);
  expect(state.loadedOnce, isTrue);
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
      final reason = 'width=$width, zoom=$zoom';
      expect(tester.takeException(), isNull, reason: reason);
      await tester.scrollUntilVisible(find.text('Unrecog\u00adnized'), 200, scrollable: find.byType(Scrollable).first);
      await tester.pump(const Duration(milliseconds: 100));
      expect(tester.takeException(), isNull, reason: reason);
      check(reason);
    }
  }
  await tester.pumpWidget(const SizedBox());
}

void main() {
  testWidgets('dashboard has no overflow at every text size; Unresolved alerts shows the count', (tester) async {
    await _eachLayout(tester, DemoRepository(), (reason) {
      // Unresolved alerts and Unrecognized share one card layout (a Wrap): label
      // on the left, value (the demo's 2 unresolved alerts) on the right.
      final label = find.text('Unresolved\nalerts');
      final card = find.ancestor(of: label, matching: find.byType(Wrap)).first;
      expect(find.descendant(of: card, matching: find.text('2')), findsOneWidget, reason: reason);
      expect(find.text('Open\nalerts'), findsNothing, reason: reason);
    });
  });

  testWidgets('right column fills the Online card height; the two cards share one width',
      (tester) async {
    for (final font in ['BricolageGrotesque', 'JetBrainsMono']) {
      final loader = FontLoader(font == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
      loader.addFont(rootBundle.load('assets/fonts/$font.ttf'));
      await loader.load();
    }
    final state = AppState(DemoRepository());
    addTearDown(state.dispose);
    addTearDown(tester.view.reset);
    await tester.runAsync(state.refresh);
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(390, 900);
    await tester.pumpWidget(MaterialApp(
      theme: MobileTheme.light,
      home: Scaffold(
        body: DashboardScreen(state: state, onOpenDevices: () {}, onOpenAlerts: () {}),
      ),
    ));
    await tester.pump(const Duration(milliseconds: 200));

    // The card = the Pressable wrapping each stat card.
    Rect cardOf(Finder text) => tester.getRect(
          find.ancestor(of: text, matching: find.byType(Pressable)).first,
        );
    final online = cardOf(find.text('ONLINE'));
    final openAlerts = cardOf(find.text('Unresolved\nalerts'));
    final unrecognized = cardOf(find.text('Unrecog\u00adnized'));

    // Unresolved alerts aligns to Online's top; Unrecognized to its bottom.
    expect(openAlerts.top, moreOrLessEquals(online.top, epsilon: 1.0));
    expect(unrecognized.bottom, moreOrLessEquals(online.bottom, epsilon: 1.0));
    // The two right cards share one width and the same right/left edges.
    expect(openAlerts.width, moreOrLessEquals(unrecognized.width, epsilon: 0.5));
    expect(openAlerts.left, moreOrLessEquals(unrecognized.left, epsilon: 0.5));
    expect(openAlerts.right, moreOrLessEquals(unrecognized.right, epsilon: 0.5));
  });

  testWidgets('dashboard with 170 devices (3-digit counts) has no overflow; Unrecognized is one word',
      (tester) async {
    await _eachLayout(tester, _ManyDevicesRepository(), (reason) {
      // The ribbon renders before the scroll (any overflow would have thrown
      // there); after scrolling to the stats the ListView may cull it, so the
      // 3-digit assertions use the Online card which is on-screen here.
      expect(find.text('/170'), findsOneWidget, reason: reason); // Online card
      // The label keeps its designed size inside its card next to the 3-digit
      // count. It renders on one line when it fits; at the largest sizes it may
      // wrap ONCE, only at its soft-hyphen break point (never an arbitrary
      // mid-word cut), with the card growing around it.
      final label = find.text('Unrecog\u00adnized');
      expect(label, findsOneWidget, reason: reason);
      final card = find.ancestor(of: label, matching: find.byType(Wrap)).first;
      expect(find.descendant(of: card, matching: find.text('114')), findsOneWidget, reason: reason);
      final p = tester.renderObject<RenderParagraph>(
        find.descendant(of: label, matching: find.byType(RichText)),
      );
      final text = p.text.toPlainText();
      expect(text, 'Unrecog\u00adnized', reason: reason); // visible text unchanged
      final lines = p
          .getBoxesForSelection(TextSelection(baseOffset: 0, extentOffset: text.length))
          .map((b) => b.top)
          .toSet();
      expect(lines.length, lessThanOrEqualTo(2), reason: '$reason: label broke beyond its hyphen point');
      final cardRect = tester.getRect(card);
      final labelRect = MatrixUtils.transformRect(p.getTransformTo(null), Offset.zero & p.size);
      expect(cardRect.inflate(.5).contains(labelRect.topLeft) && cardRect.inflate(.5).contains(labelRect.bottomRight),
          isTrue, reason: '$reason: label $labelRect outside its card $cardRect');
    });
  });
}
