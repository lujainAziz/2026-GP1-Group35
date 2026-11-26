// Sort, severity filter, hide-resolved, load-older-with-filter, and the
// back-to-top button on the alerts list.
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/alerts/alert_list_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:assas_mobile/widgets/design_scale.dart';
import 'package:assas_mobile/widgets/filter_button.dart';
import 'package:assas_mobile/widgets/ui_kit.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

// Unresolved alerts start unread on this phone; resolved ones are read.
SecurityAlert _mk(String id, Severity sev, int sec,
        {AlertState state = AlertState.newAlert}) =>
    SecurityAlert(
      id: id,
      kind: AlertKind.threat,
      title: 'sig $id',
      deviceName: 'dev',
      time: DateTime(2026, 11, 7, 10).add(Duration(seconds: sec)),
      severity: sev,
      state: state,
      read: state == AlertState.resolved,
    );

/// Serves a fixed alert set; getAlerts respects the page limit (newest first).
class _Repo extends DemoRepository {
  _Repo(this._list) {
    _list.sort((a, b) => b.time.compareTo(a.time));
  }
  final List<SecurityAlert> _list;

  @override
  Future<List<SecurityAlert>?> getAlerts({int? limit}) async =>
      limit != null && _list.length > limit ? _list.sublist(0, limit) : _list;

  @override
  Future<int?> getOpenAlertCount() async =>
      _list.where((a) => a.isUnresolved).length;
}

Future<void> _loadFonts() async {
  for (final f in ['BricolageGrotesque', 'JetBrainsMono']) {
    final l = FontLoader(f == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
    l.addFont(rootBundle.load('assets/fonts/$f.ttf'));
    await l.load();
  }
}

Future<AppState> _pump(WidgetTester tester, List<SecurityAlert> alerts,
    {double height = 1600}) async {
  SharedPreferences.setMockInitialValues({});
  await _loadFonts();
  final state = AppState(_Repo(alerts));
  addTearDown(state.dispose);
  addTearDown(tester.view.reset);
  await tester.runAsync(state.refresh);
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = Size(390, height);
  await tester.pumpWidget(MaterialApp(
    theme: MobileTheme.light,
    home: Scaffold(body: AlertListScreen(state: state)),
  ));
  await tester.pump(const Duration(milliseconds: 400));
  return state;
}

final _dot = find.byKey(const ValueKey('filterActiveDot'));

Color _fill(WidgetTester tester) => tester
    .widget<Glass>(find.descendant(
        of: find.byKey(const ValueKey('alertFilterButton')), matching: find.byType(Glass)))
    .color;

List<String> _cardOrder(WidgetTester tester) =>
    tester.widgetList<TimelineAlertCard>(find.byType(TimelineAlertCard))
        .map((c) => c.alert.id)
        .toList();

void main() {
  testWidgets('list is newest-first; the sort control is not on this screen',
      (tester) async {
    await _pump(tester, [
      _mk('med', Severity.medium, 0),      // oldest
      _mk('low', Severity.low, 30),
      _mk('high', Severity.high, 60),      // newest
    ]);
    // Newest first, always (sort toggle moved to device details).
    expect(_cardOrder(tester), ['high', 'low', 'med']);
    expect(find.text('Newest'), findsNothing);
    expect(find.text('Most severe'), findsNothing);
    // Tabs and the Filter control share one row.
    expect(find.text('All'), findsOneWidget);
    expect(find.text('Resolved'), findsOneWidget);
    expect(find.byKey(const ValueKey('alertFilterButton')), findsOneWidget);
  });

  testWidgets('severity filter (devices-style dropdown) shows only the selected severities',
      (tester) async {
    await _pump(tester, [
      _mk('low', Severity.low, 0),
      _mk('med', Severity.medium, 30),
      _mk('high', Severity.high, 60),
    ]);
    expect(_cardOrder(tester).toSet(), {'low', 'med', 'high'});
    // Release 1: only High / Medium / Low chips (no Critical).
    await tester.tap(find.byKey(const ValueKey('alertFilterButton')));
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('sevchip_critical')), findsNothing);

    // Restrict to Low + High.
    await tester.tap(find.byKey(const ValueKey('sevchip_low')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('sevchip_high')));
    await tester.pumpAndSettle();
    // Close the dropdown (tap the barrier away from the menu).
    await tester.tapAt(const Offset(10, 1000));
    await tester.pumpAndSettle();

    final ids = _cardOrder(tester).toSet();
    expect(ids.contains('med'), isFalse); // medium not selected -> hidden
    expect(ids.containsAll({'low', 'high'}), isTrue);
    // The filter button is icon-only: active = dot, count only for screen readers.
    expect(find.text('2 filters'), findsNothing);
    expect(_dot, findsOneWidget);
    expect(find.bySemanticsLabel('Filter, 2 selected'), findsOneWidget);
  });

  testWidgets('filter keeps "Load older" available so it reaches the full list',
      (tester) async {
    // 2000 newest are Medium (fills the first page -> alertsHaveMore), with a
    // High one older than the page. Restricting to High empties the
    // loaded page, but the load-older affordance must remain so older matches
    // load.
    final many = [
      for (var i = 0; i < 2000; i++) _mk('m$i', Severity.medium, 10000 - i),
      _mk('high-old', Severity.high, 0),
    ];
    final state = await _pump(tester, many);
    expect(state.alertsHaveMore, isTrue);

    await tester.tap(find.byKey(const ValueKey('alertFilterButton')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('sevchip_high'))); // show only High
    await tester.pumpAndSettle();
    await tester.tapAt(const Offset(10, 1000));
    await tester.pumpAndSettle();

    // No medium cards shown now, but the load-older control is still offered.
    expect(find.text('No alerts match the filter'), findsOneWidget);
    expect(find.text('Load older alerts'), findsOneWidget);

    // Loading older pulls in the High one, which then matches the filter
    // (the load is real-async, so drive it under runAsync).
    await tester.runAsync(() => state.loadMoreAlerts());
    await tester.pumpAndSettle();
    expect(_cardOrder(tester), ['high-old']);
  });

  testWidgets('Filter button: icon-only, fixed size, accent fill + dot when active, '
      'at normal and large font', (tester) async {
    for (final scale in [1.0, 1.3]) {
      SharedPreferences.setMockInitialValues({});
      await _loadFonts();
      final state = AppState(_Repo([
        for (var i = 0; i < 6; i++) _mk('l$i', Severity.low, 100 - i),
        for (var i = 0; i < 5; i++) _mk('h$i', Severity.high, 60 - i),
      ]));
      addTearDown(state.dispose);
      addTearDown(tester.view.reset);
      await tester.runAsync(state.refresh);
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(390, 1600); // the screen width in the image
      await tester.pumpWidget(MaterialApp(
        theme: MobileTheme.light,
        home: Builder(
          builder: (c) => MediaQuery(
            data: MediaQuery.of(c).copyWith(textScaler: TextScaler.linear(scale)),
            child: Scaffold(body: AlertListScreen(state: state)),
          ),
        ),
      ));
      await tester.pump(const Duration(milliseconds: 400));

      final pill = find.byKey(const ValueKey('alertFilterButton'));
      // Inactive: outlined, no text, no dot, fixed size, state in semantics.
      expect(find.text('Filter'), findsNothing, reason: 'scale=$scale inactive: no visible text');
      expect(find.descendant(of: pill, matching: find.byType(Text)), findsNothing);
      expect(_dot, findsNothing, reason: 'scale=$scale inactive: no dot');
      expect(_fill(tester), Ui.fade(Ui.surf, .82), reason: 'scale=$scale inactive: outlined');
      expect(find.bySemanticsLabel('Filter, none selected'), findsOneWidget);
      expect(tester.getSize(pill), const Size.square(FilterButton.size), reason: 'scale=$scale');
      expect(tester.takeException(), isNull, reason: 'scale=$scale inactive no overflow');

      // Activate two severities.
      await tester.tap(pill);
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('sevchip_low')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('sevchip_high')));
      await tester.pumpAndSettle();
      await tester.tapAt(const Offset(10, 1300));
      await tester.pumpAndSettle();

      // Active: accent fill + dot, still no text, same fixed size.
      expect(find.text('2 filters'), findsNothing, reason: 'scale=$scale active: no visible count');
      expect(find.descendant(of: pill, matching: find.byType(Text)), findsNothing);
      expect(_dot, findsOneWidget, reason: 'scale=$scale active: dot');
      expect(_fill(tester), Ui.mix(Ui.acc, .22, Ui.surf), reason: 'scale=$scale active: accent fill');
      expect(find.bySemanticsLabel('Filter, 2 selected'), findsOneWidget);
      expect(tester.getSize(pill), const Size.square(FilterButton.size),
          reason: 'scale=$scale: button size constant between states');
      expect(tester.takeException(), isNull, reason: 'scale=$scale active no overflow');

      await tester.pumpWidget(const SizedBox());
    }
  });

  testWidgets('large font: Resolved + count stay visible with Filter on the same row',
      (tester) async {
    for (final active in [false, true]) {
      SharedPreferences.setMockInitialValues({});
      await _loadFonts();
      final state = AppState(_Repo([
        for (var i = 0; i < 11; i++) _mk('o$i', Severity.high, 100 - i),
        _mk('done', Severity.high, 0, state: AlertState.resolved),
      ]));
      addTearDown(state.dispose);
      addTearDown(tester.view.reset);
      await tester.runAsync(state.refresh);
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(360, 1600);
      await tester.pumpWidget(MaterialApp(
        theme: MobileTheme.light,
        home: Builder(
          builder: (c) => MediaQuery(
            data: MediaQuery.of(c).copyWith(textScaler: const TextScaler.linear(1.4)),
            child: Scaffold(body: AlertListScreen(state: state)),
          ),
        ),
      ));
      await tester.pump(const Duration(milliseconds: 400));

      if (active) {
        await tester.tap(find.byKey(const ValueKey('alertFilterButton')));
        await tester.pumpAndSettle();
        await tester.tap(find.byKey(const ValueKey('sevchip_high')));
        await tester.pumpAndSettle();
        await tester.tap(find.byKey(const ValueKey('sevchip_low')));
        await tester.pumpAndSettle();
        await tester.tapAt(const Offset(8, 1300));
        await tester.pumpAndSettle();
        expect(find.bySemanticsLabel('Filter, 2 selected'), findsOneWidget);
        expect(_dot, findsOneWidget);
      } else {
        expect(find.bySemanticsLabel('Filter, none selected'), findsOneWidget);
        expect(_dot, findsNothing);
      }
      expect(find.text('Filter'), findsNothing);
      expect(find.text('2 filters'), findsNothing);
      expect(tester.takeException(), isNull, reason: 'active=$active no overflow');

      // Resolved label is fully on-screen (not clipped off the right).
      final resolved = tester.getRect(find.text('Resolved').first); // the tab (not a card's state pill)
      expect(resolved.left, greaterThanOrEqualTo(0));
      expect(resolved.right, lessThanOrEqualTo(360));

      // Filter sits on the SAME row as the tabs (vertical overlap with "All").
      final all = tester.getRect(find.text('All').first);
      final filter = tester.getRect(find.byKey(const ValueKey('alertFilterButton')));
      expect(filter.top < all.bottom && filter.bottom > all.top, isTrue,
          reason: 'active=$active: filter should share the tabs row');

      await tester.pumpWidget(const SizedBox());
    }
  });

  testWidgets('3 severities selected at the app smallest AND largest real font: one pinned row, all counts whole',
      (tester) async {
    // The app's actual extremes: zoom 1.0 x system 0.85 and zoom 1.2 x system 1.3.
    for (final (zoom, scale) in [(1.0, 0.85), (1.2, 1.3)]) {
      SharedPreferences.setMockInitialValues(
          {'ui.alertSeverities': ['low', 'medium', 'high']});
      await _loadFonts();
      final state = AppState(_Repo([
        for (var i = 0; i < 287; i++) _mk('o$i', Severity.high, 1000 - i),
        _mk('done', Severity.high, 0, state: AlertState.resolved),
      ]));
      addTearDown(state.dispose);
      addTearDown(tester.view.reset);
      await tester.runAsync(state.refresh);
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(390, 1600);
      await tester.pumpWidget(MaterialApp(
        theme: MobileTheme.light,
        home: Builder(
          builder: (c) => MediaQuery(
            data: MediaQuery.of(c).copyWith(textScaler: TextScaler.linear(scale)),
            child: DesignScale(
              zoom: zoom,
              child: Material(color: Ui.bg, child: AlertListScreen(state: state)),
            ),
          ),
        ),
      ));
      await tester.pump(const Duration(milliseconds: 400));
      final reason = 'zoom=$zoom scale=$scale';

      // The stored selection restores into the icon-only active state.
      expect(find.text('3 filters'), findsNothing, reason: reason);
      expect(find.bySemanticsLabel('Filter, 3 selected'), findsOneWidget, reason: reason);
      expect(_dot, findsOneWidget, reason: reason);
      expect(tester.getSize(find.byKey(const ValueKey('alertFilterButton'))),
          const Size.square(FilterButton.size), reason: reason);
      expect(tester.takeException(), isNull, reason: reason);

      // All 288 / Unread 287 (badge) / Resolved 1 all whole, button on one row.
      for (final t in ['All', 'Unread', 'Resolved', '288', '287']) {
        expect(find.text(t).first, findsOneWidget, reason: '$reason: $t');
      }
      final resolved = tester.getRect(find.text('Resolved').first);
      expect(resolved.right, lessThanOrEqualTo(390), reason: reason);
      final all = tester.getRect(find.text('All').first);
      final filter = tester.getRect(find.byKey(const ValueKey('alertFilterButton')));
      expect(filter.top < all.bottom && filter.bottom > all.top, isTrue,
          reason: '$reason: filter shares the tabs row');
      expect(filter.right, lessThanOrEqualTo(390), reason: reason);
      await tester.pumpWidget(const SizedBox());
    }
  });

  testWidgets('375px, normal text: All 267 / Unread 266 / Resolved 1 fit beside Filter',
      (tester) async {
    // Web at 375 wide goes through DesignScale; the unstacked tabs row is at its
    // tightest here with three-digit counts.
    SharedPreferences.setMockInitialValues({});
    await _loadFonts();
    final state = AppState(_Repo([
      for (var i = 0; i < 266; i++) _mk('o$i', Severity.high, 1000 - i),
      _mk('done', Severity.high, 0, state: AlertState.resolved),
    ]));
    addTearDown(state.dispose);
    addTearDown(tester.view.reset);
    await tester.runAsync(state.refresh);
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(375, 1600);
    await tester.pumpWidget(MaterialApp(
      theme: MobileTheme.light,
      home: Builder(
        builder: (c) => MediaQuery(
          data: MediaQuery.of(c).copyWith(textScaler: TextScaler.noScaling),
          child: DesignScale(
            child: Material(color: Ui.bg, child: AlertListScreen(state: state)),
          ),
        ),
      ),
    ));
    await tester.pump(const Duration(milliseconds: 400));
    expect(tester.takeException(), isNull);

    for (final t in ['All', 'Unread', 'Resolved', '267', '266']) {
      expect(find.text(t).first, findsOneWidget, reason: t);
    }
    // "Resolved" is whole: on-screen and left of the Filter button, not clipped.
    final resolved = tester.getRect(find.text('Resolved').first); // the tab
    final filter = tester.getRect(find.byKey(const ValueKey('alertFilterButton')));
    expect(resolved.right, lessThanOrEqualTo(filter.left));
    expect(filter.right, lessThanOrEqualTo(375));
    expect(resolved.top < filter.bottom && resolved.bottom > filter.top, isTrue,
        reason: 'Resolved shares the row with Filter');
  });

  testWidgets('back-to-top button appears after scrolling and returns to top',
      (tester) async {
    await _pump(
      tester,
      [for (var i = 0; i < 40; i++) _mk('a$i', Severity.medium, 4000 - i)],
      height: 700,
    );
    expect(find.bySemanticsLabel('Back to top'), findsNothing);

    final scrollable = find.byType(Scrollable).first;
    await tester.drag(scrollable, const Offset(0, -900));
    await tester.pumpAndSettle();
    expect(find.bySemanticsLabel('Back to top'), findsOneWidget);

    await tester.tap(find.bySemanticsLabel('Back to top'));
    await tester.pumpAndSettle();
    final pos = tester.widget<Scrollable>(scrollable).controller!.position;
    expect(pos.pixels, 0);
    expect(find.bySemanticsLabel('Back to top'), findsNothing);
  });

  testWidgets('pinned tabs header: rounded card like the alert cards, opaque screen-colour '
      'background, first alert not covered, at normal and large text', (tester) async {
    // Normal, large system text, and the app's largest (zoom 1.2 x system 1.3).
    for (final (zoom, scale) in [(1.0, 1.0), (1.0, 1.3), (1.2, 1.3)]) {
      SharedPreferences.setMockInitialValues({});
      await _loadFonts();
      final state = AppState(_Repo([
        for (var i = 0; i < 11; i++) _mk('o$i', Severity.high, 100 - i),
        _mk('done', Severity.high, 0, state: AlertState.resolved),
      ]));
      addTearDown(state.dispose);
      addTearDown(tester.view.reset);
      await tester.runAsync(state.refresh);
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(390, 1600);
      await tester.pumpWidget(MaterialApp(
        theme: MobileTheme.light,
        home: Builder(
          builder: (c) => MediaQuery(
            data: MediaQuery.of(c).copyWith(textScaler: TextScaler.linear(scale)),
            child: DesignScale(
              zoom: zoom,
              child: Material(color: Ui.bg, child: AlertListScreen(state: state)),
            ),
          ),
        ),
      ));
      await tester.pump(const Duration(milliseconds: 400));
      final reason = 'zoom=$zoom scale=$scale';
      expect(tester.takeException(), isNull, reason: reason);

      final button = find.byKey(const ValueKey('alertFilterButton'));
      final cardFinder = find.ancestor(
        of: button,
        matching: find.byWidgetPredicate((w) =>
            w is Container && w.decoration == surfCard(UiRadius.alertCard)),
      );
      expect(cardFinder, findsOneWidget, reason: '$reason: tabs row sits in an alert-card-style card');
      final outer = tester.widget<ColoredBox>(
          find.ancestor(of: cardFinder, matching: find.byType(ColoredBox)).first);
      expect(outer.color, Ui.bg, reason: '$reason: opaque background is the screen colour');

      // Card inset by the alert cards' margin on both sides (in design pixels).
      final card = tester.getRect(cardFinder);
      final screenW = tester.getSize(find.byType(AlertListScreen)).width;
      final unit = card.width / (screenW - 2 * UiSpace.pageCards); // DesignScale factor
      expect(card.left / unit, moreOrLessEquals(UiSpace.pageCards, epsilon: 0.5), reason: reason);

      // Everything in the row stays inside the card; the button keeps 44x44.
      final filter = tester.getRect(button);
      expect(tester.getSize(button), const Size.square(FilterButton.size), reason: reason);
      expect(filter.top, greaterThanOrEqualTo(card.top), reason: reason);
      expect(filter.bottom, lessThanOrEqualTo(card.bottom), reason: reason);
      final resolved = tester.getRect(find.text('Resolved').first);
      expect(resolved.left, greaterThanOrEqualTo(card.left), reason: reason);
      expect(resolved.right, lessThanOrEqualTo(filter.left), reason: reason);
      expect(resolved.bottom, lessThanOrEqualTo(card.bottom), reason: reason);

      // The first alert starts below the pinned header (a gap below the card).
      final header = tester.getRect(find.ancestor(of: cardFinder, matching: find.byType(ClipRect)).first);
      final firstAlert = tester.getRect(find.byType(TimelineAlertCard).first);
      expect(card.bottom, lessThan(header.bottom), reason: '$reason: gap below the card');
      expect(firstAlert.top, greaterThanOrEqualTo(header.bottom), reason: '$reason: first alert not covered');

      await tester.pumpWidget(const SizedBox());
    }
  });
}
