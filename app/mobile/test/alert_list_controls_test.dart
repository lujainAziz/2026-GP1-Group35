// Sort, severity filter, hide-resolved, load-older-with-filter, and the
// back-to-top button on the alerts list.
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/alerts/alert_list_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:assas_mobile/widgets/design_scale.dart';
import 'package:assas_mobile/widgets/ui_kit.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

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

List<String> _cardOrder(WidgetTester tester) =>
    tester.widgetList<TimelineAlertCard>(find.byType(TimelineAlertCard))
        .map((c) => c.alert.id)
        .toList();

void main() {
  testWidgets('list is newest-first; the sort control is not on this screen',
      (tester) async {
    await _pump(tester, [
      _mk('crit', Severity.critical, 0),   // oldest
      _mk('low', Severity.low, 30),
      _mk('high', Severity.high, 60),      // newest
    ]);
    // Newest first, always (sort toggle moved to device details).
    expect(_cardOrder(tester), ['high', 'low', 'crit']);
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
      _mk('crit', Severity.critical, 0),
      _mk('med', Severity.medium, 30),
      _mk('high', Severity.high, 60),
    ]);
    expect(_cardOrder(tester).toSet(), {'crit', 'med', 'high'});

    // Open the filter dropdown and restrict to Critical + High.
    await tester.tap(find.byKey(const ValueKey('alertFilterButton')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('sevchip_critical')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('sevchip_high')));
    await tester.pumpAndSettle();
    // Close the dropdown (tap the barrier away from the menu).
    await tester.tapAt(const Offset(10, 1000));
    await tester.pumpAndSettle();

    final ids = _cardOrder(tester).toSet();
    expect(ids.contains('med'), isFalse); // medium not selected -> hidden
    expect(ids.containsAll({'crit', 'high'}), isTrue);
    // The filter button shows the active count like the devices filter.
    expect(find.text('2 filters'), findsOneWidget);
  });

  testWidgets('filter keeps "Load older" available so it reaches the full list',
      (tester) async {
    // 2000 newest are Medium (fills the first page -> alertsHaveMore), with a
    // Critical one older than the page. Restricting to Critical empties the
    // loaded page, but the load-older affordance must remain so older matches
    // load.
    final many = [
      for (var i = 0; i < 2000; i++) _mk('m$i', Severity.medium, 10000 - i),
      _mk('crit-old', Severity.critical, 0),
    ];
    final state = await _pump(tester, many);
    expect(state.alertsHaveMore, isTrue);

    await tester.tap(find.byKey(const ValueKey('alertFilterButton')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('sevchip_critical'))); // show only Critical
    await tester.pumpAndSettle();
    await tester.tapAt(const Offset(10, 1000));
    await tester.pumpAndSettle();

    // No medium cards shown now, but the load-older control is still offered.
    expect(find.text('No alerts match the filter'), findsOneWidget);
    expect(find.text('Load older alerts'), findsOneWidget);

    // Loading older pulls in the critical one, which then matches the filter
    // (the load is real-async, so drive it under runAsync).
    await tester.runAsync(() => state.loadMoreAlerts());
    await tester.pumpAndSettle();
    expect(_cardOrder(tester), ['crit-old']);
  });

  testWidgets('Filter button keeps one width inactive vs active, at normal and large font',
      (tester) async {
    for (final scale in [1.0, 1.3]) {
      SharedPreferences.setMockInitialValues({});
      await _loadFonts();
      final state = AppState(_Repo([
        for (var i = 0; i < 6; i++) _mk('c$i', Severity.critical, 100 - i),
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
      expect(find.text('Filter'), findsOneWidget, reason: 'scale=$scale inactive -> "Filter"');
      final wInactive = tester.getSize(pill).width;
      expect(tester.takeException(), isNull, reason: 'scale=$scale inactive no overflow');

      // Activate two severities.
      await tester.tap(pill);
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('sevchip_critical')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('sevchip_high')));
      await tester.pumpAndSettle();
      await tester.tapAt(const Offset(10, 1300));
      await tester.pumpAndSettle();

      expect(find.text('2 filters'), findsOneWidget, reason: 'scale=$scale active -> "2 filters"');
      final wActive = tester.getSize(pill).width;
      expect(wActive, moreOrLessEquals(wInactive, epsilon: 0.5),
          reason: 'scale=$scale: pill width constant between states');
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
        _mk('done', Severity.critical, 0, state: AlertState.resolved),
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
        await tester.tap(find.byKey(const ValueKey('sevchip_critical')));
        await tester.pumpAndSettle();
        await tester.tapAt(const Offset(8, 1300));
        await tester.pumpAndSettle();
        expect(find.text('2 filters'), findsOneWidget);
      } else {
        expect(find.text('Filter'), findsOneWidget);
      }
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

  testWidgets('4 filters at the app smallest AND largest real font: one pinned row, all counts whole',
      (tester) async {
    // The app's actual extremes: zoom 1.0 x system 0.85 and zoom 1.2 x system 1.3.
    for (final (zoom, scale) in [(1.0, 0.85), (1.2, 1.3)]) {
      SharedPreferences.setMockInitialValues(
          {'ui.alertSeverities': ['low', 'medium', 'high', 'critical']});
      await _loadFonts();
      final state = AppState(_Repo([
        for (var i = 0; i < 287; i++) _mk('o$i', Severity.high, 1000 - i),
        _mk('done', Severity.critical, 0, state: AlertState.resolved),
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

      expect(find.text('4 filters'), findsOneWidget, reason: reason);
      expect(tester.takeException(), isNull, reason: reason);

      // All 288 / Open 287 / Resolved 1 all whole, with the button on one row.
      for (final t in ['All', 'Open', 'Resolved', '288', '287']) {
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

  testWidgets('375px, normal text: All 267 / Open 266 / Resolved 1 fit beside Filter',
      (tester) async {
    // Web at 375 wide goes through DesignScale; the unstacked tabs row is at its
    // tightest here with three-digit counts.
    SharedPreferences.setMockInitialValues({});
    await _loadFonts();
    final state = AppState(_Repo([
      for (var i = 0; i < 266; i++) _mk('o$i', Severity.high, 1000 - i),
      _mk('done', Severity.critical, 0, state: AlertState.resolved),
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

    for (final t in ['All', 'Open', 'Resolved', '267', '266']) {
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
}
