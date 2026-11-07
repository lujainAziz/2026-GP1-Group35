// Sort, severity filter, hide-resolved, load-older-with-filter, and the
// back-to-top button on the alerts list.
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/alerts/alert_list_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
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
  testWidgets('default sort is newest first; toggling sorts most-severe first',
      (tester) async {
    await _pump(tester, [
      _mk('crit', Severity.critical, 0),   // oldest
      _mk('low', Severity.low, 30),
      _mk('high', Severity.high, 60),      // newest
    ]);
    // Newest first by default.
    expect(_cardOrder(tester), ['high', 'low', 'crit']);
    expect(find.text('Newest'), findsOneWidget);

    // Switch to most-severe first.
    await tester.tap(find.text('Newest'));
    await tester.pumpAndSettle();
    expect(find.text('Most severe'), findsOneWidget);
    expect(_cardOrder(tester), ['crit', 'high', 'low']);
  });

  testWidgets('severity filter hides unselected severities', (tester) async {
    await _pump(tester, [
      _mk('crit', Severity.critical, 0),
      _mk('med', Severity.medium, 30),
      _mk('high', Severity.high, 60),
    ]);
    expect(_cardOrder(tester).toSet(), {'crit', 'med', 'high'});

    // Open the filter sheet and uncheck "Medium".
    await tester.tap(find.text('Filter'));
    await tester.pumpAndSettle();
    await tester.tap(find.bySemanticsLabel('Medium alerts shown'));
    await tester.pumpAndSettle();
    // Close the sheet (tap the modal barrier in the far corner).
    await tester.tapAt(const Offset(8, 8));
    await tester.pumpAndSettle();

    final ids = _cardOrder(tester).toSet();
    expect(ids.contains('med'), isFalse); // medium hidden
    expect(ids.containsAll({'crit', 'high'}), isTrue);
  });

  testWidgets('hide-resolved removes resolved alerts from the All view but keeps them loaded',
      (tester) async {
    final state = await _pump(tester, [
      _mk('open1', Severity.high, 60),
      _mk('done', Severity.critical, 30, state: AlertState.resolved),
      _mk('open2', Severity.medium, 0),
    ]);
    expect(_cardOrder(tester).toSet(), {'open1', 'done', 'open2'});

    await tester.tap(find.text('Filter'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Hide resolved alerts'));
    await tester.pumpAndSettle();
    await tester.tapAt(const Offset(8, 8));
    await tester.pumpAndSettle();

    expect(_cardOrder(tester).contains('done'), isFalse); // hidden from view
    // Nothing deleted: the resolved alert is still in the loaded data + state.
    expect(state.alerts!.any((a) => a.id == 'done' && a.state == AlertState.resolved), isTrue);
  });

  testWidgets('filter keeps "Load older" available so it reaches the full list',
      (tester) async {
    // 2000 newest are Medium (fills the first page -> alertsHaveMore), with a
    // Critical one older than the page. Filtering to Critical empties the loaded
    // page, but the load-older affordance must remain so older matches load.
    final many = [
      for (var i = 0; i < 2000; i++) _mk('m$i', Severity.medium, 10000 - i),
      _mk('crit-old', Severity.critical, 0),
    ];
    final state = await _pump(tester, many);
    expect(state.alertsHaveMore, isTrue);

    await tester.tap(find.text('Filter'));
    await tester.pumpAndSettle();
    await tester.tap(find.bySemanticsLabel('Medium alerts shown')); // hide Medium -> page empties
    await tester.pumpAndSettle();
    await tester.tapAt(const Offset(8, 8));
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
