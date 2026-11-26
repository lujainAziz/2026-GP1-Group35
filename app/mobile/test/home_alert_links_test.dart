// Home's two links to Alerts ("Unresolved alerts" card, "SEE ALL") always open
// the All tab at the top; the bottom navigation restores the last tab.
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/config/data_source.dart';
import 'package:assas_mobile/screens/alerts/alert_list_screen.dart';
import 'package:assas_mobile/screens/shell/main_shell.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

SecurityAlert _mk(String id, int sec, {AlertState state = AlertState.newAlert}) => SecurityAlert(
      id: id,
      kind: AlertKind.threat,
      title: 'sig $id',
      deviceName: 'dev',
      time: DateTime(2026, 11, 7, 10).add(Duration(seconds: sec)),
      severity: Severity.high,
      state: state,
      read: state == AlertState.resolved,
    );

/// Three unresolved alerts (newest) on top of many resolved ones, so the
/// Resolved tab scrolls and the All tab starts with an unresolved alert.
class _Repo extends DemoRepository {
  final List<SecurityAlert> _list = [
    for (var i = 0; i < 3; i++) _mk('u$i', 1000 - i),
    for (var i = 0; i < 40; i++) _mk('r$i', 500 - i, state: AlertState.resolved),
  ];

  @override
  Future<List<SecurityAlert>?> getAlerts({int? limit}) async =>
      limit != null && _list.length > limit ? _list.sublist(0, limit) : _list;

  @override
  Future<int?> getOpenAlertCount() async => _list.where((a) => a.isUnresolved).length;
}

Future<void> _settle(WidgetTester tester, [int ms = 1200]) async {
  for (var t = 0; t < ms; t += 100) {
    await tester.pump(const Duration(milliseconds: 100));
  }
}

Future<void> _pumpShell(WidgetTester tester, {required int tab}) async {
  SharedPreferences.setMockInitialValues({
    'ui.tab': tab,
    'ui.alertTab': 'resolved',
    'ui.alertSeverities': ['high'],
  });
  addTearDown(tester.view.reset);
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = const Size(390, 2000);
  await tester.pumpWidget(const MaterialApp(home: MainShell()));
  await _settle(tester);
}

Future<void> _tapNav(WidgetTester tester, String tab) async {
  await tester.tap(find.bySemanticsLabel(RegExp('^$tab tab')));
  await _settle(tester);
}

ScrollController _alertScroll(WidgetTester tester) => tester
    .widget<CustomScrollView>(find.descendant(
        of: find.byType(AlertListScreen), matching: find.byType(CustomScrollView)))
    .controller!;

Finder _alertCard(String id) => find.descendant(
    of: find.byType(AlertListScreen), matching: find.text('sig $id'));

Future<String?> _savedTab() async => (await SharedPreferences.getInstance()).getString('ui.alertTab');

void _expectResolvedTab() {
  expect(_alertCard('u0'), findsNothing);
  expect(_alertCard('r0'), findsOneWidget);
}

void _expectAllTab() {
  expect(_alertCard('u0'), findsOneWidget);
}

/// Opens Alerts (restored on Resolved), scrolls it down, then goes back Home.
Future<void> _scrolledResolvedThenHome(WidgetTester tester) async {
  await _pumpShell(tester, tab: 2);
  _expectResolvedTab();
  _alertScroll(tester).jumpTo(800);
  await _settle(tester, 300);
  expect(_alertScroll(tester).offset, greaterThan(0));
  await _tapNav(tester, 'Home');
}

Future<void> _expectAllAtTop(WidgetTester tester) async {
  _expectAllTab();
  expect(_alertScroll(tester).offset, 0);
  expect(await _savedTab(), 'all');
  // The severity filter is left alone.
  expect((await SharedPreferences.getInstance()).getStringList('ui.alertSeverities'), ['high']);
  expect(find.byKey(const ValueKey('filterActiveDot')), findsOneWidget);
}

void main() {
  setUpAll(() => repository = _Repo());

  testWidgets('Home "Unresolved alerts" opens All at the top, not the last tab (Resolved)',
      (tester) async {
    await _scrolledResolvedThenHome(tester);
    await tester.tap(find.byKey(const ValueKey('unresolvedCount')));
    await _settle(tester);
    await _expectAllAtTop(tester);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('Home "SEE ALL" opens All at the top, not the last tab (Resolved)', (tester) async {
    await _scrolledResolvedThenHome(tester);
    await tester.ensureVisible(find.text('SEE ALL →'));
    await _settle(tester, 300);
    await tester.tap(find.text('SEE ALL →'));
    await _settle(tester);
    await _expectAllAtTop(tester);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('Home link on the first build of Alerts wins over the saved Resolved tab',
      (tester) async {
    await _pumpShell(tester, tab: 0);
    await tester.tap(find.byKey(const ValueKey('unresolvedCount')));
    await _settle(tester);
    await _expectAllAtTop(tester);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('bottom navigation still restores the last tab (Resolved)', (tester) async {
    await _pumpShell(tester, tab: 0);
    await _tapNav(tester, 'Alerts');
    _expectResolvedTab();
    expect(await _savedTab(), 'resolved');

    // After a Home link chose All, a manual Resolved choice is again what the
    // bottom navigation brings back.
    await _tapNav(tester, 'Home');
    await tester.tap(find.byKey(const ValueKey('unresolvedCount')));
    await _settle(tester);
    _expectAllTab();
    await tester.tap(find.descendant(
        of: find.byType(AlertListScreen), matching: find.text('Resolved')).first);
    await _settle(tester, 400);
    _expectResolvedTab();
    await _tapNav(tester, 'Home');
    await _tapNav(tester, 'Alerts');
    _expectResolvedTab();
    expect(await _savedTab(), 'resolved');
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });
}
