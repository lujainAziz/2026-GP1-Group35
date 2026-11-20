// Release 1 "read" marker and Home card:
// - Tabs All / Unread / Resolved; unread alerts show a dot and a bold title;
//   opening the details marks the alert read (no button, never a state change);
//   the Unread tab has a small count badge.
// - Read is per phone and not a state: states stay New / Resolved.
// - The Home "Unresolved alerts" card shows the DB count; 0 = "No unresolved
//   alerts"; a failed refresh keeps the last count with "Last known"; none = "—".
// - The word "open" never appears in visible text.
import 'dart:async';

import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/alerts/alert_details_screen.dart';
import 'package:assas_mobile/screens/alerts/alert_list_screen.dart';
import 'package:assas_mobile/screens/dashboard/dashboard_screen.dart';
import 'package:assas_mobile/screens/devices/device_details_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:assas_mobile/widgets/ui_kit.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

const _camera = '7c:6b:cb:00:01:5d'; // a demo device

SecurityAlert _mk(String id, {bool read = false, AlertState state = AlertState.newAlert, int sec = 0}) =>
    SecurityAlert(
      id: id, kind: AlertKind.threat, title: 'Title $id', deviceMac: _camera,
      deviceName: 'Front door camera',
      time: DateTime(2026, 11, 7, 10).add(Duration(seconds: sec)),
      severity: Severity.high, state: state, read: read,
    );

/// Serves [list]; mark-read and state changes update it like the appliance.
class _Repo extends DemoRepository {
  _Repo(this.list);
  List<SecurityAlert> list;
  int markCalls = 0;
  Completer<void>? markGate; // holds the mark-read write in flight
  Object? markError;
  bool failAlerts = false;

  @override
  Future<List<SecurityAlert>?> getAlerts({int? limit}) async {
    if (failAlerts) throw Exception('unreachable');
    return [...list]..sort((a, b) => b.time.compareTo(a.time));
  }

  @override
  Future<int?> getOpenAlertCount() async {
    if (failAlerts) throw Exception('unreachable');
    return list.where((a) => a.isUnresolved).length;
  }

  @override
  Future<SecurityAlert?> getAlertById(String id) async {
    for (final a in list) {
      if (a.id == id) return a;
    }
    return null;
  }

  @override
  Future<SecurityAlert?> markAlertRead(String id) async {
    markCalls++;
    if (markGate != null) await markGate!.future;
    if (markError != null) throw markError!;
    list = [for (final a in list) a.id == id ? a.copyWith(read: true) : a];
    return getAlertById(id);
  }

  @override
  Future<void> setAlertState(String id, AlertState state) async {
    list = [
      for (final a in list)
        a.id == id ? a.copyWith(state: state, read: state == AlertState.resolved ? true : null) : a,
    ];
  }
}

Future<void> _fonts() async {
  for (final f in ['BricolageGrotesque', 'JetBrainsMono']) {
    final l = FontLoader(f == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
    l.addFont(rootBundle.load('assets/fonts/$f.ttf'));
    await l.load();
  }
}

Future<AppState> _state(WidgetTester tester, _Repo repo, {Map<String, Object> prefs = const {}}) async {
  SharedPreferences.setMockInitialValues(prefs);
  await _fonts();
  final s = AppState(repo);
  addTearDown(s.dispose);
  addTearDown(tester.view.reset);
  await tester.runAsync(s.refresh);
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = const Size(390, 1600);
  return s;
}

Future<void> _pumpList(WidgetTester tester, AppState s) async {
  await tester.pumpWidget(MaterialApp(
    theme: MobileTheme.light,
    home: Scaffold(body: AlertListScreen(state: s)),
  ));
  await tester.pump(const Duration(milliseconds: 400));
}

Finder _card(String id) => find.byWidgetPredicate((w) => w is TimelineAlertCard && w.alert.id == id);
Finder _dotIn(String id) => find.descendant(of: _card(id), matching: find.byKey(const ValueKey('unreadDot')));
FontWeight? _titleWeight(WidgetTester tester, String id) => tester
    .widget<Text>(find.descendant(of: _card(id), matching: find.text('Title $id')))
    .style
    ?.fontWeight;

/// Every visible string on screen (Text and RichText).
List<String> _texts(WidgetTester tester) => [
      for (final w in tester.widgetList<Text>(find.byType(Text))) w.data ?? w.textSpan?.toPlainText() ?? '',
      for (final w in tester.widgetList<RichText>(find.byType(RichText))) w.text.toPlainText(),
    ];

void _expectNoOpenWord(WidgetTester tester, String where) {
  final hits = _texts(tester).where((t) => RegExp(r'\bopen\b', caseSensitive: false).hasMatch(t));
  expect(hits, isEmpty, reason: '$where shows "open": $hits');
}

void main() {
  group('model', () {
    test('read is parsed per phone and never a state', () {
      SecurityAlert a(Object? read) => SecurityAlert.fromApi(
          {'id': '1', 'title': 'x', 'time': '2026-11-02T10:00:00', 'state': 'new', 'read': read});
      expect(a(false).isUnread, isTrue);
      expect(a(true).isUnread, isFalse);
      expect(a(null).read, isNull); // appliance without read markers: no dot
      expect(a(null).isUnread, isFalse);
      expect(a(false).copyWith(read: true).isUnread, isFalse);
      expect(a(false).copyWith(read: true).state, AlertState.newAlert);
    });
  });

  group('Alerts screen', () {
    testWidgets('tabs All / Unread / Resolved; dot + bold title for unread; badge', (tester) async {
      final s = await _state(tester, _Repo([
        _mk('u1', sec: 30),
        _mk('u2', sec: 20),
        _mk('r1', read: true, sec: 10),
        _mk('done', state: AlertState.resolved, read: true),
      ]));
      await _pumpList(tester, s);
      for (final t in ['All', 'Unread', 'Resolved']) {
        expect(find.text(t), findsWidgets, reason: t);
      }
      expect(find.text('Open'), findsNothing);
      expect(find.text('unresolved alerts'), findsOneWidget); // header
      // Unread badge = this phone's unread, unresolved count.
      expect(find.descendant(of: find.byKey(const ValueKey('unreadBadge')), matching: find.text('2')),
          findsOneWidget);
      expect(_dotIn('u1'), findsOneWidget);
      expect(_titleWeight(tester, 'u1'), FontWeight.w800);
      expect(_dotIn('r1'), findsNothing);
      expect(_titleWeight(tester, 'r1'), FontWeight.w600);
      expect(find.text('Review'), findsNothing);
      expect(find.text('Reviewed'), findsNothing);
      _expectNoOpenWord(tester, 'Alerts');

      await tester.tap(find.text('Unread'));
      await tester.pump(const Duration(milliseconds: 400));
      expect(_card('u1'), findsOneWidget);
      expect(_card('u2'), findsOneWidget);
      expect(_card('r1'), findsNothing); // read
      expect(_card('done'), findsNothing); // resolved
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets('opening the details marks the alert read: dot and badge go', (tester) async {
      final repo = _Repo([_mk('u1', sec: 30), _mk('u2', sec: 20)]);
      final s = await _state(tester, repo);
      await _pumpList(tester, s);
      await tester.tap(find.text('Title u1'));
      for (var i = 0; i < 4; i++) {
        await tester.pump(const Duration(milliseconds: 150));
      }
      expect(find.byType(AlertDetailsScreen), findsOneWidget);
      expect(repo.markCalls, 1);
      expect(find.text('Mark as read'), findsNothing); // no button
      Navigator.of(tester.element(find.byType(AlertDetailsScreen))).pop();
      for (var i = 0; i < 6; i++) {
        await tester.pump(const Duration(milliseconds: 150));
      }
      expect(_dotIn('u1'), findsNothing);
      expect(_dotIn('u2'), findsOneWidget);
      expect(find.descendant(of: find.byKey(const ValueKey('unreadBadge')), matching: find.text('1')),
          findsOneWidget);
      // Not a state change.
      expect(s.alertById('u1')!.state, AlertState.newAlert);
      expect(s.unresolvedAlertCount, 2);
      // Opening an already-read alert does not write again.
      await tester.tap(find.text('Title u1'));
      for (var i = 0; i < 4; i++) {
        await tester.pump(const Duration(milliseconds: 150));
      }
      expect(find.byType(AlertDetailsScreen), findsOneWidget);
      expect(repo.markCalls, 1);
      await tester.pumpWidget(const SizedBox());
      await tester.pump(const Duration(seconds: 1));
    });

    testWidgets('empty Unread tab: "No unread alerts", never "All clear"', (tester) async {
      final s = await _state(tester, _Repo([_mk('r1', read: true)]));
      await _pumpList(tester, s);
      expect(find.byKey(const ValueKey('unreadBadge')), findsNothing); // no badge at 0
      await tester.tap(find.text('Unread'));
      await tester.pump(const Duration(milliseconds: 400));
      expect(find.text('No unread alerts'), findsOneWidget);
      expect(find.text('All clear.'), findsNothing);
      _expectNoOpenWord(tester, 'empty Unread');
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets('a saved "open" tab from before falls back to All', (tester) async {
      final s = await _state(tester, _Repo([_mk('u1'), _mk('r1', read: true, sec: 5)]),
          prefs: {'ui.alertTab': 'open'});
      await _pumpList(tester, s);
      expect(_card('u1'), findsOneWidget);
      expect(_card('r1'), findsOneWidget); // All shows both
      await tester.pumpWidget(const SizedBox());
    });
  });

  group('AppState.markAlertRead', () {
    testWidgets('optimistic, and a failed write puts the dot back', (tester) async {
      final repo = _Repo([_mk('u1')]);
      final s = await _state(tester, repo);
      repo.markGate = Completer<void>();
      repo.markError = Exception('write failed');
      final done = s.markAlertRead('u1');
      expect(s.alertById('u1')!.isUnread, isFalse); // at once
      expect(s.unreadCount, 0);
      repo.markGate!.complete();
      await tester.runAsync(() => done);
      expect(s.alertById('u1')!.isUnread, isTrue); // reverted
      expect(s.unreadCount, 1);
    });

    testWidgets('a poll during the write does not bring the dot back', (tester) async {
      final repo = _Repo([_mk('u1')]);
      final s = await _state(tester, repo);
      repo.markGate = Completer<void>();
      final done = s.markAlertRead('u1');
      await tester.runAsync(s.refresh); // the appliance still says unread
      expect(s.alertById('u1')!.isUnread, isFalse);
      expect(s.unreadCount, 0);
      repo.markGate!.complete();
      await tester.runAsync(() => done);
      // Let the refresh that follows the write finish (demo delays).
      await tester.pump(const Duration(seconds: 1));
      expect(s.alertById('u1')!.isUnread, isFalse);
      expect(s.unreadCount, 0);
      expect(repo.list.single.read, isTrue); // the appliance has it now
    });

    testWidgets('resolving makes the alert read and leaves the Unread badge', (tester) async {
      final repo = _Repo([_mk('u1'), _mk('u2', sec: 5)]);
      final s = await _state(tester, repo);
      expect(s.unreadCount, 2);
      await tester.runAsync(() => s.setAlertState('u1', AlertState.resolved));
      expect(s.alertById('u1')!.read, isTrue);
      expect(s.unreadCount, 1);
      expect(s.unresolvedAlertCount, 1);
    });
  });

  group('Home "Unresolved alerts" card', () {
    Future<void> pumpHome(WidgetTester tester, AppState s) async {
      await tester.pumpWidget(MaterialApp(
        theme: MobileTheme.light,
        home: Scaffold(body: DashboardScreen(state: s, onOpenDevices: () {}, onOpenAlerts: () {})),
      ));
      await tester.pump(const Duration(milliseconds: 300));
    }

    Text count(WidgetTester tester) => tester.widget<Text>(find.byKey(const ValueKey('unresolvedCount')));
    Finder note() => find.byKey(const ValueKey('unresolvedNote'));

    testWidgets('shows the DB count; Network Alert Level stays Soon, Sprint 5', (tester) async {
      final s = await _state(tester, _Repo([_mk('u1'), _mk('r1', read: true, sec: 5),
          _mk('done', state: AlertState.resolved, read: true)]));
      await pumpHome(tester, s);
      expect(find.text('Unresolved\nalerts'), findsOneWidget);
      expect(count(tester).data, '2');
      expect(count(tester).style?.color, Ui.high);
      expect(note(), findsNothing);
      expect(find.text('NETWORK ALERT LEVEL'), findsOneWidget);
      expect(find.text('Soon'), findsOneWidget);
      expect(find.text('Network Alert Level arrives in Sprint 5'), findsOneWidget);
      _expectNoOpenWord(tester, 'Home');
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets('0 is muted with "No unresolved alerts" (never "All clear")', (tester) async {
      final s = await _state(tester, _Repo([_mk('done', state: AlertState.resolved, read: true)]));
      await pumpHome(tester, s);
      expect(count(tester).data, '0');
      expect(count(tester).style?.color, Ui.mute);
      expect(find.text('No unresolved alerts'), findsOneWidget);
      expect(find.textContaining('All clear'), findsNothing);
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets('a failed refresh keeps the last count dimmed with "Last known"', (tester) async {
      final repo = _Repo([_mk('u1'), _mk('u2', sec: 5)]);
      final s = await _state(tester, repo);
      repo.failAlerts = true;
      await tester.runAsync(s.refresh);
      await pumpHome(tester, s);
      expect(count(tester).data, '2');
      expect(find.text('Last known'), findsOneWidget);
      expect(count(tester).style?.color, isNot(Ui.high));
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets('no count yet shows "—"', (tester) async {
      final repo = _Repo([_mk('u1')])..failAlerts = true;
      final s = await _state(tester, repo);
      await pumpHome(tester, s);
      expect(count(tester).data, '—');
      expect(note(), findsNothing);
      await tester.pumpWidget(const SizedBox());
    });
  });

  testWidgets('device details: verdict reads "UNRESOLVED HIGH ALERT", no "open"', (tester) async {
    final s = await _state(tester, _Repo([_mk('u1')]));
    await tester.pumpWidget(MaterialApp(
      theme: MobileTheme.light,
      home: DeviceDetailsScreen(state: s, mac: _camera),
    ));
    await tester.pump(const Duration(milliseconds: 500));
    expect(find.text('UNRESOLVED HIGH ALERT'), findsOneWidget);
    _expectNoOpenWord(tester, 'Device details');
    await tester.pumpWidget(const SizedBox());
  });
}
