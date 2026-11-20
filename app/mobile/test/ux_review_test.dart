// Supervisor UX review:
// 1. Device screen: the "Alerts for this device" title is never cut off, even
//    beside the sort button at the largest text size.
// 2. "Why Assas noticed" keeps only "This matched a known security pattern."
// 3. Alert details: "Signal details" is an accordion, collapsed by default; the
//    heading (with a chevron) toggles the rows. Title, device/time line,
//    explanation, "Why Assas noticed" and Resolve stay visible.
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/alerts/alert_details_screen.dart';
import 'package:assas_mobile/screens/devices/device_details_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:assas_mobile/widgets/design_scale.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

const _camera = '7c:6b:cb:5a:21:5d'; // a demo device

SecurityAlert _mk(String id, {int sec = 0}) => SecurityAlert(
      id: id, kind: AlertKind.threat, title: 'Network scan', ruleName: 'ET SCAN rule $id',
      deviceMac: _camera, deviceName: 'Front door camera',
      time: DateTime(2026, 10, 8, 21, 20).add(Duration(seconds: sec)),
      firstTime: DateTime(2026, 10, 8, 21, 15),
      severity: Severity.medium, state: AlertState.newAlert, read: false,
      explanation: 'A device scanned the network.', occurrenceCount: 3,
      sourceIp: '192.0.2.10', destinationIp: '192.0.2.20',
    );

class _Repo extends DemoRepository {
  final list = [_mk('a1', sec: 10), _mk('a2')];
  @override
  Future<List<SecurityAlert>?> getAlerts({int? limit}) async => list;
  @override
  Future<List<SecurityAlert>?> getDeviceAlerts(String mac, {int? limit}) async =>
      list.where((a) => a.deviceMac == mac).toList();
  @override
  Future<SecurityAlert?> markAlertRead(String id) async => null;
  @override
  Future<void> setAlertState(String id, AlertState state) async {
    for (var i = 0; i < list.length; i++) {
      if (list[i].id == id) list[i] = list[i].copyWith(state: state);
    }
  }
}

Future<void> _fonts() async {
  for (final f in ['BricolageGrotesque', 'JetBrainsMono']) {
    final l = FontLoader(f == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
    l.addFont(rootBundle.load('assets/fonts/$f.ttf'));
    await l.load();
  }
}

Future<AppState> _state(WidgetTester tester) async {
  SharedPreferences.setMockInitialValues({});
  await _fonts();
  final s = AppState(_Repo());
  addTearDown(s.dispose);
  addTearDown(tester.view.reset);
  await tester.runAsync(s.refresh);
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = const Size(400, 1600);
  return s;
}

Future<void> _pumpDetails(WidgetTester tester, AppState s) async {
  await tester.pumpWidget(MaterialApp(
    theme: MobileTheme.light,
    home: AlertDetailsScreen(state: s, alertId: 'a1'),
  ));
  await tester.pump(const Duration(milliseconds: 100));
}

// SpecList labels are upper-case.
const _rows = ['ALERT TYPE', 'RULE', 'SEVERITY', 'DETECTIONS', 'FIRST DETECTED',
  'LAST DETECTED', 'SOURCE IP', 'DESTINATION IP'];

double _chevronTurns(WidgetTester tester) => tester
    .widget<AnimatedRotation>(find.descendant(
        of: find.byKey(const ValueKey('signalDetailsHeader')), matching: find.byType(AnimatedRotation)))
    .turns;

void main() {
  testWidgets('Signal details is collapsed by default; the rest stays visible', (tester) async {
    final s = await _state(tester);
    await _pumpDetails(tester, s);
    expect(find.text('Signal details'), findsOneWidget);
    expect(_chevronTurns(tester), 0); // pointing down = collapsed
    for (final r in _rows) {
      expect(find.text(r), findsNothing, reason: '$r should be collapsed');
    }
    // Always visible.
    expect(find.text('Network scan'), findsOneWidget); // title
    expect(find.text('Front door camera · 8 Oct, 9:15 PM'), findsOneWidget); // device + time
    expect(find.text('A device scanned the network.'), findsOneWidget); // explanation
    expect(find.text('WHY ASSAS NOTICED'), findsOneWidget);
    expect(find.text('Resolve'), findsOneWidget);
    // No separate show/hide button: the heading itself is the control.
    expect(find.textContaining('technical details'), findsNothing);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 1));
  });

  testWidgets('tapping the heading expands and collapses the rows', (tester) async {
    final s = await _state(tester);
    await _pumpDetails(tester, s);
    await tester.tap(find.text('Signal details'));
    await tester.pump(const Duration(milliseconds: 300));
    expect(_chevronTurns(tester), .5); // pointing up = expanded
    for (final r in _rows) {
      expect(find.text(r), findsOneWidget, reason: '$r should be shown');
    }
    expect(find.text('ET SCAN rule a1'), findsOneWidget);
    expect(find.text('Resolve'), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('signalDetailsHeader')));
    await tester.pump(const Duration(milliseconds: 300));
    expect(_chevronTurns(tester), 0);
    for (final r in _rows) {
      expect(find.text(r), findsNothing, reason: '$r should be collapsed again');
    }
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 1));
  });

  test('detection summary: same day shows times; different days show dates', () {
    expect(
      TimeFormat.detectionSummary(3, DateTime(2026, 10, 8, 21, 27), DateTime(2026, 10, 8, 21, 40)),
      'Detected 3 times · first 9:27 PM, last 9:40 PM',
    );
    expect(
      TimeFormat.detectionSummary(5, DateTime(2026, 10, 8, 23, 50), DateTime(2026, 10, 9, 0, 5)),
      'Detected 5 times · first 8 Oct, 11:50 PM, last 9 Oct, 12:05 AM',
    );
  });

  testWidgets('repeated alert: detection line under the title, visible while collapsed', (tester) async {
    final s = await _state(tester);
    await _pumpDetails(tester, s);
    expect(find.text('DETECTIONS'), findsNothing); // Signal details collapsed
    final line = find.byKey(const ValueKey('detectionLine'));
    expect(line, findsOneWidget);
    expect(tester.widget<Text>(line).data, 'Detected 3 times · first 9:15 PM, last 9:20 PM');
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 1));
  });

  testWidgets('a single detection has no detection line', (tester) async {
    final s = await _state(tester);
    (s.repo as _Repo).list[0] = SecurityAlert(
      id: 'a1', kind: AlertKind.threat, title: 'Network scan', deviceMac: _camera,
      deviceName: 'Front door camera', time: DateTime(2026, 10, 8, 21, 20),
      severity: Severity.medium, state: AlertState.newAlert, read: true,
    );
    await tester.runAsync(s.refresh);
    await _pumpDetails(tester, s);
    expect(find.byKey(const ValueKey('detectionLine')), findsNothing);
    expect(find.textContaining('Detected'), findsNothing);
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 1));
  });

  testWidgets('resolved alert reads "Resolved. Kept in your alert history."', (tester) async {
    final s = await _state(tester);
    await tester.runAsync(() => s.setAlertState('a1', AlertState.resolved));
    await _pumpDetails(tester, s);
    expect(find.text('Resolved. Kept in your alert history.'), findsOneWidget);
    expect(find.textContaining('kept in history for context'), findsNothing);
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 1));
  });

  testWidgets('device with no alerts: "No alerts for this device"', (tester) async {
    final s = await _state(tester);
    (s.repo as _Repo).list.clear();
    await tester.pumpWidget(MaterialApp(
      theme: MobileTheme.light,
      home: DeviceDetailsScreen(state: s, mac: _camera),
    ));
    await tester.pump(const Duration(milliseconds: 500));
    final title = find.text('No alerts for this device');
    await tester.scrollUntilVisible(title, 300, scrollable: find.byType(Scrollable).first);
    expect(title, findsOneWidget);
    expect(find.text('All quiet'), findsNothing);
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 1));
  });

  testWidgets('"Why Assas noticed" keeps only the first sentence', (tester) async {
    final s = await _state(tester);
    await _pumpDetails(tester, s);
    expect(find.text('This matched a known security pattern.'), findsOneWidget);
    expect(find.textContaining('ASSAS is showing the event'), findsNothing);
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 1));
  });

  testWidgets('"Alerts for this device" is never cut off beside the sort button', (tester) async {
    final s = await _state(tester);
    // The narrowest phone at the app's largest text: zoom 1.2 x system 1.3.
    tester.view.physicalSize = const Size(320, 1600);
    await tester.pumpWidget(MaterialApp(
      theme: MobileTheme.light,
      home: Builder(
        builder: (c) => MediaQuery(
          data: MediaQuery.of(c).copyWith(textScaler: const TextScaler.linear(1.3)),
          child: DesignScale(zoom: 1.2, child: DeviceDetailsScreen(state: s, mac: _camera)),
        ),
      ),
    ));
    await tester.pump(const Duration(milliseconds: 500));
    final title = find.text('Alerts for this device');
    await tester.scrollUntilVisible(title, 300, scrollable: find.byType(Scrollable).first);
    await tester.pump(const Duration(milliseconds: 100));
    expect(find.text('Newest'), findsOneWidget); // the sort button shares the row
    final paragraph = tester.renderObject<RenderParagraph>(title);
    expect(paragraph.didExceedMaxLines, isFalse, reason: 'the full title fits (wrapping if needed)');
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 1));
  });
}
