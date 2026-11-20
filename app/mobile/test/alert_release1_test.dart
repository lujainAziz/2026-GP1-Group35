// Release 1 Threat Alert decisions in the app: Resolve is the only action
// (New -> Resolved), the "{device} · {first detection time}" line under the
// title (unlinked: "Unknown device"), the original rule name always kept in the
// details (never the rule ID), and the renamed "Network Alert Level" card
// (still Soon, Sprint 5).
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/alerts/alert_details_screen.dart';
import 'package:assas_mobile/screens/dashboard/dashboard_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

Map<String, dynamic> _alert(String id, {String? mac, String? displayTitle}) => {
      'id': id, 'kind': 'threat', 'title': 'ASSAS TEST High',
      if (displayTitle != null) 'display_title': displayTitle,
      'device_mac': mac, 'device_name': mac == null ? 'Unknown device' : 'Front Cam',
      'time': '2026-10-08T21:20:00', 'severity': 'high', 'state': 'new',
      'first_event_time': '2026-10-08T21:15:00',
      'last_event_time': '2026-10-08T21:20:00',
      'occurrence_count': 3, 'rule_id': '1000001',
    };

class _Repo extends DemoRepository {
  @override
  Future<List<SecurityAlert>?> getAlerts({int? limit}) async => [
        SecurityAlert.fromApi(_alert('unlinked', displayTitle: 'Network activity detected')),
        // No display_title: the title IS the rule name, which must still show.
        SecurityAlert.fromApi(_alert('same', mac: 'aa:bb:cc:dd:ee:ff')),
      ];
}

Future<AppState> _state(WidgetTester tester) async {
  final s = AppState(_Repo());
  addTearDown(s.dispose);
  await tester.runAsync(s.refresh);
  return s;
}

Future<void> _pumpDetails(WidgetTester tester, AppState s, String id) async {
  addTearDown(tester.view.reset);
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = const Size(400, 1400);
  await tester.pumpWidget(MaterialApp(
    theme: MobileTheme.light,
    home: AlertDetailsScreen(state: s, alertId: id),
  ));
  await tester.pump(const Duration(milliseconds: 60));
}

void main() {
  testWidgets('unlinked alert: "Unknown device · first detection"; Resolve only', (tester) async {
    final s = await _state(tester);
    await _pumpDetails(tester, s, 'unlinked');
    expect(find.text('Network activity detected'), findsOneWidget);
    expect(find.text('Unknown device · 8 Oct, 9:15 PM'), findsOneWidget);
    expect(find.text('Resolve'), findsOneWidget);
    expect(find.text('Review'), findsNothing);
    expect(find.text('Reviewed'), findsNothing);
    expect(find.text('3'), findsOneWidget); // detections
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('original rule row is kept even when it equals the title; no rule ID', (tester) async {
    final s = await _state(tester);
    await _pumpDetails(tester, s, 'same');
    expect(find.text('RULE'), findsOneWidget);
    expect(find.text('ASSAS TEST High'), findsNWidgets(2)); // heading + rule row
    // Team decision: the rule ID is never shown (still parsed from the API).
    expect(find.text('RULE ID'), findsNothing);
    expect(find.textContaining('1000001'), findsNothing);
    expect(s.alertById('same')!.ruleId, '1000001');
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('dashboard card reads Network Alert Level, Soon, Sprint 5', (tester) async {
    final s = await _state(tester);
    addTearDown(tester.view.reset);
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(400, 1400);
    await tester.pumpWidget(MaterialApp(
      theme: MobileTheme.light,
      home: Scaffold(body: DashboardScreen(state: s, onOpenDevices: () {}, onOpenAlerts: () {})),
    ));
    await tester.pump(const Duration(milliseconds: 300));
    expect(find.text('NETWORK ALERT LEVEL'), findsOneWidget);
    expect(find.text('NETWORK RISK'), findsNothing);
    expect(find.text('Soon'), findsOneWidget);
    expect(find.text('Network Alert Level arrives in Sprint 5'), findsOneWidget);
    await tester.pumpWidget(const SizedBox());
  });
}
