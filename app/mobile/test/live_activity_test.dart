import 'dart:convert';
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/widgets/activity_strip.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  testWidgets('HTTP capture data reaches graph and tags; failure removes it', (tester) async {
    var fail = false;
    final client = ApiClient(baseUrl: 'http://localhost', client: MockClient((r) async {
      switch (r.url.path) {
        case '/healthz': return http.Response('{}', 200);
        case '/devices': return http.Response('[]', 200);
        case '/activity': return fail ? http.Response('', 503) : http.Response(jsonEncode({
          'available': true, 'stale': false,
          'samples': [{'packets_per_second': 2}, {'packets_per_second': 8.4}],
          'protocols': ['ARP', 'MDNS'],
        }), 200);
        default: return http.Response('', 404);
      }
    }));
    final state = AppState(ApiRepository(client));
    addTearDown(state.dispose);
    addTearDown(client.dispose);
    await state.refresh();
    Widget screen() => MaterialApp(home: Scaffold(body: Column(children: [
      ActivityTrace(activity: state.activity, connected: true),
      ObservedProtocols(activity: state.activity, connected: true),
    ])));
    await tester.pumpWidget(screen());
    expect(find.text('LIVE SIGNAL · 8.4 pkt/s'), findsOneWidget);
    expect(find.text('ARP'), findsOneWidget);
    expect(find.text('MDNS'), findsOneWidget);
    expect(find.text('CAMERA'), findsNothing);
    fail = true;
    await state.refresh();
    await tester.pumpWidget(screen());
    expect(find.text('WAITING FOR TRAFFIC DATA'), findsOneWidget);
    expect(find.text('ARP'), findsNothing);
  });

  testWidgets('idle data is zero; stale or disconnected data is not live', (tester) async {
    for (final stale in [false, true]) {
      final data = LiveActivity(samples: [0, 0], protocols: [], stale: stale);
      await tester.pumpWidget(MaterialApp(home: ActivityTrace(activity: data, connected: true)));
      expect(find.text(stale ? 'SIGNAL STALE' : 'LIVE SIGNAL · 0.0 pkt/s'), findsOneWidget);
    }
    await tester.pumpWidget(const MaterialApp(home: ActivityTrace(
      activity: LiveActivity(samples: [8], protocols: ['ARP'], stale: false), connected: false)));
    expect(find.text('SIGNAL UNAVAILABLE'), findsOneWidget);
  });

  test('demo has no fabricated live traffic', () async {
    expect(await DemoRepository().getActivity(), isNull);
  });
}
