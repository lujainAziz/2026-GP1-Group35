import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/devices/device_list_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  testWidgets('dashboard filter on first build overrides saved filter', (tester) async {
    SharedPreferences.setMockInitialValues({'ui.deviceFilter': 'trusted'});
    final state = AppState(DemoRepository())..loadedOnce = true;
    state.devices = const [
      Device(mac: 'aa', hostname: 'Known', presence: Presence.online, trusted: true),
      Device(mac: 'bb', hostname: 'New', presence: Presence.online, trusted: false),
    ];
    final request = ValueNotifier<DeviceFilter?>(DeviceFilter.unrecognized);
    addTearDown(state.dispose);
    addTearDown(request.dispose);
    await tester.pumpWidget(MaterialApp(home: Scaffold(body:
      DeviceListScreen(state: state, filterRequest: request))));
    await tester.pump();
    expect(request.value, isNull);
    expect(find.text('DEVICE INDEX · 1 / 2'), findsOneWidget);
    expect(find.text('New'), findsOneWidget);
    expect(find.text('Known'), findsNothing);
  });
}
