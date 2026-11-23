import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/devices/device_list_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/widgets/design_scale.dart';
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
    final request = ValueNotifier<Set<FilterPole>?>({FilterPole.untrusted});
    addTearDown(state.dispose);
    addTearDown(request.dispose);
    await tester.pumpWidget(MaterialApp(home: Scaffold(body:
      DeviceListScreen(state: state, filterRequest: request))));
    await tester.pump();
    expect(request.value, isNull);
    expect(find.text('DEVICES · 1 of 2'), findsOneWidget);
    expect(find.text('New'), findsOneWidget);
    expect(find.text('Known'), findsNothing);
  });

  testWidgets('filter labels stay full (no clipping) while the font size changes live', (tester) async {
    SharedPreferences.setMockInitialValues({});
    final state = AppState(DemoRepository())..loadedOnce = true;
    state.devices = const [
      Device(mac: 'aa', hostname: 'Known', presence: Presence.online, trusted: true),
    ];
    addTearDown(state.dispose);
    addTearDown(tester.view.reset);
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(320, 900);

    final scale = ValueNotifier<double>(0.85);
    final zoom = ValueNotifier<double>(1.0);
    addTearDown(scale.dispose);
    addTearDown(zoom.dispose);
    await tester.pumpWidget(MaterialApp(
      home: ListenableBuilder(
        listenable: Listenable.merge([scale, zoom]),
        builder: (context, _) => MediaQuery(
          data: MediaQuery.of(context).copyWith(textScaler: TextScaler.linear(scale.value)),
          child: DesignScale(
            zoom: zoom.value,
            child: Material(child: Scaffold(body: DeviceListScreen(state: state))),
          ),
        ),
      ),
    ));
    await tester.pump(const Duration(milliseconds: 300));

    // Open the filter menu, then change app zoom + system scale LIVE with the
    // menu open; the full pair labels must stay present (FittedBox shrinks, no
    // ellipsis) and nothing overflows during or after the change.
    await tester.tap(find.bySemanticsLabel(RegExp('^Filter devices')));
    await tester.pump(const Duration(milliseconds: 300));
    const labels = ['All', 'Attention', 'No attention needed', 'Trusted', 'Untrusted',
      'Online', 'Offline', 'Monitored', 'Not monitored'];
    for (final (z, s) in [(1.0, 0.85), (1.2, 1.0), (1.2, 1.3), (1.06, 1.3), (1.0, 0.85)]) {
      zoom.value = z;
      scale.value = s;
      await tester.pump();                                 // during the change
      expect(tester.takeException(), isNull, reason: 'during zoom=$z scale=$s');
      await tester.pump(const Duration(milliseconds: 320)); // settled
      expect(tester.takeException(), isNull, reason: 'settled zoom=$z scale=$s');
      for (final l in labels) {
        expect(find.text(l), findsOneWidget, reason: '"$l" must stay fully present at zoom=$z scale=$s');
      }
    }
  });
}
