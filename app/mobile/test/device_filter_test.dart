import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/devices/device_list_screen.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:assas_mobile/widgets/design_scale.dart';
import 'package:assas_mobile/widgets/filter_button.dart';
import 'package:assas_mobile/widgets/ui_kit.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

const _poleLabels = ['Attention', 'No attention', 'Trusted', 'Untrusted',
  'Online', 'Offline', 'Monitored', 'Not monitored'];

final _button = find.byKey(const ValueKey('deviceFilterButton'));
final _dot = find.byKey(const ValueKey('filterActiveDot'));

/// Devices tab at app [zoom] x system [scale] (the app's extremes are
/// 1.0 x 0.85 and 1.2 x 1.3).
Future<AppState> _pumpDevices(WidgetTester tester,
    {double zoom = 1.0, double scale = 1.0, Map<String, Object> prefs = const {}}) async {
  SharedPreferences.setMockInitialValues(prefs);
  final state = AppState(DemoRepository())..loadedOnce = true;
  state.devices = const [
    Device(mac: 'aa', hostname: 'Known', presence: Presence.online, trusted: true),
    Device(mac: 'bb', hostname: 'New', presence: Presence.online, trusted: false),
    Device(mac: 'cc', hostname: 'Away', presence: Presence.offline, trusted: true),
  ];
  addTearDown(state.dispose);
  addTearDown(tester.view.reset);
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = const Size(390, 900);
  await tester.pumpWidget(MaterialApp(
    home: Builder(
      builder: (c) => MediaQuery(
        data: MediaQuery.of(c).copyWith(textScaler: TextScaler.linear(scale)),
        child: DesignScale(
          zoom: zoom,
          child: Material(child: Scaffold(body: DeviceListScreen(state: state))),
        ),
      ),
    ),
  ));
  await tester.pump(const Duration(milliseconds: 300));
  return state;
}

Color _buttonFill(WidgetTester tester) => tester
    .widget<Glass>(find.descendant(of: _button, matching: find.byType(Glass)))
    .color;

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
    await tester.tap(find.bySemanticsLabel('Filter, none selected'));
    await tester.pump(const Duration(milliseconds: 300));
    const labels = ['All', ..._poleLabels];
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

  testWidgets('filter button is icon-only and fixed-size; active = accent fill + dot; '
      'search field keeps its width and style', (tester) async {
    for (final (zoom, scale) in [(1.0, 0.85), (1.0, 1.0), (1.2, 1.3)]) {
      final reason = 'zoom=$zoom scale=$scale';
      await _pumpDevices(tester, zoom: zoom, scale: scale);

      // Inactive: outlined, no dot, no text, fixed size, state in semantics.
      expect(tester.getSize(_button), const Size.square(FilterButton.size), reason: reason);
      expect(_dot, findsNothing, reason: reason);
      expect(_buttonFill(tester), Ui.fade(Ui.surf, .82), reason: reason);
      expect(find.bySemanticsLabel('Filter, none selected'), findsOneWidget, reason: reason);
      expect(find.descendant(of: _button, matching: find.byType(Text)), findsNothing, reason: reason);
      final searchSize = tester.getSize(find.byType(TextField));
      final searchStyle = tester.widget<TextField>(find.byType(TextField)).style;

      // Select two filters from the menu, then close it.
      await tester.tap(_button);
      await tester.pump(const Duration(milliseconds: 300));
      await tester.tap(find.text('Trusted'));
      await tester.pump();
      await tester.tap(find.text('Online'));
      await tester.pump();
      await tester.tapAt(const Offset(10, 880));
      await tester.pump(const Duration(milliseconds: 300));

      // Active: accent fill + dot, still no text and the same size.
      expect(tester.getSize(_button), const Size.square(FilterButton.size), reason: reason);
      expect(_dot, findsOneWidget, reason: reason);
      expect(_buttonFill(tester), Ui.mix(Ui.acc, .22, Ui.surf), reason: reason);
      expect(find.bySemanticsLabel('Filter, 2 selected'), findsOneWidget, reason: reason);
      expect(find.descendant(of: _button, matching: find.byType(Text)), findsNothing, reason: reason);
      for (final t in ['Filter', '2 filters', 'Trusted', 'Online']) {
        expect(find.text(t), findsNothing, reason: '$reason: no visible "$t" on the button');
      }
      // The filter applied (only the trusted, online device is listed).
      expect(find.text('Known'), findsOneWidget, reason: reason);
      expect(find.text('New'), findsNothing, reason: reason);

      // The search field did not move, grow or shrink, and kept its style.
      expect(tester.getSize(find.byType(TextField)), searchSize, reason: reason);
      expect(tester.widget<TextField>(find.byType(TextField)).style, searchStyle, reason: reason);
      expect(tester.takeException(), isNull, reason: reason);

      // One filter: still the dot; the count is only in the semantics.
      await tester.tap(_button);
      await tester.pump(const Duration(milliseconds: 300));
      await tester.tap(find.text('Online'));
      await tester.pump();
      await tester.tapAt(const Offset(10, 880));
      await tester.pump(const Duration(milliseconds: 300));
      expect(find.bySemanticsLabel('Filter, 1 selected'), findsOneWidget, reason: reason);
      expect(_dot, findsOneWidget, reason: reason);
      expect(tester.getSize(find.byType(TextField)), searchSize, reason: reason);

      await tester.pumpWidget(const SizedBox());
    }
  });

  testWidgets('menu: every option label renders at the same size, also at the largest text',
      (tester) async {
    for (final (zoom, scale) in [(1.0, 0.85), (1.0, 1.0), (1.2, 1.3)]) {
      final reason = 'zoom=$zoom scale=$scale';
      await _pumpDevices(tester, zoom: zoom, scale: scale);
      await tester.tap(_button);
      await tester.pump(const Duration(milliseconds: 300));
      // Select one so a check mark shows; it must not change any label's size.
      await tester.tap(find.text('No attention'));
      await tester.pump();

      // On-screen height = font size x every scale applied (FittedBox included).
      final ref = tester.getRect(find.text('No attention')).height;
      for (final l in _poleLabels) {
        expect(tester.getRect(find.text(l)).height, moreOrLessEquals(ref, epsilon: 0.01),
            reason: '$reason: "$l" must render at the same size as "No attention"');
        expect(tester.widget<Text>(find.text(l)).style, UiText.menuItem,
            reason: '$reason: "$l" same font size and weight');
      }
      expect(find.text('No attention needed'), findsNothing, reason: reason);
      expect(tester.takeException(), isNull, reason: reason);
      await tester.pumpWidget(const SizedBox());
    }
  });

  testWidgets('a stored filter from an older session still restores', (tester) async {
    // The stored format (comma-joined pole names) and key are unchanged.
    await _pumpDevices(tester, prefs: {'ui.deviceFilter': 'notAttention,trusted'});
    await tester.pump();
    expect(find.bySemanticsLabel('Filter, 2 selected'), findsOneWidget);
    expect(_dot, findsOneWidget);
    expect(find.text('New'), findsNothing);
    expect(find.text('Known'), findsOneWidget);
    expect(find.text('Away'), findsOneWidget);
  });

  testWidgets('filters matching no device: general hint that names no filter', (tester) async {
    // No device is both untrusted and offline.
    await _pumpDevices(tester, prefs: {'ui.deviceFilter': 'untrusted,offline'});
    await tester.pump();
    expect(find.text('No devices found'), findsOneWidget);
    expect(find.text('No devices match the selected filters.'), findsOneWidget);
    expect(find.textContaining('No devices in'), findsNothing);
    expect(find.textContaining('Untrusted'), findsNothing);
    expect(find.textContaining('2 filters'), findsNothing);
  });

  testWidgets('search + filters matching nothing: general hint; search alone keeps its hint',
      (tester) async {
    // Search with a filter set: the hint names the term, not the filter.
    await _pumpDevices(tester, prefs: {'ui.deviceFilter': 'trusted', 'ui.deviceSearch': 'zzz'});
    await tester.pump();
    expect(find.text('No devices found'), findsOneWidget);
    expect(find.text('Nothing matches “zzz” with the selected filters.'), findsOneWidget);
    expect(find.textContaining(' in Trusted'), findsNothing);
    await tester.pumpWidget(const SizedBox());

    // Search alone: unchanged.
    await _pumpDevices(tester, prefs: {'ui.deviceSearch': 'zzz'});
    await tester.pump();
    expect(find.text('No devices found'), findsOneWidget);
    expect(find.text('Nothing matches “zzz”.'), findsOneWidget);
  });
}
