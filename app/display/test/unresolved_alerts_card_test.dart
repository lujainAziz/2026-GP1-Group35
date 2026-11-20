// The 7-inch display's "Unresolved alerts" card: the DB count of New alerts
// from GET /alerts/open_count (getOpenAlertCount), never a downloaded list.
// 0 is muted with "No unresolved alerts"; a failed poll keeps the last count
// dimmed with "Last known"; no count yet (or no endpoint) shows "—".
import 'package:assas_core/assas_core.dart';
import 'package:assas_design/theme/assas_ui.dart';
import 'package:assas_display/display_ui.dart';
import 'package:assas_display/screens/status_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

/// Answers getOpenAlertCount with [results] in turn (the last one repeats):
/// an int, null (endpoint missing, 404) or an Exception (API unreachable).
class _CountRepo extends DemoRepository {
  _CountRepo(this.results);
  final List<Object?> results;
  int countCalls = 0;
  int alertListCalls = 0;

  @override
  Future<int?> getOpenAlertCount() async {
    final r = results[countCalls < results.length ? countCalls : results.length - 1];
    countCalls++;
    if (r is Exception) throw r;
    return r as int?;
  }

  @override
  Future<List<SecurityAlert>?> getAlerts({int? limit}) async {
    alertListCalls++;
    return const [];
  }

  @override
  Future<List<PairedPhone>?> getPairedPhones() async => const [];
}

Future<_CountRepo> _pump(WidgetTester tester, List<Object?> results) async {
  await tester.binding.setSurfaceSize(const Size(1024, 600));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  for (final font in ['BricolageGrotesque', 'JetBrainsMono']) {
    final loader = FontLoader(font == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
    loader.addFont(rootBundle.load('assets/fonts/$font.ttf'));
    await loader.load();
  }
  final repo = _CountRepo(results);
  await tester.pumpWidget(MaterialApp(theme: DisplayUi.theme, home: StatusScreen(repo: repo)));
  await _settle(tester);
  return repo;
}

// One refresh: health + devices (demo delays) + the count.
Future<void> _settle(WidgetTester tester) async {
  for (var i = 0; i < 4; i++) {
    await tester.pump(const Duration(milliseconds: 250));
  }
}

// The next 5-second poll.
Future<void> _nextPoll(WidgetTester tester) async {
  await tester.pump(const Duration(seconds: 4));
  await _settle(tester);
}

String _count(WidgetTester tester) =>
    tester.widget<Text>(find.byKey(const ValueKey('unresolvedCount'))).data!;
Color? _countColor(WidgetTester tester) =>
    tester.widget<Text>(find.byKey(const ValueKey('unresolvedCount'))).style?.color;
Finder get _note => find.byKey(const ValueKey('unresolvedNote'));

Future<void> _end(WidgetTester tester) async {
  expect(tester.takeException(), isNull);
  await tester.pumpWidget(const SizedBox());
  await tester.pump(const Duration(seconds: 1));
}

void main() {
  testWidgets('shows the DB count of New alerts, not a downloaded list', (tester) async {
    final repo = await _pump(tester, [3]);
    expect(_count(tester), '3');
    expect(_countColor(tester), Ui.high);
    expect(_note, findsNothing);
    expect(repo.countCalls, greaterThan(0));
    expect(repo.alertListCalls, 0);
    // No Soon tag on this card; the Network Alert Level card stays Soon.
    expect(find.text('SOON · SPRINT 2'), findsNothing);
    expect(find.text('SOON · SPRINT 5'), findsOneWidget);
    await _end(tester);
  });

  testWidgets('0 is muted with "No unresolved alerts" (never "All clear")', (tester) async {
    await _pump(tester, [0]);
    expect(_count(tester), '0');
    expect(_countColor(tester), Ui.mute);
    expect(find.text('No unresolved alerts'), findsOneWidget);
    expect(find.text('All clear'), findsNothing);
    expect(find.textContaining(RegExp('open', caseSensitive: false)), findsNothing);
    await _end(tester);
  });

  testWidgets('no endpoint (404) or first poll failing shows "—"', (tester) async {
    await _pump(tester, [null]);
    expect(_count(tester), '—');
    expect(_note, findsNothing);
    await _end(tester);

    await _pump(tester, [Exception('unreachable')]);
    expect(_count(tester), '—');
    expect(find.text('Last known'), findsNothing);
    await _end(tester);
  });

  testWidgets('a failed poll keeps the last count dimmed with "Last known"; recovery clears it',
      (tester) async {
    await _pump(tester, [5, Exception('unreachable'), 4]);
    expect(_count(tester), '5');
    expect(_note, findsNothing);

    await _nextPoll(tester);
    expect(_count(tester), '5');
    expect(find.text('Last known'), findsOneWidget);
    expect(_countColor(tester), isNot(Ui.high)); // dimmed

    await _nextPoll(tester);
    expect(_count(tester), '4');
    expect(_countColor(tester), Ui.high);
    expect(_note, findsNothing);
    await _end(tester);
  });

  testWidgets('a failed poll after 0 keeps "0" with "Last known"', (tester) async {
    await _pump(tester, [0, Exception('unreachable')]);
    await _nextPoll(tester);
    expect(_count(tester), '0');
    expect(find.text('Last known'), findsOneWidget);
    expect(find.text('No unresolved alerts'), findsNothing);
    await _end(tester);
  });
}
