import 'package:assas_core/assas_core.dart';
import 'package:flutter_test/flutter_test.dart';

SecurityAlert _a(String id, Severity sev, DateTime t) => SecurityAlert(
      id: id,
      kind: AlertKind.threat,
      title: 'sig $id',
      deviceName: 'dev',
      time: t,
      severity: sev,
      state: AlertState.newAlert,
    );

void main() {
  final t0 = DateTime(2026, 11, 7, 10, 0, 0);
  DateTime at(int sec) => t0.add(Duration(seconds: sec));

  group('sortedAlerts', () {
    test('newest first orders by event time descending', () {
      final out = sortedAlerts([
        _a('old', Severity.low, at(0)),
        _a('new', Severity.low, at(100)),
        _a('mid', Severity.low, at(50)),
      ], AlertSort.newest);
      expect(out.map((a) => a.id).toList(), ['new', 'mid', 'old']);
    });

    test('most severe first: High, Medium, Low', () {
      final out = sortedAlerts([
        _a('med', Severity.medium, at(10)),
        _a('low', Severity.low, at(10)),
        _a('high', Severity.high, at(10)),
      ], AlertSort.severity);
      expect(out.map((a) => a.id).toList(), ['high', 'med', 'low']);
    });

    test('equal severity falls back to newest first', () {
      final out = sortedAlerts([
        _a('h-old', Severity.high, at(0)),
        _a('h-new', Severity.high, at(90)),
        _a('m', Severity.medium, at(95)),
      ], AlertSort.severity);
      // High leads even though Medium is newest; within High newer comes first.
      expect(out.map((a) => a.id).toList(), ['h-new', 'h-old', 'm']);
    });

    test('does not mutate the input list', () {
      final input = [_a('a', Severity.low, at(0)), _a('b', Severity.high, at(1))];
      final copy = List.of(input);
      sortedAlerts(input, AlertSort.severity);
      expect(input.map((a) => a.id).toList(), copy.map((a) => a.id).toList());
    });
  });

  group('alertsWithSeverity', () {
    final all = [
      _a('h', Severity.high, at(2)),
      _a('m', Severity.medium, at(1)),
      _a('l', Severity.low, at(0)),
    ];

    test('keeps only the selected severities', () {
      final out = alertsWithSeverity(all, {Severity.high, Severity.low});
      expect(out.map((a) => a.id).toList(), ['h', 'l']);
    });

    test('empty set shows everything (no accidental blank list)', () {
      expect(alertsWithSeverity(all, <Severity>{}).length, 3);
    });

    test('a full set shows everything', () {
      expect(alertsWithSeverity(all, Severity.values.toSet()).length, 3);
    });
  });
}
