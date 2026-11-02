// Sprint 2 (PBI-14) Threat Alert front-end tests.
//
// Pure-Dart tests (no widgets/platform channels) covering the parts that carry
// the Sprint-2 logic: the SecurityAlert API contract, the feature-flag gating
// that keeps later-sprint surfaces hidden, and the device-list badge gating.
// Screen rendering + screenshots are verified in the Flutter run step (the Pi
// has no Flutter SDK).
import 'package:assas_core/assas_core.dart';
import 'package:assas_design/release_status.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/widgets/device_signals.dart';
import 'package:flutter_test/flutter_test.dart';

Map<String, dynamic> _apiAlert({Map<String, dynamic> over = const {}}) => {
      'id': '7',
      'kind': 'threat',
      'title': 'ET MALWARE X',
      'device_mac': 'aa:bb:cc:dd:ee:ff',
      'device_name': 'Front Cam',
      'time': '2026-11-02T10:04:00',
      'severity': 'critical',
      'state': 'new',
      'first_event_time': '2026-11-02T10:00:00',
      'last_event_time': '2026-11-02T10:04:00',
      'occurrence_count': 4,
      'rule_id': '2025001',
      'source_ip': '10.0.0.5',
      'destination_ip': '8.8.8.8',
      'src_port': 1234,
      'dst_port': 53,
      'explanation': null,
      'anomaly_score': null,
      ...over,
    };

void main() {
  group('SecurityAlert.fromApi contract (PBI-14)', () {
    test('parses the full threat-alert payload incl. Sprint-2 fields', () {
      final a = SecurityAlert.fromApi(_apiAlert());
      expect(a.kind, AlertKind.threat);
      expect(a.severity, Severity.critical);
      expect(a.state, AlertState.newAlert);
      expect(a.deviceMac, 'aa:bb:cc:dd:ee:ff');
      expect(a.deviceName, 'Front Cam');
      expect(a.time, DateTime.parse('2026-11-02T10:04:00'));
      expect(a.firstTime, DateTime.parse('2026-11-02T10:00:00'));
      expect(a.lastTime, DateTime.parse('2026-11-02T10:04:00'));
      expect(a.occurrenceCount, 4);
      expect(a.ruleId, '2025001');
      expect(a.sourceIp, '10.0.0.5');
      expect(a.destinationIp, '8.8.8.8');
      expect(a.srcPort, 1234);
      expect(a.dstPort, 53);
      expect(a.explanation, isNull);
    });

    test('defaults when the additive fields are absent', () {
      final a = SecurityAlert.fromApi({
        'id': '1', 'kind': 'threat', 'title': 'x', 'device_name': 'd',
        'time': '2026-11-02T10:00:00', 'severity': 'medium', 'state': 'new',
      });
      expect(a.occurrenceCount, 1);
      expect(a.srcPort, isNull);
      expect(a.ruleId, isNull);
      expect(a.firstTime, isNull);
    });

    test('severity/state map with any casing and fall back safely', () {
      expect(SecurityAlert.severityFromApi('HIGH'), Severity.high);
      expect(SecurityAlert.severityFromApi('weird'), Severity.low);
      expect(SecurityAlert.stateFromApi('new'), AlertState.newAlert);
      expect(SecurityAlert.stateFromApi(null), AlertState.newAlert);
    });

    test('copyWith preserves the Sprint-2 fields', () {
      final a = SecurityAlert.fromApi(_apiAlert());
      final b = a.copyWith(state: AlertState.reviewed);
      expect(b.state, AlertState.reviewed);
      expect(b.occurrenceCount, 4);
      expect(b.ruleId, '2025001');
      expect(b.srcPort, 1234);
      expect(b.firstTime, a.firstTime);
    });
  });

  group('Sprint-2 feature gating', () {
    test('only the three approved mobile surfaces are enabled', () {
      expect(FeatureRelease.alerts, isTrue); // Alerts tab, details, device alerts
      // Everything else stays hidden until its own sprint:
      expect(FeatureRelease.alertsHome, isFalse); // Home count + recent summary
      expect(FeatureRelease.alertSeverityBadges, isFalse); // device-list badges
      expect(FeatureRelease.alertDisplay, isFalse); // 7-inch display count
      expect(FeatureRelease.alertExplanations, isFalse); // "What happened" block
      expect(FeatureRelease.alertManagement, isFalse); // Review/Resolve + tabs
      expect(FeatureRelease.risk, isFalse); // network risk
    });
  });

  group('Device-list alert badges stay hidden (alertSeverityBadges off)', () {
    test('worstByMac still computes the worst unresolved severity per mac', () {
      final worst = Signals.worstByMac([
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': 'm1', 'severity': 'low'})),
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': 'm1', 'severity': 'high'})),
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': null, 'severity': 'critical'})),
      ]);
      expect(worst['m1'], Severity.high);
      expect(worst.keys.toList(), ['m1']); // unlinked alert (null mac) badges no device
    });

    test('Signals.all yields no severity badges while the gate is off', () {
      final state = AppState(DemoRepository());
      state.devices = const [
        Device(mac: 'm1', presence: Presence.online, trusted: true),
        Device(mac: 'm2', presence: Presence.online, trusted: true),
      ];
      state.alerts = [
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': 'm1', 'severity': 'critical'})),
      ];
      final signals = Signals.all(state);
      expect(signals.every((s) => s.alertSev == null), isTrue);
      expect(signals.any((s) => s.hasAlert), isFalse);
      state.dispose();
    });
  });
}
