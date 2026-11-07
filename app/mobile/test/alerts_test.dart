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
    test('alerts + state management are enabled; later-sprint surfaces hidden', () {
      expect(FeatureRelease.alerts, isTrue); // Alerts tab, details, device alerts
      // PBI-22 RELEASED in Sprint 2 (team decision): Review/Resolve actions,
      // New/Reviewed/Resolved badges, All/Open/Resolved tabs and the live
      // unresolved (New+Reviewed) counter are all live.
      expect(FeatureRelease.alertManagement, isTrue);
      expect(FeatureRelease.alertSeverityBadges, isTrue); // PBI-09/10: signals + priority
      // Everything else stays hidden until its own sprint:
      expect(FeatureRelease.alertsHome, isFalse); // Home count + recent summary (PBI-24)
      expect(FeatureRelease.alertDisplay, isFalse); // 7-inch display count
      expect(FeatureRelease.alertExplanations, isFalse); // "What happened" block
      expect(FeatureRelease.risk, isFalse); // network risk
    });
  });

  group('PBI-09/10: unresolved alerts feed the device signals', () {
    test('worstByMac: worst unresolved severity per mac; unlinked/resolved excluded', () {
      final worst = Signals.worstByMac([
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': 'm1', 'severity': 'low'})),
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': 'm1', 'severity': 'high'})),
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': null, 'severity': 'critical'})),
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': 'm2', 'severity': 'critical', 'state': 'resolved'})),
      ]);
      expect(worst['m1'], Severity.high);
      // unlinked (null mac) and resolved alerts are attributed to no device
      expect(worst.keys.toList(), ['m1']);
    });

    test('New/Reviewed alert → severity signal; resolving all clears it but keeps Attention when due', () {
      final state = AppState(DemoRepository());
      addTearDown(state.dispose);
      state.devices = const [
        // Unrecognized + not monitored device with an alert.
        Device(mac: 'm1', presence: Presence.online, trusted: false, monitored: false),
        // Fully-trusted, monitored device with an alert.
        Device(mac: 'm2', presence: Presence.online, trusted: true, monitored: true),
      ];
      state.alerts = [
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': 'm1', 'severity': 'medium', 'state': 'reviewed'})),
        SecurityAlert.fromApi(_apiAlert(over: {'id': 'b', 'device_mac': 'm2', 'severity': 'high', 'state': 'new'})),
      ];
      var s1 = Signals.of(state, state.devices[0]);
      var s2 = Signals.of(state, state.devices[1]);
      // Reviewed still counts as unresolved; severity shown in the severity palette.
      expect(s1.hasAlert, isTrue);
      expect(s1.alertSev, Severity.medium);
      expect(s1.rowAccent, sevColor(Severity.medium));
      expect(s2.alertSev, Severity.high);
      expect(s1.needsAttention && s2.needsAttention, isTrue);

      // Resolve ALL alerts: the severity signal disappears...
      state.alerts = [
        for (final a in state.alerts!) a.copyWith(state: AlertState.resolved),
      ];
      s1 = Signals.of(state, state.devices[0]);
      s2 = Signals.of(state, state.devices[1]);
      expect(s1.hasAlert, isFalse);
      expect(s2.hasAlert, isFalse);
      // ...but m1 stays Attention (unrecognized + not monitored), m2 does not.
      expect(s1.needsAttention, isTrue);
      expect(s2.needsAttention, isFalse);
    });

    test('Home priority: the device with the open alert sorts first among online', () {
      final state = AppState(DemoRepository());
      addTearDown(state.dispose);
      state.devices = const [
        Device(mac: 'aa', hostname: 'Quiet', presence: Presence.online, trusted: true, monitored: true),
        Device(mac: 'bb', hostname: 'Alerting', presence: Presence.online, trusted: true, monitored: true),
      ];
      state.alerts = [
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': 'bb', 'severity': 'high'})),
      ];
      final sorted = Signals.sorted(state);
      expect(sorted.first.device.mac, 'bb');
    });
  });
}
