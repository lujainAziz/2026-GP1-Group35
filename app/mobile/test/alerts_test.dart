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
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:assas_mobile/widgets/device_signals.dart';
import 'package:flutter/painting.dart' show Color;
import 'package:flutter_test/flutter_test.dart';

Map<String, dynamic> _apiAlert({Map<String, dynamic> over = const {}}) => {
      'id': '7',
      'kind': 'threat',
      'title': 'ET MALWARE X',
      'device_mac': 'aa:bb:cc:dd:ee:ff',
      'device_name': 'Front Cam',
      'time': '2026-11-02T10:04:00',
      'severity': 'high',
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
      expect(a.severity, Severity.high);
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

    test('Release 1: no Critical or Reviewed; old values map to High / New', () {
      expect(Severity.values, [Severity.low, Severity.medium, Severity.high]);
      expect(AlertState.values, [AlertState.newAlert, AlertState.resolved]);
      // An older appliance may still send these.
      expect(SecurityAlert.severityFromApi('critical'), Severity.high);
      expect(SecurityAlert.stateFromApi('reviewed'), AlertState.newAlert);
      expect(SecurityAlert.stateToApi(AlertState.resolved), 'resolved');
    });

    test('severity scale is red / orange / amber everywhere (High / Medium / Low)', () {
      final p = AssasColors.palette;
      (Color, Color) pair(BadgeColors b) => (b.background, b.foreground);
      // Badges and the severity filter dot.
      expect(pair(BadgeColors.high), (p.tintRed, p.fgRed)); // former Critical
      expect(pair(BadgeColors.medium), (p.tintOrange, p.fgOrange)); // former High
      expect(pair(BadgeColors.low), (p.tintAmber, p.fgAmber)); // former Medium
      // Timeline dot, row accent, details.
      expect(sevColor(Severity.high), Ui.crit);
      expect(sevColor(Severity.medium), Ui.high);
      expect(sevColor(Severity.low), Ui.med);
      // Label-based (alert level).
      expect(Ui.severity('High'), Ui.crit);
      expect(Ui.severity('Medium'), Ui.high);
      expect(Ui.severity('Low'), Ui.med);
      // No green for any severity: green stays "fine" (online, trusted, resolved).
      for (final s in Severity.values) {
        expect(sevColor(s), isNot(Ui.low), reason: '$s');
      }
      // Non-severity orange (Not Monitored) is unchanged.
      expect(Ui.notMonitored, Ui.high);
    });

    test('first detection falls back to the alert time', () {
      final a = SecurityAlert.fromApi(_apiAlert());
      expect(a.firstDetected, DateTime.parse('2026-11-02T10:00:00'));
      final b = SecurityAlert.fromApi(_apiAlert(over: {'first_event_time': null}));
      expect(b.firstDetected, DateTime.parse('2026-11-02T10:04:00'));
    });

    test('copyWith preserves the Sprint-2 fields', () {
      final a = SecurityAlert.fromApi(_apiAlert(over: {'display_title': 'Malware activity', 'device_role': 'target'}));
      final b = a.copyWith(state: AlertState.resolved);
      expect(b.state, AlertState.resolved);
      expect(b.occurrenceCount, 4);
      expect(b.ruleId, '2025001');
      expect(b.srcPort, 1234);
      expect(b.firstTime, a.firstTime);
      expect(b.title, 'Malware activity');
      expect(b.ruleName, 'ET MALWARE X');
      expect(b.deviceRole, 'target');
    });

    test('plain title, rule name, explanation and role line from the API', () {
      final a = SecurityAlert.fromApi(_apiAlert(over: {
        'display_title': 'Malware activity',
        'explanation': 'Traffic from or to this device matches a known pattern of malicious software.',
        'classtype': 'trojan-activity',
        'device_role': 'source',
      }));
      expect(a.title, 'Malware activity');      // shown in the alert list
      expect(a.ruleName, 'ET MALWARE X');       // original Suricata rule name
      expect(a.ruleId, '2025001');              // still parsed (hidden in the UI)
      expect(a.explanation, startsWith('Traffic from or to this device'));
      expect(a.roleLine, 'This device started the activity.');
      final t = SecurityAlert.fromApi(_apiAlert(over: {'device_role': 'target'}));
      expect(t.roleLine, 'This device was the target.');
    });

    test('older appliance (no display_title) and unknown role fall back', () {
      final a = SecurityAlert.fromApi(_apiAlert(over: {'device_role': 'sideways'}));
      expect(a.title, 'ET MALWARE X');          // rule name, as before
      expect(a.ruleName, 'ET MALWARE X');
      expect(a.deviceRole, isNull);
      expect(a.roleLine, isNull);
      final none = SecurityAlert.fromApi(_apiAlert(over: {'title': null}));
      expect(none.title, 'Network activity detected');
      expect(none.ruleName, isNull);
    });
  });

  group('Sprint-2 feature gating', () {
    test('alerts + state management are enabled; later-sprint surfaces hidden', () {
      expect(FeatureRelease.alerts, isTrue); // Alerts tab, details, device alerts
      // PBI-22 RELEASED (Release 1: New -> Resolved only): the Resolve action,
      // New/Resolved badges, All/Open/Resolved tabs and the live unresolved
      // (New) counter are all live.
      expect(FeatureRelease.alertManagement, isTrue);
      expect(FeatureRelease.alertSeverityBadges, isTrue); // PBI-09/10: signals + priority
      // 7-inch display "Unresolved alerts" card (Sprint 2 feature, Release 1).
      expect(FeatureRelease.alertDisplay, isTrue);
      // Home "Unresolved alerts" card (Release 1); the Home recent summary
      // (PBI-24) stays hidden.
      expect(FeatureRelease.alertsHome, isTrue);
      expect(FeatureRelease.alertsHomeRecent, isFalse);
      // Everything else stays hidden until its own sprint:
      // Threat Alert explanations RELEASED in Sprint 2 (Option 2).
      expect(FeatureRelease.alertExplanations, isTrue); // "What happened" block
      expect(FeatureRelease.risk, isFalse); // Network Alert Level (Sprint 5)
    });
  });

  group('PBI-09/10: unresolved alerts feed the device signals', () {
    test('worstByMac: worst unresolved severity per mac; unlinked/resolved excluded', () {
      final worst = Signals.worstByMac([
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': 'm1', 'severity': 'low'})),
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': 'm1', 'severity': 'high'})),
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': null, 'severity': 'high'})),
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': 'm2', 'severity': 'high', 'state': 'resolved'})),
      ]);
      expect(worst['m1'], Severity.high);
      // unlinked (null mac) and resolved alerts are attributed to no device
      expect(worst.keys.toList(), ['m1']);
    });

    test('New alert → severity signal; resolving all clears it but keeps Attention when due', () {
      final state = AppState(DemoRepository());
      addTearDown(state.dispose);
      state.devices = const [
        // Unrecognized + not monitored device with an alert.
        Device(mac: 'm1', presence: Presence.online, trusted: false, monitored: false),
        // Fully-trusted, monitored device with an alert.
        Device(mac: 'm2', presence: Presence.online, trusted: true, monitored: true),
      ];
      state.alerts = [
        SecurityAlert.fromApi(_apiAlert(over: {'device_mac': 'm1', 'severity': 'medium', 'state': 'new'})),
        SecurityAlert.fromApi(_apiAlert(over: {'id': 'b', 'device_mac': 'm2', 'severity': 'high', 'state': 'new'})),
      ];
      var s1 = Signals.of(state, state.devices[0]);
      var s2 = Signals.of(state, state.devices[1]);
      // An open (New) alert gives the severity signal, in the severity palette.
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
