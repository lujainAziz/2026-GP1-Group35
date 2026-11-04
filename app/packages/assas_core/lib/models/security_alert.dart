import '../theme/assas_colors.dart';
import 'device.dart';

/// Threat Alert = Suricata (Sprint 2). Anomaly Alert = Isolation Forest (Sprint 3).
enum AlertKind { threat, anomaly }

enum Severity { low, medium, high, critical }

enum AlertState { newAlert, reviewed, resolved }

class SecurityAlert {
  final String id;
  final AlertKind kind;

  /// Short name, e.g. "Port scan detected" or "Unusual activity".
  final String title;
  final String? deviceMac;
  final String deviceName;
  final DateTime time;
  final Severity severity;
  final AlertState state;

  /// Plain-language "What happened" text (Human-Readable Alert, Sprint 4).
  final String? explanation;

  /// Extra short note under the explanation.
  final String? note;

  /// Threat alerts only (PBI-11).
  final String? sourceIp;
  final String? destinationIp;

  /// Threat alerts (PBI-14): matched rule, ports, and dedup fields.
  final String? ruleId;
  final int? srcPort;
  final int? dstPort;

  /// How many times this alert fired (deduplicated); 1 unless merged.
  final int occurrenceCount;

  /// First and last event times (first stays fixed; last advances on merges).
  final DateTime? firstTime;
  final DateTime? lastTime;

  const SecurityAlert({
    required this.id,
    required this.kind,
    required this.title,
    this.deviceMac,
    required this.deviceName,
    required this.time,
    required this.severity,
    required this.state,
    this.explanation,
    this.note,
    this.sourceIp,
    this.destinationIp,
    this.ruleId,
    this.srcPort,
    this.dstPort,
    this.occurrenceCount = 1,
    this.firstTime,
    this.lastTime,
  });

  bool get isUnresolved => state != AlertState.resolved;

  /// Device name for display: opaque machine identifiers collapse to
  /// 'Unknown device' (the raw name stays in [deviceName] / the API).
  String get displayDeviceName => sanitizeDeviceName(deviceName);

  String get kindLabel => kind == AlertKind.threat ? 'Threat Alert' : 'Anomaly Alert';

  String get severityLabel => switch (severity) {
        Severity.low => 'Low',
        Severity.medium => 'Medium',
        Severity.high => 'High',
        Severity.critical => 'Critical',
      };

  BadgeColors get severityColors => switch (severity) {
        Severity.low => BadgeColors.low,
        Severity.medium => BadgeColors.medium,
        Severity.high => BadgeColors.high,
        Severity.critical => BadgeColors.critical,
      };

  String get stateLabel => switch (state) {
        AlertState.newAlert => 'New',
        AlertState.reviewed => 'Reviewed',
        AlertState.resolved => 'Resolved',
      };

  BadgeColors get stateColors => switch (state) {
        AlertState.newAlert => BadgeColors.stateNew,
        AlertState.reviewed => BadgeColors.stateReviewed,
        AlertState.resolved => BadgeColors.stateResolved,
      };

  /// Default note for anomaly alerts (PBI-14: not presented as a confirmed attack).
  String? get displayNote =>
      note ??
      (kind == AlertKind.anomaly
          ? 'This activity is unusual for this device. It is not a confirmed attack, but it may need your attention.'
          : null);

  SecurityAlert copyWith({AlertState? state}) => SecurityAlert(
        id: id,
        kind: kind,
        title: title,
        deviceMac: deviceMac,
        deviceName: deviceName,
        time: time,
        severity: severity,
        state: state ?? this.state,
        explanation: explanation,
        note: note,
        sourceIp: sourceIp,
        destinationIp: destinationIp,
        ruleId: ruleId,
        srcPort: srcPort,
        dstPort: dstPort,
        occurrenceCount: occurrenceCount,
        firstTime: firstTime,
        lastTime: lastTime,
      );

  // ---------- From the real API (PROPOSED contract, endpoint not built yet) ----------
  // {
  //   "id": "a-17", "kind": "threat" | "anomaly", "title": "Port scan detected",
  //   "device_mac": "5b:8c:...", "device_name": "Work laptop",
  //   "time": "2026-10-08T21:15:00", "severity": "low|medium|high|critical",
  //   "state": "new|reviewed|resolved", "explanation": "...", "note": "...",
  //   "source_ip": "...", "destination_ip": "..."
  // }
  factory SecurityAlert.fromApi(Map<String, dynamic> j) {
    return SecurityAlert(
      id: j['id'].toString(),
      kind: j['kind']?.toString() == 'anomaly' ? AlertKind.anomaly : AlertKind.threat,
      title: (j['title'] ?? 'Security alert').toString(),
      deviceMac: j['device_mac']?.toString(),
      deviceName: (j['device_name'] ?? 'Unknown device').toString(),
      time: DateTime.tryParse(j['time']?.toString() ?? '') ?? DateTime.now(),
      severity: severityFromApi(j['severity']?.toString()),
      state: stateFromApi(j['state']?.toString()),
      explanation: j['explanation']?.toString(),
      note: j['note']?.toString(),
      sourceIp: j['source_ip']?.toString(),
      destinationIp: j['destination_ip']?.toString(),
      ruleId: j['rule_id']?.toString(),
      srcPort: (j['src_port'] as num?)?.toInt(),
      dstPort: (j['dst_port'] as num?)?.toInt(),
      occurrenceCount: (j['occurrence_count'] as num?)?.toInt() ?? 1,
      firstTime: DateTime.tryParse(j['first_event_time']?.toString() ?? ''),
      lastTime: DateTime.tryParse(j['last_event_time']?.toString() ?? ''),
    );
  }

  static Severity severityFromApi(String? v) => switch (v?.toLowerCase()) {
        'critical' => Severity.critical,
        'high' => Severity.high,
        'medium' => Severity.medium,
        _ => Severity.low,
      };

  static AlertState stateFromApi(String? v) => switch (v?.toLowerCase()) {
        'reviewed' => AlertState.reviewed,
        'resolved' => AlertState.resolved,
        _ => AlertState.newAlert,
      };

  static String stateToApi(AlertState s) => switch (s) {
        AlertState.newAlert => 'new',
        AlertState.reviewed => 'reviewed',
        AlertState.resolved => 'resolved',
      };
}
