/// Connection to the appliance (from GET /healthz, see API_CONTRACT.md).
enum ConnectionStatus {
  checking,
  /// 200 + daemon_stale=false
  live,

  /// 200 + daemon_stale=true, or 503 (database unavailable)
  stale,

  /// Request failed / timed out
  unreachable,
}

extension ConnectionStatusLabel on ConnectionStatus {
  String get label => switch (this) {
        ConnectionStatus.checking => 'Connecting',
        ConnectionStatus.live => 'Connected',
        ConnectionStatus.stale => 'Outdated data',
        ConnectionStatus.unreachable => 'Offline',
      };
}

/// Network Alert Level (Sprint 5): the highest severity among unresolved
/// alerts. The label is kept as text coming from the backend.
class RiskInfo {
  final String level;
  const RiskInfo(this.level);

  factory RiskInfo.fromApi(Map<String, dynamic> j) =>
      RiskInfo((j['level'] ?? 'Unknown').toString());
}
