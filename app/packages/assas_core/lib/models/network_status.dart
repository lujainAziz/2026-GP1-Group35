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

/// Network risk level (Sprint 4). The exact levels are decided by the risk-level
/// research, so the label is kept as text coming from the backend.
class RiskInfo {
  final String level;
  const RiskInfo(this.level);

  factory RiskInfo.fromApi(Map<String, dynamic> j) =>
      RiskInfo((j['level'] ?? 'Unknown').toString());
}
