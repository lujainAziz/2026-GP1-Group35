/// Settings the user can change from the app.
class ApplianceSettings {
  /// Optional light local probes used to identify devices
  /// (unicast mDNS, NetBIOS name query, limited nmap probe).
  /// Off = fully passive monitoring (Scope section of the report).
  final bool activeProbes;

  const ApplianceSettings({required this.activeProbes});

  ApplianceSettings copyWith({bool? activeProbes}) =>
      ApplianceSettings(activeProbes: activeProbes ?? this.activeProbes);

  // PROPOSED: GET /settings  ->  {"active_probes": true}
  factory ApplianceSettings.fromApi(Map<String, dynamic> j) =>
      ApplianceSettings(activeProbes: j['active_probes'] == true);

  Map<String, dynamic> toApi() => {'active_probes': activeProbes};
}
