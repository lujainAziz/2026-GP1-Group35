/// Settings the user can change from the app.
class ApplianceSettings {
  /// Optional active identification probes used to identify devices:
  /// unicast mDNS, NBNS / NetBIOS name query, and a limited Nmap probe.
  /// Off disables only these optional probes; network monitoring and basic
  /// device discovery (e.g. ARP) continue.
  final bool activeProbes;

  const ApplianceSettings({required this.activeProbes});

  ApplianceSettings copyWith({bool? activeProbes}) =>
      ApplianceSettings(activeProbes: activeProbes ?? this.activeProbes);

  // PROPOSED: GET /settings  ->  {"active_probes": true}
  factory ApplianceSettings.fromApi(Map<String, dynamic> j) =>
      ApplianceSettings(activeProbes: j['active_probes'] == true);

  Map<String, dynamic> toApi() => {'active_probes': activeProbes};
}
