/// One device in the inventory, already translated into what the user sees.
///
/// Internal backend statuses (observed / candidate) never reach the UI:
/// the user only sees Online / Offline (team decision).
enum Presence { online, offline }

/// PBI-13: a device is "Insufficient Data" until its baseline is established.
enum BaselineStatus { insufficientData, established }

class Device {
  final String mac;
  final String? ip;
  final List<String> ipv6;

  /// Name the user gave the device in the app (null = use the detected name).
  final String? userName;
  final String? hostname;
  final String? model;
  final String? vendor;
  final String? deviceType;
  final Presence presence;

  /// Unrecognized = not marked as trusted by the user.
  /// It has nothing to do with the device type classification.
  final bool trusted;

  /// PBI-04 "Not Monitored". null = backend does not report it yet.
  final bool? monitored;

  final BaselineStatus baseline;
  final DateTime? lastSeen;

  const Device({
    required this.mac,
    this.ip,
    this.ipv6 = const [],
    this.userName,
    this.hostname,
    this.model,
    this.vendor,
    this.deviceType,
    required this.presence,
    required this.trusted,
    this.monitored,
    this.baseline = BaselineStatus.insufficientData,
    this.lastSeen,
  });

  // ---------- Display values (one place, so every screen shows the same text) ----------

  /// user's name -> hostname -> model -> "Unknown device".
  String get displayName => _clean(userName) ?? detectedName;

  /// The name Assas detected, ignoring the user's name.
  String get detectedName => _clean(hostname) ?? _clean(model) ?? 'Unknown device';

  bool get hasUserName => _clean(userName) != null;
  String get vendorLabel => _clean(vendor) ?? 'Unknown';
  String get typeLabel => _clean(deviceType) ?? 'Unknown';

  /// Type text with the model appended ("Type · Model") when a distinct model
  /// is known; otherwise just the type. Model is shown only when non-empty and
  /// different from the displayed device name. Additive display helper.
  String get typeWithModel {
    final m = _clean(model);
    return (m == null || m == displayName) ? typeLabel : '$typeLabel · $m';
  }
  String get ipLabel => _clean(ip) ?? 'Unknown';
  String get macLabel => mac.toUpperCase();

  bool get isOnline => presence == Presence.online;
  bool get isUnrecognized => !trusted;
  bool get isNotMonitored => monitored == false;

  String get onlineLabel => isOnline ? 'Online' : 'Offline';
  String get recognitionLabel => trusted ? 'Trusted' : 'Unrecognized';
  String get baselineLabel =>
      baseline == BaselineStatus.established ? 'Established' : 'Insufficient data';

  /// [userName]: pass '' to clear the user's name.
  Device copyWith({bool? trusted, String? userName}) => Device(
        mac: mac,
        ip: ip,
        ipv6: ipv6,
        userName: userName == null ? this.userName : (userName.isEmpty ? null : userName),
        hostname: hostname,
        model: model,
        vendor: vendor,
        deviceType: deviceType,
        presence: presence,
        trusted: trusted ?? this.trusted,
        monitored: monitored,
        baseline: baseline,
        lastSeen: lastSeen,
      );

  // ---------- From the real API ----------

  /// Works with both GET /devices (summary) and GET /devices/{mac} (detail).
  ///
  /// Fields used today (docs/API_CONTRACT.md):
  ///   mac, ip, hostname, model, vendor, device_type, status, last_seen
  /// Fields the backend still needs to ADD (team decisions):
  ///   presence        "online" | "offline"   (user-facing, so the app never reads observed/candidate)
  ///   trusted         true | false           (Mark as trusted, must survive restart)
  ///   monitored       true | false           (PBI-04 Not Monitored)
  ///   baseline_status "insufficient_data" | "established"
  factory Device.fromApi(Map<String, dynamic> j) {
    return Device(
      mac: (j['mac'] ?? '').toString(),
      ip: j['ip']?.toString(),
      ipv6: j['ipv6'] is List
          ? List<String>.unmodifiable((j['ipv6'] as List)
              .whereType<String>().map((v) => v.trim()).where((v) => v.isNotEmpty).toSet())
          : const [],
      userName: j['user_name']?.toString(),
      hostname: j['hostname']?.toString(),
      model: j['model']?.toString(),
      vendor: j['vendor']?.toString(),
      deviceType: j['device_type']?.toString(),
      presence: _presenceFrom(j),
      trusted: _asBool(j['trusted']) ?? false,
      monitored: _asBool(j['monitored']),
      baseline: j['baseline_status']?.toString() == 'established'
          ? BaselineStatus.established
          : BaselineStatus.insufficientData,
      lastSeen: _parseTime(j['last_seen']),
    );
  }

  static Presence _presenceFrom(Map<String, dynamic> j) {
    // Preferred: user-facing field from the backend.
    final presence = j['presence']?.toString();
    if (presence != null) {
      return presence == 'online' ? Presence.online : Presence.offline;
    }
    // Fallback until the backend adds "presence": only "online" counts as Online.
    // observed / candidate / offline are all shown as Offline (never shown by name).
    return const ['online', 'observed'].contains(j['status']?.toString())
        ? Presence.online : Presence.offline;
  }
}

String? _clean(String? v) {
  if (v == null) return null;
  final t = v.trim();
  if (t.isEmpty || t.toLowerCase() == 'null' || t.toLowerCase() == 'unknown') return null;
  return t;
}

bool? _asBool(dynamic v) {
  if (v == null) return null;
  if (v is bool) return v;
  if (v is num) return v != 0;
  final s = v.toString().toLowerCase();
  if (s == 'true' || s == '1') return true;
  if (s == 'false' || s == '0') return false;
  return null;
}

DateTime? _parseTime(dynamic v) {
  if (v == null) return null;
  return DateTime.tryParse(v.toString());
}
