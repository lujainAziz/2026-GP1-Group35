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

  /// Where vendor / device_type / model came from (backend vendor_source,
  /// class_source, model_source). null = not reported.
  final String? vendorSource;
  final String? classSource;
  final String? modelSource;

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
    this.vendorSource,
    this.classSource,
    this.modelSource,
  });

  // ---------- Display values (one place, so every screen shows the same text) ----------

  /// user's name -> hostname -> model -> "Unknown device".
  String get displayName => _clean(userName) ?? detectedName;

  /// The name Assas detected, ignoring the user's name. A detected hostname that
  /// is just an opaque machine identifier (UUID / long hex / long vowel-less
  /// token) is not human-friendly, so it falls back to the model or
  /// "Unknown device". The real identifier (MAC) and renaming are unaffected.
  String get detectedName {
    final h = _clean(hostname);
    if (h != null && !_looksLikeMachineId(h)) return h;
    return _clean(model) ?? 'Unknown device';
  }

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

  /// True when the value was derived from the hostname rather than observed.
  bool get typeInferred =>
      (classSource ?? '').toLowerCase().contains('hostname');
  bool get modelInferred =>
      (modelSource ?? '').toLowerCase().contains('hostname');
  bool get vendorInferred {
    final s = (vendorSource ?? '').trim().toLowerCase();
    return s.startsWith('inferred: hostname') ||
        (s == 'inferred: model' && modelInferred);
  }

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
        vendorSource: vendorSource,
        classSource: classSource,
        modelSource: modelSource,
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
      vendorSource: j['vendor_source']?.toString(),
      classSource: j['class_source']?.toString(),
      modelSource: j['model_source']?.toString(),
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

/// True for a hostname that is an opaque auto-generated identifier (not a
/// human-friendly name): a UUID, a long hex string, or a long separator-free,
/// essentially vowel-less token. Conservative so real names (with vowels,
/// hyphens/dots, or under 24 chars) are kept as-is.
/// Friendly display name for a raw, server-provided device name (e.g. the name
/// carried on an alert). Mirrors [Device.detectedName]'s rule: an opaque machine
/// identifier (UUID / long hex / long vowel-less token) becomes 'Unknown
/// device'; real and user-chosen names pass through unchanged.
String sanitizeDeviceName(String? name) {
  final n = name?.trim();
  if (n == null || n.isEmpty) return 'Unknown device';
  return _looksLikeMachineId(n) ? 'Unknown device' : n;
}

bool _looksLikeMachineId(String s) {
  if (s.contains(' ')) return false;
  final uuid = RegExp(
      r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$');
  if (uuid.hasMatch(s)) return true;
  if (s.length >= 24 && RegExp(r'^[0-9a-fA-F]+$').hasMatch(s)) return true;
  if (s.length >= 24 && !s.contains('-') && !s.contains('.')) {
    final vowels = RegExp(r'[AEIOUaeiou]').allMatches(s).length;
    if (vowels / s.length < 0.1) return true;
  }
  return false;
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
