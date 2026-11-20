import '../models/appliance_settings.dart';
import '../models/live_activity.dart';
import '../models/device.dart';
import '../models/network_status.dart';
import '../models/pairing_code.dart';
import '../models/paired_phone.dart';
import '../models/security_alert.dart';
import 'api_client.dart';
import 'assas_repository.dart';

// =====================================================================
//  REAL BACKEND
//
//  EXISTING endpoints (docs/API_CONTRACT.md):
//    GET  /healthz
//    GET  /devices?limit=500
//    GET  /devices/{mac}
//
//  PROPOSED endpoints (backend still needs to build them):
//    POST /pair/verify          {"code": "ABC123"}  -> {"ticket": "..."}  401 = invalid or expired, 404 = older appliance
//    POST /pair                 {"code": "ABC123"}  -> {"token": "..."}   400/401 = invalid or expired
//                               {"ticket": "..."}   -> {"token": "..."}   401 = ticket invalid or expired
//    POST /unpair               (Bearer token)      -> 204               ends this phone's session
//    GET  /pairing/code         -> {"code","expires_at"}   LOCALHOST ONLY (the 7-inch display)
//    PUT  /devices/{mac}/trust  {"trusted": true}   -> 204               saved in DB (survives restart)
//    GET  /alerts               -> [alert, ...]     (Sprint 2+)
//    PATCH /alerts/{id}         {"state": "resolved"}
//    GET  /risk                 -> {"level": "High"} (Network Alert Level, Sprint 5)
//    GET  /settings             -> {"active_probes": true}
//    PUT  /settings             {"active_probes": false}
//
//  Device fields to add on /devices and /devices/{mac}:
//    presence ("online"|"offline"), trusted (bool), monitored (bool),
//    baseline_status ("insufficient_data"|"established")
//
//  Every endpoint except /healthz and /pair needs "Authorization: Bearer <token>".
//  Requests from 127.0.0.1 (the display) do not need a token.
//
//  If an endpoint is not built yet (404), the app shows "Not available yet"
//  instead of crashing or showing fake numbers.
// =====================================================================
class ApiRepository implements AssasRepository {
  ApiRepository(this._api);

  final ApiClient _api;
  String? applianceId;

  @override
  bool get isDemo => false;

  @override
  String get applianceAddress => _api.baseUrl;

  @override
  void setAuthToken(String? token) => _api.token = token;

  static Future<String?> identityAt(String url) async {
    final client = ApiClient(baseUrl: url);
    try {
      final response = await client.get('/healthz');
      ApiClient.ensureOk(response, 'identify appliance');
      return ApiClient.decodeObject(response)['appliance_id']?.toString();
    } finally {
      client.dispose();
    }
  }

  // ---------- Status ----------

  @override
  Future<ConnectionStatus> checkHealth() async {
    try {
      final r = await _api.get('/healthz');
      if (r.statusCode == 503) return ConnectionStatus.stale;
      ApiClient.ensureOk(r, '/healthz');
      final j = ApiClient.decodeObject(r);
      return j['daemon_stale'] == true ? ConnectionStatus.stale : ConnectionStatus.live;
    } catch (_) {
      return ConnectionStatus.unreachable;
    }
  }

  @override
  Future<RiskInfo?> getRiskLevel() async {
    final r = await _api.get('/risk');
    if (r.statusCode == 404) return null; // not built yet
    ApiClient.ensureOk(r, '/risk');
    return RiskInfo.fromApi(ApiClient.decodeObject(r));
  }

  // ---------- Devices ----------
  @override
  Future<LiveActivity?> getActivity() async {
    final response = await _api.get('/activity');
    if (response.statusCode == 404) return null;
    ApiClient.ensureOk(response, '/activity');
    final data = ApiClient.decodeObject(response);
    return data['available'] == true ? LiveActivity.fromApi(data) : null;
  }

  @override
  Future<List<Device>> getDevices() async {
    const pageSize = 500;
    final devices = <String, Device>{};
    var offset = 0;
    while (true) {
      final r = await _api.get('/devices?limit=$pageSize&offset=$offset');
      ApiClient.ensureOk(r, '/devices');
      final page = ApiClient.decodeList(r).map(Device.fromApi).toList();
      final previousCount = devices.length;
      for (final device in page) {
        devices[device.mac] = device;
      }
      if (page.length < pageSize) return devices.values.toList();
      if (devices.length == previousCount) {
        throw const FormatException('Device pagination did not advance');
      }
      offset += page.length;
    }
  }

  @override
  Future<Device> getDevice(String mac) async {
    final r = await _api.get('/devices/${Uri.encodeComponent(mac)}');
    ApiClient.ensureOk(r, '/devices/{mac}');
    return Device.fromApi(ApiClient.decodeObject(r));
  }

  @override
  Future<void> setTrusted(String mac, bool trusted) async {
    final r = await _api.put(
      '/devices/${Uri.encodeComponent(mac)}/trust',
      {'trusted': trusted},
    );
    ApiClient.ensureOk(r, 'trust device');
  }

  @override
  Future<void> renameDevice(String mac, String? name) async {
    final clean = name?.trim();
    final r = await _api.put(
      '/devices/${Uri.encodeComponent(mac)}/name',
      {'name': (clean == null || clean.isEmpty) ? null : clean},
    );
    ApiClient.ensureOk(r, 'rename device');
  }

  // ---------- Alerts ----------

  // Page size + default cap (the UI raises the cap via "load older").
  static const _alertPageSize = 200;
  static const _alertFetchCap = 2000;

  /// Page through [path] (adding limit/offset) and return up to [maxItems] of the
  /// newest alerts. Returns null only when the first request 404s (endpoint not
  /// built) and [nullIf404] is set; a later-page 404 just stops.
  Future<List<SecurityAlert>?> _pageAlerts(String path, {bool nullIf404 = false, int? maxItems}) async {
    final cap = maxItems ?? _alertFetchCap;
    final out = <SecurityAlert>[];
    var offset = 0;
    while (offset < cap) {
      final size = (cap - offset).clamp(1, _alertPageSize);
      final sep = path.contains('?') ? '&' : '?';
      final r = await _api.get('$path${sep}limit=$size&offset=$offset');
      if (r.statusCode == 404) return offset == 0 && nullIf404 ? null : out;
      ApiClient.ensureOk(r, path);
      final page = ApiClient.decodeList(r).map(SecurityAlert.fromApi).toList();
      out.addAll(page);
      if (page.length < size) break; // last page
      offset += size;
    }
    out.sort((a, b) => b.time.compareTo(a.time)); // newest first (PBI-19)
    return out;
  }

  @override
  Future<List<SecurityAlert>?> getAlerts({int? limit}) =>
      _pageAlerts('/alerts', nullIf404: true, maxItems: limit);

  @override
  Future<List<SecurityAlert>?> getDeviceAlerts(String mac, {int? limit}) =>
      _pageAlerts('/devices/${Uri.encodeComponent(mac)}/alerts', maxItems: limit);

  @override
  Future<SecurityAlert?> getAlertById(String id) async {
    final r = await _api.get('/alerts/${Uri.encodeComponent(id)}');
    if (r.statusCode == 404) return null;
    ApiClient.ensureOk(r, 'alert $id');
    return SecurityAlert.fromApi(ApiClient.decodeObject(r));
  }

  @override
  Future<int?> getOpenAlertCount() async {
    final r = await _api.get('/alerts/open_count');
    if (r.statusCode == 404) return null; // not built yet
    ApiClient.ensureOk(r, '/alerts/open_count');
    return (ApiClient.decodeObject(r)['open'] as num?)?.toInt();
  }

  @override
  Future<void> setAlertState(String id, AlertState state) async {
    final r = await _api.patch(
      '/alerts/${Uri.encodeComponent(id)}',
      {'state': SecurityAlert.stateToApi(state)},
    );
    ApiClient.ensureOk(r, 'update alert');
  }

  // ---------- Pairing ----------

  @override
  Future<String> pair(String code, {String? deviceName}) async {
    var name = deviceName?.trim() ?? '';
    if (name.length > 40) name = name.substring(0, 40);
    final r = await _api.post('/pair', {
      'code': code.trim().toUpperCase(),
      if (name.isNotEmpty) 'device_name': name,
    });
    if (r.statusCode == 400 || r.statusCode == 401 || r.statusCode == 403) {
      throw const PairingException(PairingException.wrongCode);
    }
    if (r.statusCode < 200 || r.statusCode >= 300) {
      throw const PairingException('Pairing failed. Try again.');
    }
    final result = ApiClient.decodeObject(r);
    applianceId = result['appliance_id']?.toString();
    final token = result['token']?.toString();
    if (token == null || token.isEmpty) {
      throw const PairingException('Pairing failed. Try again.');
    }
    return token;
  }

  @override
  Future<String?> verifyPairingCode(String code) async {
    final r = await _api.post('/pair/verify', {'code': code.trim().toUpperCase()});
    if (r.statusCode == 404) return null; // older appliance: use pair(code)
    if (r.statusCode == 400 || r.statusCode == 401 || r.statusCode == 403) {
      throw const PairingException(PairingException.wrongCode);
    }
    if (r.statusCode < 200 || r.statusCode >= 300) {
      throw const PairingException('Pairing failed. Try again.');
    }
    final ticket = ApiClient.decodeObject(r)['ticket']?.toString();
    if (ticket == null || ticket.isEmpty) {
      throw const PairingException('Pairing failed. Try again.');
    }
    return ticket;
  }

  @override
  Future<String> pairWithTicket(String ticket, {String? deviceName}) async {
    var name = deviceName?.trim() ?? '';
    if (name.length > 40) name = name.substring(0, 40);
    final r = await _api.post('/pair', {
      'ticket': ticket,
      if (name.isNotEmpty) 'device_name': name,
    });
    if (r.statusCode == 401) {
      throw const PairingException(PairingException.ticketExpired);
    }
    if (r.statusCode < 200 || r.statusCode >= 300) {
      throw const PairingException('Pairing failed. Try again.');
    }
    final result = ApiClient.decodeObject(r);
    applianceId = result['appliance_id']?.toString();
    final token = result['token']?.toString();
    if (token == null || token.isEmpty) {
      throw const PairingException('Pairing failed. Try again.');
    }
    return token;
  }

  @override
  Future<void> unpair() async {
    final r = await _api.post('/unpair');
    ApiClient.ensureOk(r, '/unpair');
  }

  @override
  Future<PairingCode> getCurrentPairingCode() async {
    final r = await _api.get('/pairing/code');
    ApiClient.ensureOk(r, '/pairing/code');
    return PairingCode.fromApi(ApiClient.decodeObject(r));
  }

  @override
  Future<List<PairedPhone>?> getPairedPhones() async {
    final r = await _api.get('/sessions');
    if (r.statusCode == 404) return null; // not merged on the backend yet
    ApiClient.ensureOk(r, '/sessions');
    return [for (final j in ApiClient.decodeList(r)) PairedPhone.fromApi(j)]
      ..sort((a, b) => a.id.compareTo(b.id));
  }

  // ---------- Settings ----------

  @override
  Future<ApplianceSettings> getSettings() async {
    final r = await _api.get('/settings');
    ApiClient.ensureOk(r, '/settings');
    return ApplianceSettings.fromApi(ApiClient.decodeObject(r));
  }

  @override
  Future<void> updateSettings(ApplianceSettings settings) async {
    final r = await _api.put('/settings', settings.toApi());
    ApiClient.ensureOk(r, 'update settings');
  }
}
