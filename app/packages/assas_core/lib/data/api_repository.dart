import '../models/appliance_settings.dart';
import '../models/device.dart';
import '../models/network_status.dart';
import '../models/pairing_code.dart';
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
//    POST /pair                 {"code": "ABC123"}  -> {"token": "..."}   400/401 = invalid or expired
//    POST /unpair               (Bearer token)      -> 204               ends this phone's session
//    GET  /pairing/code         -> {"code","expires_at"}   LOCALHOST ONLY (the 7-inch display)
//    PUT  /devices/{mac}/trust  {"trusted": true}   -> 204               saved in DB (survives restart)
//    GET  /alerts               -> [alert, ...]     (Sprint 2+)
//    PATCH /alerts/{id}         {"state": "reviewed" | "resolved"}
//    GET  /risk                 -> {"level": "High"} (Sprint 4)
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

  @override
  bool get isDemo => false;

  @override
  String get applianceAddress => _api.baseUrl;

  @override
  void setAuthToken(String? token) => _api.token = token;

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
  Future<List<Device>> getDevices() async {
    final r = await _api.get('/devices?limit=500');
    ApiClient.ensureOk(r, '/devices');
    return ApiClient.decodeList(r).map(Device.fromApi).toList();
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

  // ---------- Alerts ----------

  @override
  Future<List<SecurityAlert>?> getAlerts() async {
    final r = await _api.get('/alerts');
    if (r.statusCode == 404) return null; // not built yet
    ApiClient.ensureOk(r, '/alerts');
    final list = ApiClient.decodeList(r).map(SecurityAlert.fromApi).toList()
      ..sort((a, b) => b.time.compareTo(a.time)); // newest first (PBI-19)
    return list;
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
  Future<String> pair(String code) async {
    final r = await _api.post('/pair', {'code': code.trim().toUpperCase()});
    if (r.statusCode == 400 || r.statusCode == 401 || r.statusCode == 403) {
      throw const PairingException('Invalid or expired pairing code.');
    }
    if (r.statusCode < 200 || r.statusCode >= 300) {
      throw const PairingException('Could not reach your Assas device. Try again.');
    }
    final token = ApiClient.decodeObject(r)['token']?.toString();
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
