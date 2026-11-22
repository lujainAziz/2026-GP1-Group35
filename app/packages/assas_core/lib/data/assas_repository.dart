import '../models/appliance_settings.dart';
import '../models/live_activity.dart';
import '../models/device.dart';
import '../models/network_status.dart';
import '../models/pairing_code.dart';
import '../models/paired_phone.dart';
import '../models/security_alert.dart';

/// Everything the screens need from the appliance.
///
/// Two implementations:
///   - DemoRepository : fixed demo data, no backend needed
///   - ApiRepository  : real FastAPI backend on the Pi
///
/// Screens only talk to this interface, so switching demo <-> real
/// is ONE line in each app's lib/config/data_source.dart.
abstract class AssasRepository {
  /// true for demo data (shown in Settings so nobody confuses demo with real data).
  bool get isDemo;

  /// Address shown in Settings.
  String get applianceAddress;

  /// Token received after pairing. null = not paired.
  void setAuthToken(String? token);

  // ---------- Status ----------
  Future<ConnectionStatus> checkHealth();
  Future<LiveActivity?> getActivity() async => null;

  /// null = not available yet (Sprint 4). Never shown as a fake value.
  Future<RiskInfo?> getRiskLevel();

  // ---------- Devices (Sprint 1) ----------
  Future<List<Device>> getDevices();
  Future<Device> getDevice(String mac);
  Future<void> setTrusted(String mac, bool trusted);

  /// Give a device a custom name. null or empty = go back to the detected name.
  Future<void> renameDevice(String mac, String? name);

  // ---------- Alerts (Sprint 2+) ----------
  /// null = alerts are not available yet. Empty list = no alerts.
  /// Paginated server-side; returns up to [limit] of the newest alerts (null =
  /// the repository's default cap). The caller raises [limit] to "load older".
  Future<List<SecurityAlert>?> getAlerts({int? limit});
  Future<void> setAlertState(String id, AlertState state);

  /// Total OPEN (New) alerts as a DB aggregate — not the length of a
  /// loaded page. null = not available yet.
  Future<int?> getOpenAlertCount();

  /// Alerts for one device, fetched independently of the global list so older
  /// ones are never hidden behind the page limit. null = not available.
  Future<List<SecurityAlert>?> getDeviceAlerts(String mac, {int? limit});

  /// One alert by id, fetched directly (so it survives leaving the loaded page).
  /// null = not found / not available.
  Future<SecurityAlert?> getAlertById(String id);

  /// Mark one alert read for this phone (opening its details does this). Not a
  /// state change. Returns the updated alert; null = not available (unknown
  /// alert, or an appliance without read markers).
  Future<SecurityAlert?> markAlertRead(String id);

  /// This phone's unread alerts that are still unresolved (the Unread tab),
  /// newest first, up to [limit]. null = not available.
  Future<List<SecurityAlert>?> getUnreadAlerts({int? limit});

  /// Count of this phone's unread, unresolved alerts as a DB aggregate (the
  /// Unread tab badge). null = not available.
  Future<int?> getUnreadAlertCount();

  // ---------- Pairing (Sprint 1) ----------
  /// Phone: sends the code (and the phone's name), returns the session token.
  /// Throws [PairingException] if the code is invalid or expired.
  /// [deviceName] is optional, max 40 characters (backend: "Unnamed phone").
  Future<String> pair(String code, {String? deviceName});

  /// Phone, step 1 of two-step pairing: checks the code before the phone name
  /// is asked. Returns a short-lived, single-use ticket for [pairWithTicket].
  /// Throws [PairingException] if the code is invalid or expired.
  /// null = the appliance has no /pair/verify yet; use [pair] instead.
  Future<String?> verifyPairingCode(String code);

  /// Phone, step 2: sends the ticket and the phone's name, returns the token.
  /// Throws [PairingException] ([PairingException.ticketExpired]) if the
  /// ticket is invalid, expired or already used.
  Future<String> pairWithTicket(String ticket, {String? deviceName});

  /// Phone: ends this phone's session (Settings > Unpair).
  Future<void> unpair();

  /// 7-inch display only: the current rotating code.
  Future<PairingCode> getCurrentPairingCode();

  /// 7-inch display only: phones paired with this device, ordered by id.
  /// null = the backend does not have GET /sessions yet.
  Future<List<PairedPhone>?> getPairedPhones();

  // ---------- Settings ----------
  Future<ApplianceSettings> getSettings();
  Future<void> updateSettings(ApplianceSettings settings);
}

class PairingException implements Exception {
  final String message;
  const PairingException(this.message);

  /// Shown when the code is wrong or expired (the code changes every minute).
  static const String wrongCode =
      'The code is wrong or has expired. Check the current code on the ASSAS screen and try again.';

  /// Shown when the ticket from step 1 expired or was already used.
  static const String ticketExpired =
      'Pairing took too long. Enter the new code shown on the ASSAS screen and try again.';
  @override
  String toString() => message;
}

class AssasApiException implements Exception {
  final String message;
  final int? statusCode;
  const AssasApiException(this.message, {this.statusCode});
  @override
  String toString() =>
      statusCode == null ? message : '$message (HTTP $statusCode)';
}
