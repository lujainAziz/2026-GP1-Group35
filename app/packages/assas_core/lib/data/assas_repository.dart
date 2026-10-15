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
  Future<List<SecurityAlert>?> getAlerts();
  Future<void> setAlertState(String id, AlertState state);

  // ---------- Pairing (Sprint 1) ----------
  /// Phone: sends the code (and the phone's name), returns the session token.
  /// Throws [PairingException] if the code is invalid or expired.
  /// [deviceName] is optional, max 40 characters (backend: "Unnamed phone").
  Future<String> pair(String code, {String? deviceName});

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
