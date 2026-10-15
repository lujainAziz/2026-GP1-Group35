import 'package:shared_preferences/shared_preferences.dart';

/// Keeps the pairing token on the phone so the user pairs only once.
class SessionStore {
  SessionStore._();

  static const _tokenKey = 'assas_session_token';

  static Future<String?> getToken() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_tokenKey);
  }

  static Future<String?> getApplianceId() async =>
      (await SharedPreferences.getInstance()).getString('assas_appliance_id');

  static Future<void> saveToken(String token, {String? applianceId}) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_tokenKey, token);
    if (applianceId != null) {
      await prefs.setString('assas_appliance_id', applianceId);
    } else {
      await prefs.remove('assas_appliance_id');
    }
  }

  static Future<void> clear() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_tokenKey);
    await prefs.remove('assas_appliance_id');
  }
}
