import 'package:shared_preferences/shared_preferences.dart';

/// Keeps the user's screen choices when the app is closed and opened again:
/// the open tab, the device filter and search, and the alert tab.
/// Display state only; nothing here is sent to the appliance.
class UiMemory {
  UiMemory._();

  static const _tab = 'ui.tab';
  static const _deviceFilter = 'ui.deviceFilter';
  static const _deviceSearch = 'ui.deviceSearch';
  static const _alertTab = 'ui.alertTab';

  static Future<SharedPreferences> get _p => SharedPreferences.getInstance();

  static Future<int> tab() async => (await _p).getInt(_tab) ?? 0;
  static Future<void> setTab(int v) async {
    await (await _p).setInt(_tab, v);
  }

  static Future<String?> deviceFilter() async => (await _p).getString(_deviceFilter);
  static Future<void> setDeviceFilter(String v) async {
    await (await _p).setString(_deviceFilter, v);
  }

  static Future<String> deviceSearch() async => (await _p).getString(_deviceSearch) ?? '';
  static Future<void> setDeviceSearch(String v) async {
    await (await _p).setString(_deviceSearch, v);
  }

  static Future<String?> alertTab() async => (await _p).getString(_alertTab);
  static Future<void> setAlertTab(String v) async {
    await (await _p).setString(_alertTab, v);
  }
}
