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
  static const _alertSort = 'ui.alertSort';
  static const _alertSeverities = 'ui.alertSeverities';
  static const _alertHideResolved = 'ui.alertHideResolved';
  static const _deviceAlertSort = 'ui.deviceAlertSort';

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

  // Alert list: sort order, which severities are shown, and whether resolved
  // alerts are hidden from the list (display only — never changes stored state).
  static Future<String?> alertSort() async => (await _p).getString(_alertSort);
  static Future<void> setAlertSort(String v) async {
    await (await _p).setString(_alertSort, v);
  }

  static Future<List<String>?> alertSeverities() async => (await _p).getStringList(_alertSeverities);
  static Future<void> setAlertSeverities(List<String> v) async {
    await (await _p).setStringList(_alertSeverities, v);
  }

  static Future<bool> alertHideResolved() async => (await _p).getBool(_alertHideResolved) ?? false;
  static Future<void> setAlertHideResolved(bool v) async {
    await (await _p).setBool(_alertHideResolved, v);
  }

  // Per-device alerts: sort order.
  static Future<String?> deviceAlertSort() async => (await _p).getString(_deviceAlertSort);
  static Future<void> setDeviceAlertSort(String v) async {
    await (await _p).setString(_deviceAlertSort, v);
  }
}
