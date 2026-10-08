import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Appearance settings chosen by the user (saved on the phone).
class AppSettings extends ChangeNotifier {
  AppSettings._();
  static final AppSettings instance = AppSettings._();

  /// Text size steps. Kept in a safe range so the layout never breaks.
  static const List<double> textScales = [0.9, 1.0, 1.1, 1.2];
  static const List<String> textScaleLabels = ['Small', 'Default', 'Large', 'Larger'];

  /// Final text scale (user choice x phone setting) is kept inside this range.
  static const double minTextScale = 0.85;
  static const double maxTextScale = 1.3;

  static const _darkKey = 'assas_dark_mode';
  static const _scaleKey = 'assas_text_scale_index';

  bool darkMode = false;
  int textScaleIndex = 1;

  double get textScale => textScales[textScaleIndex];
  String get textScaleLabel => textScaleLabels[textScaleIndex];

  Future<void> load() async {
    final prefs = await SharedPreferences.getInstance();
    darkMode = prefs.getBool(_darkKey) ?? false;
    textScaleIndex = (prefs.getInt(_scaleKey) ?? 1).clamp(0, textScales.length - 1).toInt();
  }

  Future<void> setDarkMode(bool value) async {
    darkMode = value;
    notifyListeners();
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_darkKey, value);
  }

  Future<void> setTextScaleIndex(int index) async {
    textScaleIndex = index.clamp(0, textScales.length - 1).toInt();
    notifyListeners();
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt(_scaleKey, textScaleIndex);
  }
}
