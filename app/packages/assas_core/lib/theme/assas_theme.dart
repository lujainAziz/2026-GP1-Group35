import 'package:flutter/material.dart';

import 'assas_palette.dart';

/// Flutter theme for each mode (buttons, inputs, tab bar, dialogs...).
class AssasTheme {
  AssasTheme._();

  static ThemeData get light => _build(AssasPalette.light);
  static ThemeData get dark => _build(AssasPalette.dark);

  static ThemeData _build(AssasPalette p) {
    final scheme = ColorScheme.fromSeed(
      seedColor: p.button,
      brightness: p.brightness,
    ).copyWith(
      primary: p.button,
      onPrimary: Colors.white,
      surface: p.dialog,
      onSurface: p.ink,
      error: p.danger,
    );

    return ThemeData(
      useMaterial3: true,
      brightness: p.brightness,
      colorScheme: scheme,
      // Transparent so the AssasBackground shows behind every screen.
      scaffoldBackgroundColor: Colors.transparent,
      dividerColor: p.border,
      textTheme: (p.brightness == Brightness.dark
              ? Typography.material2021().white
              : Typography.material2021().black)
          .apply(bodyColor: p.ink, displayColor: p.ink),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: p.button,
          foregroundColor: Colors.white,
          minimumSize: const Size.fromHeight(48),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          textStyle: const TextStyle(fontWeight: FontWeight.w700, fontSize: 15),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: p.primary,
          minimumSize: const Size.fromHeight(48),
          side: BorderSide(color: p.primary, width: 1.5),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          textStyle: const TextStyle(fontWeight: FontWeight.w700, fontSize: 15),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: p.inputFill,
        hintStyle: TextStyle(color: p.muted),
        contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: p.border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: p.border),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: p.primary, width: 1.5),
        ),
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: Colors.transparent,
        surfaceTintColor: Colors.transparent,
        elevation: 0,
        indicatorColor: p.tintPurple,
        labelTextStyle: WidgetStateProperty.resolveWith((states) {
          final selected = states.contains(WidgetState.selected);
          return TextStyle(
            fontSize: 12,
            fontWeight: selected ? FontWeight.w700 : FontWeight.w500,
            color: selected ? p.primary : p.muted,
          );
        }),
        iconTheme: WidgetStateProperty.resolveWith((states) {
          final selected = states.contains(WidgetState.selected);
          return IconThemeData(color: selected ? p.primary : p.muted);
        }),
      ),
      switchTheme: SwitchThemeData(
        trackColor: WidgetStateProperty.resolveWith(
          (s) => s.contains(WidgetState.selected) ? p.button : p.tintSlate,
        ),
      ),
      sliderTheme: SliderThemeData(
        activeTrackColor: p.button,
        inactiveTrackColor: p.tintPurple,
        thumbColor: p.button,
      ),
      snackBarTheme: const SnackBarThemeData(behavior: SnackBarBehavior.floating),
      dialogTheme: DialogThemeData(backgroundColor: p.dialog),
    );
  }
}
