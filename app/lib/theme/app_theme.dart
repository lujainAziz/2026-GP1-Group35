import 'package:flutter/material.dart';

class AppColors {
  // Official Assas Brand Palette
  static const Color darkPurpleBase = Color(0xFF200E23);
  static const Color darkPurpleAccent = Color(0xFF29102D);
  static const Color mediumPurple = Color(0xFF571D62);
  static const Color vibrantPurple = Color(0xFF661973);
  static const Color highlightPurple = Color(0xFF722086);

  // Dynamic Risk & Posture Alert Colors
  static const Color statusSafe = Color(0xFF00BFA5);    // Low risk (< 35)
  static const Color statusWarning = Color(0xFFF59E0B); // Medium risk (35 - 69)
  static const Color statusDanger = Color(0xFFE11D48);  // High risk (>= 70)

  // Dark Appearance (Aura AI / Shruhh inspired)
  static const Color darkBackground = Color(0xFF120917);
  static const Color darkCardSurface = Color(0xFF200E23);
  static const Color darkCardBorder = Color(0xFF3D1647);

  // Soft Light Appearance
  static const Color lightBackground = Color(0xFFF5F2F7);
  static const Color lightCardSurface = Color(0xFFFFFFFF);
  static const Color lightCardBorder = Color(0xFFE9E2EE);
}

class AppTheme {
  static ThemeData get darkTheme {
    return ThemeData(
      brightness: Brightness.dark,
      scaffoldBackgroundColor: AppColors.darkBackground,
      primaryColor: AppColors.vibrantPurple,
      cardColor: AppColors.darkCardSurface,
      dividerColor: AppColors.darkCardBorder,
      colorScheme: const ColorScheme.dark(
        primary: AppColors.vibrantPurple,
        secondary: AppColors.statusSafe,
        surface: AppColors.darkCardSurface,
        error: AppColors.statusDanger,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: Colors.transparent,
        elevation: 0,
        centerTitle: false,
        titleTextStyle: TextStyle(
          color: Colors.white,
          fontSize: 22,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }

  static ThemeData get lightTheme {
    return ThemeData(
      brightness: Brightness.light,
      scaffoldBackgroundColor: AppColors.lightBackground,
      primaryColor: AppColors.mediumPurple,
      cardColor: AppColors.lightCardSurface,
      dividerColor: AppColors.lightCardBorder,
      colorScheme: const ColorScheme.light(
        primary: AppColors.mediumPurple,
        secondary: AppColors.statusSafe,
        surface: AppColors.lightCardSurface,
        error: AppColors.statusDanger,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: Colors.transparent,
        elevation: 0,
        centerTitle: false,
        titleTextStyle: TextStyle(
          color: AppColors.darkPurpleBase,
          fontSize: 22,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}