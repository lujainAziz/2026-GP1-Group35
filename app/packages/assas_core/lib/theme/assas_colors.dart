import 'package:flutter/material.dart';

import 'assas_palette.dart';

/// Colors of the ACTIVE mode (light or dark). Screens read colors from here.
/// To change a color, edit assas_palette.dart (light and dark values).
///
/// Note: these are getters, so they cannot be used inside `const (...)`.
class AssasColors {
  AssasColors._();

  static AssasPalette _p = AssasPalette.light;

  static AssasPalette get palette => _p;
  static bool get isDark => _p.brightness == Brightness.dark;

  /// Called by the app when the user switches dark mode.
  static void useDark(bool dark) => _p = dark ? AssasPalette.dark : AssasPalette.light;

  // Brand
  static Color get primary => _p.primary;
  static Color get button => _p.button;
  static Color get header => _p.header;
  static Color get headerDark => _p.headerDark;

  // Text
  static Color get ink => _p.ink;
  static Color get muted => _p.muted;

  // Background
  static Color get bgTop => _p.bgTop;
  static Color get bgMid => _p.bgMid;
  static Color get bgBottom => _p.bgBottom;
  static Color get background => _p.bgMid;
  static Color get blobPurple => _p.blobPurple;
  static Color get blobPink => _p.blobPink;
  static Color get blobPeach => _p.blobPeach;
  static Color get waveTint => _p.waveTint;

  // Glass
  static Color get card => _p.card;
  static Color get border => _p.border;
  static Color get shadow => _p.shadow;
  static Color get inputFill => _p.inputFill;
  static Color get dialog => _p.dialog;
  static Color get iconBoxTop => _p.iconBoxTop;

  // Status
  static Color get online => _p.online;
  static Color get offline => _p.offline;
  static Color get warningBg => _p.tintAmber;
  static Color get warningFg => _p.fgAmber;
  static Color get danger => _p.danger;

  // Tints
  static Color get tintPurple => _p.tintPurple;
  static Color get tintBlue => _p.tintBlue;
  static Color get tintGreen => _p.tintGreen;
  static Color get tintPink => _p.tintPink;
  static Color get tintOrange => _p.tintOrange;
  static Color get tintAmber => _p.tintAmber;
  static Color get tintSlate => _p.tintSlate;
  static Color get tintTeal => _p.tintTeal;
}

/// Background / foreground color pair (badges and icon boxes).
/// Alerts and icons keep their own colors (not everything purple).
class BadgeColors {
  final Color background;
  final Color foreground;
  const BadgeColors(this.background, this.foreground);

  static AssasPalette get _p => AssasColors.palette;

  // Severity (Low / Medium / High / Critical)
  static BadgeColors get low => BadgeColors(_p.tintGreen, _p.fgGreen);
  static BadgeColors get medium => BadgeColors(_p.tintAmber, _p.fgAmber);
  static BadgeColors get high => BadgeColors(_p.tintOrange, _p.fgOrange);
  static BadgeColors get critical => BadgeColors(_p.tintRed, _p.fgRed);

  // Alert state (New / Reviewed / Resolved)
  static BadgeColors get stateNew => BadgeColors(_p.tintPurple, _p.fgPurple);
  static BadgeColors get stateReviewed => BadgeColors(_p.tintBlue, _p.fgBlue);
  static BadgeColors get stateResolved => BadgeColors(_p.tintSlate, _p.fgSlate);

  // Recognition
  static BadgeColors get unrecognized => BadgeColors(_p.tintAmber, _p.fgAmber);
  static BadgeColors get trusted => BadgeColors(_p.tintGreen, _p.fgGreen);
  static BadgeColors get notMonitored => BadgeColors(_p.tintSlate, _p.fgSlate);

  // Icon tints
  static BadgeColors get purple => BadgeColors(_p.tintPurple, _p.fgPurple);
  static BadgeColors get blue => BadgeColors(_p.tintBlue, _p.fgBlue);
  static BadgeColors get green => BadgeColors(_p.tintGreen, _p.fgGreen);
  static BadgeColors get pink => BadgeColors(_p.tintPink, _p.fgPink);
  static BadgeColors get orange => BadgeColors(_p.tintOrange, _p.fgOrange);
  static BadgeColors get amber => BadgeColors(_p.tintAmber, _p.fgAmber);
  static BadgeColors get slate => BadgeColors(_p.tintSlate, _p.fgSlate);
  static BadgeColors get teal => BadgeColors(_p.tintTeal, _p.fgTeal);

  /// Bright risk color that stays readable on the purple header (both modes).
  static Color riskOnPurple(String label) {
    final l = label.toLowerCase();
    if (l.contains('critical')) return const Color(0xFFFF9AA5);
    if (l.contains('high')) return const Color(0xFFFFB38A);
    if (l.contains('moderate') || l.contains('medium')) return const Color(0xFFFFE08A);
    return const Color(0xFF9EF0C0);
  }

  /// Color for a network risk level label coming from the backend
  /// (works for Low / Moderate / Medium / High / Critical).
  static BadgeColors forRiskLabel(String label) {
    final l = label.toLowerCase();
    if (l.contains('critical')) return critical;
    if (l.contains('high')) return high;
    if (l.contains('moderate') || l.contains('medium')) return medium;
    return low;
  }
}
