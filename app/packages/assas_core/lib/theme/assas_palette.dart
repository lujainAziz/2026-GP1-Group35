import 'package:flutter/material.dart';

/// Every color of the app, for one mode (light or dark).
/// Edit the values here to change the look of BOTH apps.
class AssasPalette {
  const AssasPalette({
    required this.brightness,
    required this.primary,
    required this.button,
    required this.header,
    required this.headerDark,
    required this.ink,
    required this.muted,
    required this.bgTop,
    required this.bgMid,
    required this.bgBottom,
    required this.blobPurple,
    required this.blobPink,
    required this.blobPeach,
    required this.waveTint,
    required this.card,
    required this.border,
    required this.shadow,
    required this.inputFill,
    required this.dialog,
    required this.iconBoxTop,
    required this.online,
    required this.offline,
    required this.danger,
    required this.tintPurple,
    required this.tintBlue,
    required this.tintGreen,
    required this.tintPink,
    required this.tintOrange,
    required this.tintAmber,
    required this.tintSlate,
    required this.tintTeal,
    required this.tintRed,
    required this.fgPurple,
    required this.fgBlue,
    required this.fgGreen,
    required this.fgPink,
    required this.fgOrange,
    required this.fgAmber,
    required this.fgSlate,
    required this.fgTeal,
    required this.fgRed,
  });

  final Brightness brightness;

  // Brand (logo purples)
  final Color primary; // accent text / icons
  final Color button; // filled buttons
  final Color header;
  final Color headerDark;

  // Text
  final Color ink;
  final Color muted;

  // Background
  final Color bgTop;
  final Color bgMid;
  final Color bgBottom;
  final Color blobPurple;
  final Color blobPink;
  final Color blobPeach;
  final Color waveTint;

  // Glass
  final Color card;
  final Color border;
  final Color shadow;
  final Color inputFill;
  final Color dialog;
  final Color iconBoxTop;

  // Status
  final Color online;
  final Color offline;
  final Color danger;

  // Soft tints (icon boxes / badges) and their text colors
  final Color tintPurple, tintBlue, tintGreen, tintPink, tintOrange;
  final Color tintAmber, tintSlate, tintTeal, tintRed;
  final Color fgPurple, fgBlue, fgGreen, fgPink, fgOrange;
  final Color fgAmber, fgSlate, fgTeal, fgRed;

  // ===================== LIGHT =====================
  static const light = AssasPalette(
    brightness: Brightness.light,
    primary: Color(0xFF6B2280),
    button: Color(0xFF6B2280),
    header: Color(0xFF8A3A9E),
    headerDark: Color(0xFF571D62),
    ink: Color(0xFF2A1530),
    muted: Color(0xFF6F5F78),
    bgTop: Color(0xFFF3EAFA),
    bgMid: Color(0xFFE6D6F3),
    bgBottom: Color(0xFFF6E6F1),
    blobPurple: Color(0xFFC59ADF),
    blobPink: Color(0xFFF2A9CB),
    blobPeach: Color(0xFFF6CFA6),
    waveTint: Color(0xFFFFFFFF),
    card: Color(0xFFFFFFFF),
    border: Color(0xB3FFFFFF),
    shadow: Color(0x2E5B1F6E),
    inputFill: Color(0xD9FFFFFF),
    dialog: Color(0xFFF7F1FB),
    iconBoxTop: Color(0xFFFFFFFF),
    online: Color(0xFF1F7A4A),
    offline: Color(0xFF8A8499),
    danger: Color(0xFFA8242F),
    tintPurple: Color(0xFFF1E4F6),
    tintBlue: Color(0xFFE2ECFB),
    tintGreen: Color(0xFFE0F3E8),
    tintPink: Color(0xFFFBE3EF),
    tintOrange: Color(0xFFFDE6DC),
    tintAmber: Color(0xFFFCF0D6),
    tintSlate: Color(0xFFECEAF1),
    tintTeal: Color(0xFFDDF3F1),
    tintRed: Color(0xFFFBE0E2),
    fgPurple: Color(0xFF6B2280),
    fgBlue: Color(0xFF2C5AA0),
    fgGreen: Color(0xFF1F7A4A),
    fgPink: Color(0xFFB0306E),
    fgOrange: Color(0xFFB5461C),
    fgAmber: Color(0xFF8F5E07),
    fgSlate: Color(0xFF5E5873),
    fgTeal: Color(0xFF1D7A72),
    fgRed: Color(0xFFA8242F),
  );

  // ===================== DARK =====================
  static const dark = AssasPalette(
    brightness: Brightness.dark,
    primary: Color(0xFFD3A6E6),
    button: Color(0xFF8A3A9E),
    header: Color(0xFF6A2A7C),
    headerDark: Color(0xFF3A1446),
    ink: Color(0xFFF3EAF7),
    muted: Color(0xFFB7A6C2),
    bgTop: Color(0xFF1E1027),
    bgMid: Color(0xFF2A1436),
    bgBottom: Color(0xFF24112B),
    blobPurple: Color(0xFF7D3F99),
    blobPink: Color(0xFF9C3F6E),
    blobPeach: Color(0xFF8A5A3A),
    waveTint: Color(0xFFB98ACD),
    card: Color(0xFF3B2348),
    border: Color(0x33FFFFFF),
    shadow: Color(0x66000000),
    inputFill: Color(0xCC2E1B38),
    dialog: Color(0xFF2A1736),
    iconBoxTop: Color(0xFF4A2D5A),
    online: Color(0xFF5BD08F),
    offline: Color(0xFF9A90A8),
    danger: Color(0xFFFF7A86),
    tintPurple: Color(0xFF3E2450),
    tintBlue: Color(0xFF1F2E4A),
    tintGreen: Color(0xFF1C3A2C),
    tintPink: Color(0xFF45203A),
    tintOrange: Color(0xFF45291E),
    tintAmber: Color(0xFF3F3218),
    tintSlate: Color(0xFF2F2A38),
    tintTeal: Color(0xFF193B39),
    tintRed: Color(0xFF48202A),
    fgPurple: Color(0xFFD3A6E6),
    fgBlue: Color(0xFF8AB4F8),
    fgGreen: Color(0xFF6FD39B),
    fgPink: Color(0xFFF48FC0),
    fgOrange: Color(0xFFFFA27A),
    fgAmber: Color(0xFFF0C46A),
    fgSlate: Color(0xFFC3BACF),
    fgTeal: Color(0xFF6ED6CB),
    fgRed: Color(0xFFFF8A94),
  );
}
