import 'package:flutter/material.dart';

import 'assas_colors.dart';

/// Text sizes and weights in one place.
/// Change a size here and every screen that uses it changes.
/// (The user's text-size setting scales all of these together.)
class AssasText {
  AssasText._();

  // ---------- On the purple header (always white) ----------
  static const TextStyle headerTitle =
      TextStyle(color: Colors.white, fontSize: 24, fontWeight: FontWeight.w800);
  static const TextStyle headerTitleSmall =
      TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.w800);
  static const TextStyle headerBody =
      TextStyle(color: Colors.white, fontWeight: FontWeight.w600);

  // ---------- On the page ----------
  static TextStyle get section =>
      TextStyle(fontSize: 16, fontWeight: FontWeight.w800, color: AssasColors.ink);
  static TextStyle get cardTitle =>
      TextStyle(fontSize: 15, fontWeight: FontWeight.w800, color: AssasColors.ink);
  static TextStyle get body =>
      TextStyle(fontSize: 14, fontWeight: FontWeight.w600, color: AssasColors.ink);
  static TextStyle get bodyStrong =>
      TextStyle(fontSize: 14, fontWeight: FontWeight.w700, color: AssasColors.ink);
  static TextStyle get secondary =>
      TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: AssasColors.ink);
  static TextStyle get caption => TextStyle(fontSize: 13, color: AssasColors.muted);
  static TextStyle get small => TextStyle(fontSize: 12.5, color: AssasColors.muted);
  static TextStyle get label =>
      TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600, color: AssasColors.ink);
  static TextStyle get mutedLabel =>
      TextStyle(fontWeight: FontWeight.w600, color: AssasColors.muted);
  static TextStyle get statValue =>
      TextStyle(fontSize: 22, fontWeight: FontWeight.w800, color: AssasColors.ink);
}
