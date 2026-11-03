import 'dart:ui' as ui;

import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

// Mobile-only design tokens, copied from ASSAS_Final/DESIGN_SPEC.md.
// The 7-inch display keeps using assas_core's theme and is not affected.
//
// Light / dark follows the existing switch (AssasColors.isDark).

/// Colors for one mode (DESIGN_SPEC.md section 1.1).
class UiPalette {
  const UiPalette({
    required this.brightness,
    required this.bg,
    required this.surf,
    required this.surf2,
    required this.line,
    required this.ink,
    required this.mute,
    required this.acc,
    required this.accInk,
    required this.crit,
    required this.high,
    required this.med,
    required this.low,
    required this.glow,
    required this.ambientA,
    required this.ambientB,
    required this.grid,
  });

  final Brightness brightness;
  final Color bg;
  final Color surf;
  final Color surf2;
  final Color line;
  final Color ink;
  final Color mute;
  final Color acc;
  final Color accInk;
  final Color crit;
  final Color high;
  final Color med;
  final Color low;
  final Color glow;
  final Color ambientA;
  final Color ambientB;
  final Color grid;

  static const dark = UiPalette(
    brightness: Brightness.dark,
    bg: Color(0xFF0F0B16),
    surf: Color(0xFF18121F),
    surf2: Color(0xFF231B2E),
    line: Color(0x17FFFFFF), // rgba(255,255,255,.09)
    ink: Color(0xFFF4EFF9),
    mute: Color(0xFFA99EB8),
    acc: Color(0xFFB88CFF),
    accInk: Color(0xFF140C20),
    crit: Color(0xFFFF6B81),
    high: Color(0xFFFF9466),
    med: Color(0xFFF2C14E),
    low: Color(0xFF5FDDA8),
    glow: Color(0x61B88CFF), // rgba(184,140,255,.38)
    ambientA: Color(0x1FB88CFF), // rgba(184,140,255,.12)
    ambientB: Color(0x0E5FDDA8), // rgba(95,221,168,.055)
    grid: Color(0x06FFFFFF), // rgba(255,255,255,.025)
  );

  static const light = UiPalette(
    brightness: Brightness.light,
    bg: Color(0xFFF7F4FA),
    surf: Color(0xFFFFFFFF),
    surf2: Color(0xFFEEE8F4),
    line: Color(0x1A170F22), // rgba(23,15,34,.10)
    ink: Color(0xFF170F22),
    mute: Color(0xFF665B74),
    acc: Color(0xFF6B2FD6),
    accInk: Color(0xFFFFFFFF),
    crit: Color(0xFFC8243F),
    high: Color(0xFFBC4C1A),
    med: Color(0xFF8F6400),
    low: Color(0xFF12804F),
    glow: Color(0x386B2FD6), // rgba(107,47,214,.22)
    ambientA: Color(0x1A6B2FD6), // rgba(107,47,214,.10)
    ambientB: Color(0x0A12804F), // rgba(18,128,79,.04)
    grid: Color(0x09170F22), // rgba(23,15,34,.035)
  );
}

/// Colors of the active mode. Screens read colors from here.
class Ui {
  Ui._();

  static UiPalette get p => AssasColors.isDark ? UiPalette.dark : UiPalette.light;

  static Color get bg => p.bg;
  static Color get surf => p.surf;
  static Color get surf2 => p.surf2;
  static Color get line => p.line;
  static Color get ink => p.ink;
  static Color get mute => p.mute;
  static Color get acc => p.acc;
  static Color get accInk => p.accInk;
  static Color get crit => p.crit;
  static Color get high => p.high;
  static Color get med => p.med;
  static Color get low => p.low;
  static Color get glow => p.glow;
  static Color get ambientA => p.ambientA;
  static Color get ambientB => p.ambientB;
  static Color get grid => p.grid;

  // Fixed colors used by the design in both modes.
  static const Color white = Color(0xFFFFFFFF);
  static const Color black = Color(0xFF000000);
  static const Color eyeBadgeInk = Color(0xFF120B18);

  // Status
  static Color get online => p.low;
  static Color get offline => p.mute;
  static Color get trusted => p.low;
  static Color get unrecognized => p.med;
  static Color get notMonitored => p.high;

  /// CSS `color-mix(in oklch, a pct%, b)`, approximated in sRGB.
  /// [pct] is 0..1 (e.g. 0.22 for 22%).
  static Color mix(Color a, double pct, Color b) => Color.lerp(b, a, pct)!;

  /// CSS `color-mix(in oklch, a pct%, transparent)`.
  static Color fade(Color a, double pct) => a.withValues(alpha: a.a * pct);

  /// Severity / risk label -> color (Critical, High, Medium/Moderate, Low).
  static Color severity(String label) {
    final l = label.toLowerCase();
    if (l.contains('critical')) return crit;
    if (l.contains('high')) return high;
    if (l.contains('medium') || l.contains('moderate')) return med;
    return low;
  }
}

/// Font families (files in assets/fonts, declared in pubspec.yaml).
class UiFont {
  UiFont._();
  static const String sans = 'Bricolage Grotesque';
  static const String mono = 'JetBrains Mono';
}

/// Text styles (DESIGN_SPEC.md section 2.2).
/// Letter spacing is given in em like the design and converted to px.
class UiText {
  UiText._();

  static FontWeight _weight(int w) =>
      FontWeight.values[((w / 100).round() - 1).clamp(0, 8).toInt()];

  /// Bricolage Grotesque. The font is variable, so the exact weight and the
  /// optical size (auto in the browser) are set as font variations.
  static TextStyle sans(
    double size,
    int weight, {
    double? height,
    double em = 0,
    Color? color,
  }) {
    return TextStyle(
      fontFamily: UiFont.sans,
      fontSize: size,
      fontWeight: _weight(weight),
      fontVariations: [
        ui.FontVariation.weight(weight.toDouble()),
        ui.FontVariation.opticalSize(size.clamp(12, 96).toDouble()),
      ],
      height: height,
      letterSpacing: em * size,
      color: color ?? Ui.ink,
    );
  }

  /// JetBrains Mono (variable weight).
  static TextStyle mono(
    double size,
    int weight, {
    double? height,
    double em = 0,
    Color? color,
  }) {
    return TextStyle(
      fontFamily: UiFont.mono,
      fontSize: size,
      fontWeight: _weight(weight),
      fontVariations: [ui.FontVariation.weight(weight.toDouble())],
      height: height,
      letterSpacing: em * size,
      color: color ?? Ui.ink,
    );
  }

  // ---------- Titles and display ----------
  static TextStyle get alertsHero => sans(120, 800, height: 0.82, em: -0.06);
  static TextStyle get devicesHero => sans(72, 800, height: 0.9, em: -0.05);
  static TextStyle get riskWord => sans(66, 800, height: 0.98, em: -0.035);
  static TextStyle get onlineNumber => sans(64, 800, height: 0.9, em: -0.04);
  static TextStyle get settingsTitle => sans(46, 800, height: 0.92, em: -0.045);
  static TextStyle get pairTitle => sans(44, 800, height: 0.95, em: -0.04);
  static TextStyle get statNumber => sans(40, 800, em: -0.04);
  // Detail-screen titles: sized so long device names / alert signatures stay
  // readable (wrap, no clip) even at the smallest font setting. Used only on the
  // device-details and alert-details titles.
  static TextStyle get deviceName => sans(26, 800, height: 1.02, em: -0.03);
  static TextStyle get alertTitle => sans(22, 800, height: 1.12, em: -0.02);
  static TextStyle get splashWordmark => mono(24, 700, em: 0.55);

  // ---------- Section headers ----------
  static TextStyle get section => sans(20, 700, em: -0.02);
  static TextStyle get heroSuffix => sans(24, 700, em: -0.02);
  static TextStyle get kicker => mono(11, 500, em: 0.14);
  static TextStyle get groupLabel => mono(11, 600, em: 0.12);
  static TextStyle get wordmark => mono(13, 700, em: 0.32);

  // ---------- Body ----------
  static TextStyle get alertDescription => sans(15.5, 400, height: 1.5);
  static TextStyle get pairBody => sans(15, 400, height: 1.45);
  static TextStyle get input => sans(15, 500);
  static TextStyle get alertCardTitle => sans(17, 700, height: 1.25, em: -0.01);
  static TextStyle get recentTitle => sans(16, 700, em: -0.01);
  static TextStyle get rowTitle => sans(17, 700);
  static TextStyle get cardTitle => sans(16, 700);
  static TextStyle get why => sans(14, 400, height: 1.5);
  static TextStyle get deviceListName => sans(13.5, 750);
  static TextStyle get secondary => sans(13, 400);
  static TextStyle get rowSubtitle => sans(12.5, 400);
  static TextStyle get banner => sans(11.5, 400, height: 1.35);
  static TextStyle get error => sans(12, 400, height: 1.35);

  // ---------- Captions and mono data ----------
  static TextStyle get ip => mono(18, 700, height: 1.25, em: -0.02);
  static TextStyle get mac => mono(15, 700, height: 1.25, em: -0.02);
  static TextStyle get overviewNumber => mono(26, 800, height: 0.95, em: -0.03);
  static TextStyle get ribbonNumber => mono(13, 800);
  static TextStyle get specValue => mono(12.5, 600);
  static TextStyle get link => mono(12, 500); // "← BACK", "SEE ALL →"
  static TextStyle get connection => mono(11, 500);
  static TextStyle get alertMeta => mono(10.5, 500, em: 0.06);
  static TextStyle get alertTime => mono(10.5, 400);
  static TextStyle get verdict => mono(10.5, 600, em: 0.14);
  static TextStyle get specLabel => mono(10, 500, em: 0.1);
  static TextStyle get identityLabel => mono(9.5, 500, em: 0.14);
  static TextStyle get overviewLabel => mono(9, 600, em: 0.02);
  static TextStyle get ribbonLabel => mono(9, 600, em: 0.05);
  static TextStyle get watchTag => mono(9, 600, em: 0.08);
  static TextStyle get watchLead => mono(9, 600, em: 0.12);
  static TextStyle get typeKicker => mono(9, 600, em: 0.14);
  static TextStyle get listMeta => mono(8.7, 500);
  static TextStyle get synced => mono(8.5, 500);
  static TextStyle get indexHeader => mono(8.5, 600, em: 0.08);
  static TextStyle get listStatus => mono(8.4, 700);
  static TextStyle get liveSignal => mono(8, 600, em: 0.12);
  static TextStyle get eyeName => mono(8, 600, height: 1.25);
  static TextStyle get listFlag => mono(6.9, 700, em: 0.03);

  // ---------- Badges and pills ----------
  static TextStyle get pill => mono(10, 600);
  static TextStyle get statusPill => mono(10, 600, em: 0.1);
  static TextStyle get navBadge => mono(10, 700);
  static TextStyle get tabCount => mono(11, 600);
  static TextStyle get eyeBadge => mono(6.5, 800, em: 0.04);

  // ---------- Buttons ----------
  static TextStyle get button => sans(16, 700);
  static TextStyle get tab => sans(16, 700, em: -0.01);
  static TextStyle get navLabel => sans(14, 700);
  static TextStyle get menuItem => sans(14, 600);
  static TextStyle get clearSearch => sans(13, 700);
  static TextStyle get toast => sans(13, 600);
  static TextStyle get codeInput => mono(15, 600, em: 0.28);
}

/// Corner radius (DESIGN_SPEC.md section 4).
class UiRadius {
  UiRadius._();
  static const double nav = 33;
  static const double navItem = 25;
  static const double button = 28;
  static const double input = 28;
  static const double search = 25;
  static const double protectionCard = 28;
  static const double onlineCard = 26;
  static const double settingsCard = 26;
  static const double explainCard = 24;
  static const double card = 22; // stat, identity, spec list
  static const double alertCard = 20;
  static const double dropdown = 20;
  static const double dropdownItem = 14;
  static const double themeOption = 20;
  static const double iconTile = 18;
  static const double textSizeOption = 18;
  static const double row = 16;
  static const double toggle = 15;
  static const double overview = 14;
  static const double banner = 14;
  static const double explainTile = 10;
  static const double headerPill = 16;
  static const double bracket = 5;
  static const double pill = 999;
}

/// Spacing (DESIGN_SPEC.md section 3).
class UiSpace {
  UiSpace._();
  static const double pageText = 22;
  static const double pageCards = 16;
  static const double pagePair = 24;
  static const double statusBar = 46;
  static const double navBottomPad = 118;
  static const double detailBottomPad = 28;
  static const double cardPadV = 14;
  static const double cardPadH = 16;
}

/// Shadows (DESIGN_SPEC.md section 5.2).
class UiShadow {
  UiShadow._();

  static List<BoxShadow> get nav => const [
        BoxShadow(color: Color(0x3D000000), offset: Offset(0, 14), blurRadius: 34),
      ];

  static List<BoxShadow> get glass => const [
        BoxShadow(color: Color(0x14000000), offset: Offset(0, 12), blurRadius: 40),
      ];

  static List<BoxShadow> get orb => const [
        BoxShadow(color: Color(0x29000000), offset: Offset(0, 8), blurRadius: 22),
      ];

  static List<BoxShadow> get dropdown => const [
        BoxShadow(color: Color(0x73000000), offset: Offset(0, 18), blurRadius: 40),
      ];

  static List<BoxShadow> get toggleKnob => const [
        BoxShadow(color: Color(0x38000000), offset: Offset(0, 2), blurRadius: 8),
      ];

  /// `0 0 <blur> color` glow.
  static List<BoxShadow> glow(Color color, double blur) =>
      [BoxShadow(color: color, blurRadius: blur)];
}

/// ThemeData for the phone app.
class MobileTheme {
  MobileTheme._();

  static ThemeData get light => _build(UiPalette.light);
  static ThemeData get dark => _build(UiPalette.dark);

  static ThemeData _build(UiPalette p) {
    final scheme = ColorScheme(
      brightness: p.brightness,
      primary: p.acc,
      onPrimary: p.accInk,
      secondary: p.acc,
      onSecondary: p.accInk,
      error: p.crit,
      onError: Ui.white,
      surface: p.surf,
      onSurface: p.ink,
    );

    final base = p.brightness == Brightness.dark
        ? Typography.material2021().white
        : Typography.material2021().black;

    TextStyle sans(double size, int weight) =>
        UiText.sans(size, weight, color: p.ink);

    final buttonShape =
        RoundedRectangleBorder(borderRadius: BorderRadius.circular(UiRadius.button));

    OutlineInputBorder inputBorder(Color color, double width) => OutlineInputBorder(
          borderRadius: BorderRadius.circular(UiRadius.input),
          borderSide: BorderSide(color: color, width: width),
        );

    return ThemeData(
      useMaterial3: true,
      brightness: p.brightness,
      colorScheme: scheme,
      fontFamily: UiFont.sans,
      // Transparent so the background widget shows behind every screen.
      scaffoldBackgroundColor: Colors.transparent,
      canvasColor: p.bg,
      dividerColor: p.line,
      dividerTheme: DividerThemeData(color: p.line, thickness: 1, space: 1),
      textTheme: base.apply(
        fontFamily: UiFont.sans,
        bodyColor: p.ink,
        displayColor: p.ink,
      ),
      iconTheme: IconThemeData(color: p.ink),
      appBarTheme: AppBarTheme(
        backgroundColor: Colors.transparent,
        surfaceTintColor: Colors.transparent,
        foregroundColor: p.ink,
        elevation: 0,
        scrolledUnderElevation: 0,
        titleTextStyle: sans(20, 700),
      ),
      cardTheme: CardThemeData(
        color: p.surf,
        surfaceTintColor: Colors.transparent,
        elevation: 0,
        margin: EdgeInsets.zero,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(UiRadius.card),
          side: BorderSide(color: p.line),
        ),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: p.acc,
          foregroundColor: p.accInk,
          minimumSize: const Size.fromHeight(56),
          shape: buttonShape,
          textStyle: sans(16, 700),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: p.ink,
          minimumSize: const Size.fromHeight(56),
          side: BorderSide(color: p.acc, width: 1.5),
          shape: buttonShape,
          textStyle: sans(16, 700),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: p.acc,
          textStyle: UiText.mono(12, 500, color: p.acc),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: p.surf,
        hintStyle: sans(15, 500).copyWith(color: p.mute),
        contentPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 18),
        border: inputBorder(p.line, 1),
        enabledBorder: inputBorder(p.line, 1),
        focusedBorder: inputBorder(p.acc, 1.5),
        errorBorder: inputBorder(p.crit, 1),
        focusedErrorBorder: inputBorder(p.crit, 1.5),
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: Colors.transparent,
        surfaceTintColor: Colors.transparent,
        elevation: 0,
        indicatorColor: p.acc,
        labelTextStyle: WidgetStateProperty.resolveWith((states) {
          final selected = states.contains(WidgetState.selected);
          return UiText.sans(14, 700, color: selected ? p.ink : p.mute);
        }),
        iconTheme: WidgetStateProperty.resolveWith((states) {
          final selected = states.contains(WidgetState.selected);
          return IconThemeData(color: selected ? p.accInk : p.mute, size: 21);
        }),
      ),
      switchTheme: SwitchThemeData(
        thumbColor: WidgetStateProperty.all(Ui.white),
        trackColor: WidgetStateProperty.resolveWith(
          (s) => s.contains(WidgetState.selected) ? p.acc : p.surf2,
        ),
        trackOutlineColor: WidgetStateProperty.all(p.line),
      ),
      sliderTheme: SliderThemeData(
        activeTrackColor: p.acc,
        inactiveTrackColor: p.surf2,
        thumbColor: p.acc,
      ),
      progressIndicatorTheme: ProgressIndicatorThemeData(color: p.acc),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        // Above the floating tab bar (design toast sits at bottom 104).
        insetPadding: const EdgeInsets.fromLTRB(24, 0, 24, 104),
        backgroundColor: p.ink,
        contentTextStyle: UiText.sans(13, 600, color: p.bg),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(UiRadius.pill)),
      ),
      dialogTheme: DialogThemeData(
        backgroundColor: p.surf,
        surfaceTintColor: Colors.transparent,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(UiRadius.settingsCard)),
      ),
      bottomSheetTheme: BottomSheetThemeData(
        backgroundColor: p.surf,
        surfaceTintColor: Colors.transparent,
      ),
    );
  }
}
