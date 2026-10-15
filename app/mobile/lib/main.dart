import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import 'config/data_source.dart';
import 'screens/pairing/pairing_screen.dart';
import 'screens/shell/main_shell.dart';
import 'services/appliance_locator.dart';
import 'services/session_store.dart';
import 'state/app_settings.dart';
import 'theme/assas_ui.dart';
import 'widgets/assas_mobile_background.dart';
import 'widgets/design_scale.dart';
import 'widgets/splash_gate.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Appearance (dark mode, text size) saved from last time.
  await AppSettings.instance.load();
  AssasColors.useDark(AppSettings.instance.darkMode);

  // Build the active repository before first paint. The real backend resolves
  // its base URL via resolveApiBaseUrl (ASSAS_API_BASE_URL override -> DNS-SD
  // _assas._tcp -> assas-pi.local fallback); the demo repository ignores it.
  repository = await createRepository(resolveApiBaseUrl);

  // Already paired before? Use the saved token and skip the pairing screen.
  final token = await SessionStore.getToken();
  repository.setAuthToken(token);

  runApp(AssasApp(isPaired: token != null));
}

class AssasApp extends StatefulWidget {
  const AssasApp({super.key, required this.isPaired});

  final bool isPaired;

  @override
  State<AssasApp> createState() => _AssasAppState();
}

class _AssasAppState extends State<AssasApp> {
  final _settings = AppSettings.instance;

  @override
  void initState() {
    super.initState();
    _settings.addListener(_onSettingsChanged);
  }

  @override
  void dispose() {
    _settings.removeListener(_onSettingsChanged);
    super.dispose();
  }

  void _onSettingsChanged() {
    AssasColors.useDark(_settings.darkMode);
    setState(() {});
    // Colors are read directly by every screen, so ask every screen
    // (including the open ones) to redraw with the new colors.
    void rebuild(Element el) {
      el.markNeedsBuild();
      el.visitChildren(rebuild);
    }

    (context as Element).visitChildren(rebuild);
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Assas',
      debugShowCheckedModeBanner: false,
      // No stretch / glow when a list hits its top or bottom (design scrolls flat).
      scrollBehavior: const MaterialScrollBehavior().copyWith(overscroll: false),
      theme: MobileTheme.light,
      darkTheme: MobileTheme.dark,
      themeMode: _settings.darkMode ? ThemeMode.dark : ThemeMode.light,
      // Same .4s as the background fade when switching Midnight / Pearl.
      themeAnimationDuration: const Duration(milliseconds: 400),
      builder: (context, child) {
        // Phone text setting, kept in a safe range. The user's Text size choice
        // zooms the whole screen instead (DesignScale), like the design.
        final mq = MediaQuery.of(context);
        final scale = mq.textScaler.scale(1).clamp(
          AppSettings.minTextScale,
          AppSettings.maxTextScale,
        ).toDouble();
        // Keep the design's proportions on any screen width (design = 390).
        return DesignScale(
          zoom: _settings.textScale,
          // Builder: read the scaled screen size from DesignScale.
          child: Builder(
            builder: (context) => MediaQuery(
              data: MediaQuery.of(context).copyWith(textScaler: TextScaler.linear(scale)),
              // Design background (bg + ambient glow + grid) behind every screen.
              child: AssasMobileBackground(child: child ?? const SizedBox()),
            ),
          ),
        );
      },
      // Splash from the design, then the same first screen as before.
      home: SplashGate(child: widget.isPaired ? const MainShell() : const PairingScreen()),
    );
  }
}
