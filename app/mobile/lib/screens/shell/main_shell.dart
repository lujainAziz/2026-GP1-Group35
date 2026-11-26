import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../../config/data_source.dart';
import '../../services/session_store.dart';
import '../../state/app_state.dart';
import '../../theme/assas_ui.dart';
import '../../widgets/assas_nav_bar.dart';
import '../../widgets/device_signals.dart';
import '../../widgets/ui_kit.dart';
import '../../widgets/ui_memory.dart';
import '../../widgets/ui_overlays.dart';
import '../alerts/alert_list_screen.dart';
import '../dashboard/dashboard_screen.dart';
import '../devices/device_list_screen.dart';
import '../pairing/pairing_screen.dart';
import '../settings/settings_screen.dart';

/// Bottom tabs: Home / Devices / Alerts / Settings.
/// Tabs switch freely (navigation diagram). The tab bar floats as glass.
class MainShell extends StatefulWidget {
  const MainShell({super.key});

  @override
  State<MainShell> createState() => _MainShellState();
}

class _MainShellState extends State<MainShell> {
  late final AppState _state = AppState(repository);
  int _index = 0;

  /// Filter (set of poles) the Devices tab should switch to when opened from
  /// the dashboard. Empty set = All.
  final _deviceFilter = ValueNotifier<Set<FilterPole>?>(null);

  /// Set when the dashboard opens the Alerts tab: show All, scrolled to the top.
  final _alertsAll = ValueNotifier<bool>(false);

  @override
  void initState() {
    super.initState();
    _state.addListener(_onSessionEnded);
    _state.startPolling();
    // Reopen the tab the user was on last time.
    UiMemory.tab().then((t) {
      if (mounted) setState(() => _index = t.clamp(0, 3).toInt());
    });
  }

  @override
  void dispose() {
    _state.removeListener(_onSessionEnded);
    _deviceFilter.dispose();
    _alertsAll.dispose();
    _state.dispose();
    super.dispose();
  }

  bool _leaving = false;

  /// Forget a revoked session and remove protected screens from the stack.
  Future<void> _onSessionEnded() async {
    if (!_state.sessionEnded || _leaving) return;
    _leaving = true;
    await SessionStore.clear();
    repository.setAuthToken(null);
    if (!mounted) return;
    showToast(context, 'This phone is no longer paired. Pair it again to continue.');
    Navigator.of(context).pushAndRemoveUntil(
      MaterialPageRoute(builder: (_) => const PairingScreen()),
      (_) => false,
    );
  }

  void _goTo(int index) {
    setState(() => _index = index);
    UiMemory.setTab(index);
  }

  void _openDevices(Set<FilterPole> filter) {
    _deviceFilter.value = filter;
    _goTo(1);
  }

  void _openAlerts() {
    _alertsAll.value = true;
    _goTo(2);
  }

  @override
  Widget build(BuildContext context) {
    final bottom = math.max(22.0, MediaQuery.paddingOf(context).bottom + 8);
    final tabs = [
      DashboardScreen(
        state: _state,
        onOpenDevices: () => _openDevices(const {}),
        onOpenUnrecognized: () => _openDevices(const {FilterPole.untrusted}),
        onOpenAlerts: _openAlerts,
      ),
      DeviceListScreen(state: _state, filterRequest: _deviceFilter),
      AlertListScreen(state: _state, allRequest: _alertsAll),
      SettingsScreen(state: _state),
    ];
    return Scaffold(
      body: Stack(
        children: [
          IndexedStack(
            index: _index,
            children: [
              for (var i = 0; i < tabs.length; i++)
                // Replays the design's screen entrance each time a tab opens.
                FadeSlideIn(replayKey: i == _index ? 'on' : 'off', child: tabs[i]),
            ],
          ),
          // Decorative corner bracket above the tab bar (design: right 12, bottom 104).
          Positioned(
            right: 12,
            bottom: bottom + 82,
            child: const IgnorePointer(
              child: Opacity(
                opacity: .42,
                child: CustomPaint(size: Size(28, 28), painter: _CornerPainter()),
              ),
            ),
          ),
          Positioned(
            left: 16,
            right: 16,
            bottom: bottom,
            child: ListenableBuilder(
              listenable: _state,
              builder: (context, _) => AssasNavBar(
                index: _index,
                onSelect: _goTo,
                unread: Signals.unreadCount(_state),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// Bottom-right bracket: 1px accent on the right and bottom, radius 8.
class _CornerPainter extends CustomPainter {
  const _CornerPainter();

  @override
  void paint(Canvas canvas, Size size) {
    const r = 8.0;
    final w = size.width - .5, h = size.height - .5;
    final p = Path()
      ..moveTo(w, 0)
      ..lineTo(w, h - r)
      ..arcToPoint(Offset(w - r, h), radius: const Radius.circular(r))
      ..lineTo(0, h);
    canvas.drawPath(
      p,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1
        ..color = Ui.acc,
    );
  }

  @override
  bool shouldRepaint(_CornerPainter old) => true;
}
