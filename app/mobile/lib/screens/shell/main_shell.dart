import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../config/data_source.dart';
import '../../state/app_state.dart';
import '../alerts/alert_list_screen.dart';
import '../dashboard/dashboard_screen.dart';
import '../devices/device_list_screen.dart';
import '../settings/settings_screen.dart';

/// Bottom tabs: Dashboard / Devices / Alerts / Settings.
/// Tabs switch freely (navigation diagram). The tab bar floats as glass.
class MainShell extends StatefulWidget {
  const MainShell({super.key});

  @override
  State<MainShell> createState() => _MainShellState();
}

class _MainShellState extends State<MainShell> {
  late final AppState _state = AppState(repository);
  int _index = 0;

  @override
  void initState() {
    super.initState();
    _state.startPolling();
  }

  @override
  void dispose() {
    _state.dispose();
    super.dispose();
  }

  void _goTo(int index) => setState(() => _index = index);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      extendBody: true, // content scrolls behind the floating glass bar
      body: IndexedStack(
        index: _index,
        children: [
          DashboardScreen(
            state: _state,
            onOpenDevices: () => _goTo(1),
            onOpenAlerts: () => _goTo(2),
          ),
          DeviceListScreen(state: _state),
          AlertListScreen(state: _state),
          SettingsScreen(state: _state),
        ],
      ),
      bottomNavigationBar: SafeArea(
        top: false,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
          child: GlassCard(
            padding: EdgeInsets.zero,
            radius: 26,
            opacity: 0.7,
            child: NavigationBar(
              height: 66,
              selectedIndex: _index,
              onDestinationSelected: _goTo,
              destinations: const [
                NavigationDestination(
                  icon: Icon(Icons.home_outlined),
                  selectedIcon: Icon(Icons.home_rounded),
                  label: 'Dashboard',
                ),
                NavigationDestination(
                  icon: Icon(Icons.devices_outlined),
                  selectedIcon: Icon(Icons.devices_rounded),
                  label: 'Devices',
                ),
                NavigationDestination(
                  icon: Icon(Icons.notifications_none_rounded),
                  selectedIcon: Icon(Icons.notifications_rounded),
                  label: 'Alerts',
                ),
                NavigationDestination(
                  icon: Icon(Icons.settings_outlined),
                  selectedIcon: Icon(Icons.settings_rounded),
                  label: 'Settings',
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
