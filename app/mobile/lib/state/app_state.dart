import 'dart:async';

import 'package:assas_core/assas_core.dart';
import 'package:flutter/foundation.dart';

/// Holds the latest data for all tabs and refreshes it every few seconds
/// (API_CONTRACT polling guidance: devices every 5 s).
///
/// When a request fails, the last good data stays on screen and only the
/// connection pill changes.
class AppState extends ChangeNotifier {
  AppState(this.repo);

  final AssasRepository repo;

  List<Device> devices = const [];
  List<SecurityAlert>? alerts; // null = not available yet
  RiskInfo? risk; // null = not available yet
  ConnectionStatus connection = ConnectionStatus.live;
  bool loadedOnce = false;

  Timer? _timer;
  bool _busy = false;

  void startPolling() {
    refresh();
    _timer?.cancel();
    _timer = Timer.periodic(const Duration(seconds: 5), (_) => refresh());
  }

  void stopPolling() {
    _timer?.cancel();
    _timer = null;
  }

  Future<void> refresh() async {
    if (_busy) return;
    _busy = true;
    try {
      connection = await repo.checkHealth();

      try {
        devices = await repo.getDevices();
      } catch (_) {
        // keep last devices
      }
      try {
        alerts = await repo.getAlerts();
      } catch (_) {
        // keep last alerts
      }
      try {
        risk = await repo.getRiskLevel();
      } catch (_) {
        // keep last risk
      }
      loadedOnce = true;
      notifyListeners();
    } finally {
      _busy = false;
    }
  }

  // ---------- Derived values for the dashboard ----------
  int get onlineCount => devices.where((d) => d.isOnline).length;
  int get totalCount => devices.length;
  int get unrecognizedCount => devices.where((d) => d.isUnrecognized).length;

  /// null when alerts are not available yet (never shown as a fake 0).
  int? get unresolvedCount => alerts?.where((a) => a.isUnresolved).length;

  Device? deviceByMac(String mac) {
    for (final d in devices) {
      if (d.mac == mac) return d;
    }
    return null;
  }

  SecurityAlert? alertById(String id) {
    for (final a in alerts ?? const <SecurityAlert>[]) {
      if (a.id == id) return a;
    }
    return null;
  }

  List<SecurityAlert>? alertsForDevice(String mac) =>
      alerts?.where((a) => a.deviceMac == mac).toList();

  // ---------- Actions ----------
  Future<void> setTrusted(String mac, bool trusted) async {
    await repo.setTrusted(mac, trusted);
    await refresh();
  }

  Future<void> setAlertState(String id, AlertState state) async {
    await repo.setAlertState(id, state);
    await refresh();
  }

  @override
  void dispose() {
    stopPolling();
    super.dispose();
  }
}
