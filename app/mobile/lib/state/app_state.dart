import 'dart:async';

import 'package:assas_core/assas_core.dart';
import 'package:flutter/foundation.dart';
import 'package:assas_design/release_status.dart';

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
  LiveActivity? activity;
  ConnectionStatus connection = ConnectionStatus.checking;
  bool loadedOnce = false;

  /// True when Assas rejected this phone's session (HTTP 401): it was revoked
  /// or the appliance was reset. The phone must pair again.
  bool sessionEnded = false;

  /// When the device list was last received from Assas (null = never).
  DateTime? lastSync;

  Timer? _timer;
  /// Generation of the refresh in flight. A refresh cancelled by stopPolling()
  /// no longer blocks the next one, so polling resumes at once after restart.
  int? _busyGeneration;
  bool _disposed = false;
  int _generation = 0;

  void startPolling() {
    if (sessionEnded) return;
    refresh();
    _timer?.cancel();
    _timer = Timer.periodic(const Duration(seconds: 5), (_) => refresh());
  }

  void stopPolling() {
    _generation++;
    _timer?.cancel();
    _timer = null;
  }

  Future<void> refresh() async {
    if (_busyGeneration == _generation || sessionEnded || _disposed) return;
    final generation = _generation;
    bool cancelled() => _disposed || generation != _generation || sessionEnded;
    _busyGeneration = generation;
    try {
      final health = await repo.checkHealth();
      if (cancelled()) return;
      connection = health;

      try {
        final latest = await repo.getDevices();
        if (cancelled()) return;
        devices = latest;
        lastSync = DateTime.now();
      } on AssasApiException catch (e) {
        if (cancelled()) return;
        if (e.statusCode == 401) {
          // Session revoked: stop asking, the screen sends the user to pairing.
          sessionEnded = true;
          stopPolling();
          notifyListeners();
          return;
        }
        // other errors: keep last devices
        if (connection == ConnectionStatus.live) connection = ConnectionStatus.stale;
      } catch (_) {
        if (cancelled()) return;
        // keep last devices
        if (connection == ConnectionStatus.live) connection = ConnectionStatus.stale;
      }
      try {
        final latest = await repo.getActivity();
        if (cancelled()) return;
        activity = latest;
      } catch (e) {
        if (cancelled()) return;
        activity = null;
        if (handleFailure(e)) return;
      }
      if (FeatureRelease.alerts) {
      try {
        alerts = await repo.getAlerts();
      } catch (_) {
        // keep last alerts
      }
      }
      if (FeatureRelease.risk) {
      try {
        risk = await repo.getRiskLevel();
      } catch (_) {
        // keep last risk
      }
      }
      if (cancelled()) return;
      loadedOnce = true;
      notifyListeners();
    } finally {
      if (_busyGeneration == generation) _busyGeneration = null;
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

  /// Use the same revoked-session handling for every protected operation.
  bool handleFailure(Object error) {
    if (_disposed) return false;
    if (error is! AssasApiException || error.statusCode != 401) return false;
    if (!sessionEnded) {
      sessionEnded = true;
      stopPolling();
      notifyListeners();
    }
    return true;
  }

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
    _disposed = true;
    stopPolling();
    super.dispose();
  }
}
