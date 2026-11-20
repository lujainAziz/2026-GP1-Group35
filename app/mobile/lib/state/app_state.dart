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

  /// Unresolved (New) alerts as a DB aggregate for the Alerts hero and the Home
  /// card — not the length of the loaded page. null = not available yet.
  int? unresolvedAlertCount;

  /// This phone's unread, unresolved alerts (the Unread tab), loaded up to
  /// [alertLimit] like [alerts]. null = not available (e.g. an appliance
  /// without read markers).
  List<SecurityAlert>? unreadAlerts;

  /// This phone's unread, unresolved alerts as a DB aggregate (the Unread tab
  /// badge). null = not available.
  int? unreadAlertCount;

  /// Alerts marked read here whose server write may not be visible to a poll
  /// yet; applied over refreshed data so the unread dot does not flash back.
  /// Value: when the write succeeded (null = still in flight). An entry is
  /// dropped after a poll that STARTED after that time has loaded.
  final Map<String, DateTime?> _readPending = {};

  /// The Unread badge: the DB count, else the loaded list's length.
  int? get unreadCount => unreadAlertCount ?? unreadAlerts?.length;

  bool get unreadHaveMore => (unreadAlerts?.length ?? 0) >= alertLimit;

  /// Alerts have their own freshness/error state, independent of devices/health:
  /// getAlerts can fail while health + devices succeed, and on a security screen
  /// the user must not see stale alerts presented as current. [alertsError] is
  /// true when the last alerts refresh failed (old data is kept but flagged);
  /// [alertsLastSync] is when alerts last loaded successfully.
  bool alertsError = false;
  DateTime? alertsLastSync;

  /// How many of the newest alerts the list currently loads. Raised by
  /// loadMoreAlerts() so older alerts are loaded on demand instead of being
  /// silently dropped at the cap. The open-count figure is always the full DB
  /// aggregate, independent of this.
  static const int _alertPageStep = 2000;
  int alertLimit = _alertPageStep;

  /// True when the loaded list is full to the current cap, so there may be
  /// older alerts not yet loaded.
  bool get alertsHaveMore => (alerts?.length ?? 0) >= alertLimit;

  Future<void> loadMoreAlerts() async {
    alertLimit += _alertPageStep;
    await refresh();
  }

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
    final started = DateTime.now();
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
        // Unread list + badge run alongside the list and the count (no extra
        // round-trip) but fail on their own: the result is the values or the
        // error, so it never throws unhandled if the code below returns early.
        final unreadFuture = Future.wait([
          repo.getUnreadAlerts(limit: alertLimit),
          repo.getUnreadAlertCount(),
        ]).then<Object>((v) => v, onError: (Object e) => e);
        try {
          // Fetch the list and the open-count concurrently so alerts add one
          // round-trip of latency, not two.
          final results = await Future.wait([repo.getAlerts(limit: alertLimit), repo.getOpenAlertCount()]);
          if (cancelled()) return;
          alerts = _withPendingReads(results[0] as List<SecurityAlert>?);
          unresolvedAlertCount = results[1] as int?;
          alertsError = false;
          alertsLastSync = DateTime.now();
        } catch (e) {
          if (cancelled()) return;
          // Keep the last alerts on screen but flag them as not current; apply
          // the same revoked-session handling as other protected calls.
          alertsError = true;
          if (handleFailure(e)) return;
        }
        // A failure here keeps the last unread values and never marks the main
        // alert list as not current.
        final unreadResult = await unreadFuture;
        if (cancelled()) return;
        if (unreadResult is List<Object?>) {
          final unread = unreadResult[0] as List<SecurityAlert>?;
          var count = unreadResult[1] as int?;
          if (count != null && unread != null) {
            // The server may not count a pending read yet; never show it.
            count -= unread.where((a) => _readPending.containsKey(a.id)).length;
            if (count < 0) count = 0;
          }
          unreadAlerts = unread?.where((a) => !_readPending.containsKey(a.id)).toList();
          unreadAlertCount = count;
          // Writes confirmed before this poll started are now in its data.
          _readPending.removeWhere((_, done) => done != null && done.isBefore(started));
        } else if (handleFailure(unreadResult)) {
          return;
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
    final old = alertById(id);
    await repo.setAlertState(id, state);
    // Apply the change locally at once so the list badge and the unresolved
    // count stay consistent even if a poll is already in flight (refresh() can
    // be gated by the in-flight generation). refresh() below reconciles with
    // the server. A resolved alert counts as read.
    final resolved = state == AlertState.resolved;
    if (alerts != null) {
      alerts = [
        for (final a in alerts!)
          a.id == id ? a.copyWith(state: state, read: resolved ? true : null) : a,
      ];
    }
    if (old != null && unresolvedAlertCount != null) {
      final wasUnresolved = old.isUnresolved;
      if (wasUnresolved && resolved) unresolvedAlertCount = unresolvedAlertCount! - 1;
      if (!wasUnresolved && !resolved) unresolvedAlertCount = unresolvedAlertCount! + 1;
    }
    if (resolved) {
      _dropUnread(id, wasUnread: (old?.isUnread ?? false) || _unreadById(id) != null);
    }
    notifyListeners();
    await refresh();
  }

  /// Opening an alert's details marks it read for this phone (no button). The
  /// dot and bold title go at once; a failed write puts them back. Not a
  /// state change. Only called when the alert is unread or not loaded.
  Future<void> markAlertRead(String id) async {
    final loaded = alertById(id) ?? _unreadById(id);
    if (loaded != null && !loaded.isUnread) return; // read, resolved or unknown
    final before = (alerts, unreadAlerts, unreadAlertCount);
    _readPending[id] = null;
    if (alerts != null) {
      alerts = [for (final a in alerts!) a.id == id ? a.copyWith(read: true) : a];
    }
    // Only an unresolved alert is in the Unread badge.
    _dropUnread(id, wasUnread: loaded != null && loaded.isUnresolved);
    notifyListeners();
    try {
      final updated = await repo.markAlertRead(id);
      if (_disposed) return;
      if (updated != null && alerts != null) {
        alerts = [for (final a in alerts!) a.id == id ? updated : a];
      }
    } catch (e) {
      if (_disposed) return;
      _readPending.remove(id);
      // Put the dot back.
      alerts = before.$1;
      unreadAlerts = before.$2;
      unreadAlertCount = before.$3;
      handleFailure(e);
      notifyListeners();
      return;
    }
    _readPending[id] = DateTime.now();
    notifyListeners();
    unawaited(refresh());
  }

  SecurityAlert? _unreadById(String id) {
    for (final a in unreadAlerts ?? const <SecurityAlert>[]) {
      if (a.id == id) return a;
    }
    return null;
  }

  /// Remove [id] from the Unread list, and from the badge when it was counted.
  void _dropUnread(String id, {required bool wasUnread}) {
    unreadAlerts = unreadAlerts?.where((a) => a.id != id).toList();
    if (wasUnread && unreadAlertCount != null && unreadAlertCount! > 0) {
      unreadAlertCount = unreadAlertCount! - 1;
    }
  }

  List<SecurityAlert>? _withPendingReads(List<SecurityAlert>? list) =>
      _readPending.isEmpty || list == null
          ? list
          : [for (final a in list) _readPending.containsKey(a.id) ? a.copyWith(read: true) : a];

  @override
  void dispose() {
    _disposed = true;
    stopPolling();
    super.dispose();
  }
}
