import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../theme/assas_ui.dart';
import 'ui_icons.dart';

// Display rules from the design (ASSAS.dc.html, renderVals).
// Read-only: everything here is computed from data the screens already have.

Color sevColor(Severity s) => switch (s) {
      Severity.critical => Ui.crit,
      Severity.high => Ui.high,
      Severity.medium => Ui.med,
      Severity.low => Ui.low,
    };

int sevRank(Severity s) => s.index + 1; // low 1 ... critical 4

String sevUpper(Severity s) => switch (s) {
      Severity.critical => 'CRITICAL',
      Severity.high => 'HIGH',
      Severity.medium => 'MEDIUM',
      Severity.low => 'LOW',
    };

String kindUpper(SecurityAlert a) => a.kind == AlertKind.threat ? 'THREAT' : 'ANOMALY';

/// Status pill colors: New = accent, Reviewed / Resolved = muted.
Color stateColor(SecurityAlert a) => a.state == AlertState.newAlert ? Ui.acc : Ui.mute;
Color stateBg(SecurityAlert a) =>
    a.state == AlertState.newAlert ? Ui.fade(Ui.acc, 0.20) : Ui.fade(Ui.mute, 0.16);

/// One device plus its worst open alert.
class DeviceSignal {
  const DeviceSignal(this.device, this.alertSev);

  final Device device;
  final Severity? alertSev;

  bool get hasAlert => alertSev != null;
  bool get unrec => device.isUnrecognized;
  bool get notMonitored => device.isNotMonitored;
  bool get online => device.isOnline;
  bool get needsAttention => hasAlert || unrec || notMonitored;

  /// Attention priority within the same connection state.
  int get score =>
      (alertSev != null ? sevRank(alertSev!) * 1000 : 0) +
      (unrec ? 82 : 0) +
      (notMonitored ? 64 : 0) +
      (online ? 12 : 0);

  Color get alertColor => alertSev == null ? Colors.transparent : sevColor(alertSev!);
  Color get heroColor => hasAlert ? alertColor : unrec ? Ui.med : !online ? Ui.mute : Ui.acc;
  Color get rowAccent => hasAlert
      ? alertColor
      : unrec
          ? Ui.med
          : notMonitored
              ? Ui.high
              : online
                  ? Ui.low
                  : Ui.line;
  Color get bar => online ? (hasAlert ? alertColor : unrec ? Ui.med : Ui.low) : Ui.line;
  Color get signalColor => hasAlert ? alertColor : unrec ? Ui.med : notMonitored ? Ui.high : Ui.acc;
  String get badge => hasAlert ? '!' : unrec ? 'NEW' : notMonitored ? 'WATCH' : '';
  Color get dotColor => online ? Ui.low : Ui.mute;
  Color get trustColor => device.trusted ? Ui.low : Ui.med;
  String get icon => UiIcons.forDevice(device);

  String get verdict => hasAlert
      ? '${sevUpper(alertSev!)} ALERT OPEN'
      : unrec
          ? 'NOT RECOGNIZED YET'
          : !online
              ? 'OFFLINE'
              : 'ALL CLEAR';

  static int compare(DeviceSignal a, DeviceSignal b) {
    // Presence takes precedence even over an offline device's open alerts.
    if (a.online != b.online) return a.online ? -1 : 1;
    final s = b.score - a.score;
    if (s != 0) return s;
    final name = a.device.displayName.toLowerCase().compareTo(b.device.displayName.toLowerCase());
    if (name != 0) return name;
    // Multiple unnamed devices must retain a stable order between refreshes.
    return a.device.mac.compareTo(b.device.mac);
  }
}


/// Connection status text and color (CONNECTED / OUTDATED / OFFLINE).
class ConnectionLook {
  ConnectionLook._();

  // User-facing connection is Connected / Disconnected, with Outdated when the
  // last data could not be refreshed. This describes the app<->appliance link
  // only; Online/Offline is reserved for each device's own presence.
  static String text(ConnectionStatus c) => switch (c) {
        ConnectionStatus.checking => 'CONNECTING',
        ConnectionStatus.live => 'CONNECTED',
        ConnectionStatus.stale => 'OUTDATED',
        ConnectionStatus.unreachable => 'DISCONNECTED',
      };

  static Color color(ConnectionStatus c) => switch (c) {
        ConnectionStatus.checking => Ui.mute,
        ConnectionStatus.live => Ui.low,
        ConnectionStatus.stale => Ui.med,
        ConnectionStatus.unreachable => Ui.crit,
      };

  /// "SYNCED NOW" while fresh, otherwise how long ago the last sync was.
  static String synced(ConnectionStatus c, DateTime? last) {
    // When the data is stale, say so plainly instead of a fresh "synced" phrase.
    if (c == ConnectionStatus.stale) return 'OUTDATED';
    if (last == null) return c == ConnectionStatus.live ? 'SYNCING…' : 'NOT SYNCED YET';
    final age = DateTime.now().difference(last);
    if (c == ConnectionStatus.live && age.inSeconds < 15) return 'SYNCED NOW';
    final ago = age.inSeconds < 60
        ? '${age.inSeconds}S AGO'
        : age.inMinutes < 60
            ? '${age.inMinutes} MIN AGO'
            : '${age.inHours} H AGO';
    return 'LAST SYNC · $ago';
  }
}
