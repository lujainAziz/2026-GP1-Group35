import 'package:assas_core/assas_core.dart';
import '../state/app_state.dart';
import 'coming_soon.dart';
import 'package:assas_design/widgets/device_signals.dart';
export 'package:assas_design/widgets/device_signals.dart';
class Signals {
  Signals._();

  /// Worst unresolved alert severity per device MAC.
  static Map<String, Severity> worstByMac(List<SecurityAlert>? alerts) {
    final out = <String, Severity>{};
    for (final a in alerts ?? const <SecurityAlert>[]) {
      final mac = a.deviceMac;
      if (mac == null || !a.isUnresolved) continue;
      final cur = out[mac];
      if (cur == null || sevRank(a.severity) > sevRank(cur)) out[mac] = a.severity;
    }
    return out;
  }

  static List<DeviceSignal> all(AppState s) {
    final worst = worstByMac(Released.alertsOf(s));
    return [for (final d in s.devices) DeviceSignal(d, worst[d.mac])];
  }

  static DeviceSignal of(AppState s, Device d) => DeviceSignal(d, worstByMac(Released.alertsOf(s))[d.mac]);

  /// Sorted by priority, then name.
  static List<DeviceSignal> sorted(AppState s) => all(s)..sort(DeviceSignal.compare);

  /// Unresolved alerts first, then resolved.
  static List<SecurityAlert> openFirst(List<SecurityAlert> alerts) => [
        ...alerts.where((a) => a.isUnresolved),
        ...alerts.where((a) => !a.isUnresolved),
      ];

  /// Red badge on the Alerts tab (0 until alert management ships).
  static int unreadCount(AppState s) => !Released.alertManagement
      ? 0
      : (Released.alertsOf(s) ?? const <SecurityAlert>[]).where((a) => a.state == AlertState.newAlert).length;
}
