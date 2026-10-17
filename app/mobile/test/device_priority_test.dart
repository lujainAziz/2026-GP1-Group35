import 'package:assas_core/assas_core.dart';
import 'package:assas_design/widgets/device_signals.dart';
import 'package:flutter_test/flutter_test.dart';

DeviceSignal signal(String mac, {bool online = true, bool trusted = true,
    bool monitored = true, Severity? severity, String? name}) => DeviceSignal(
  Device(mac: mac, presence: online ? Presence.online : Presence.offline,
    trusted: trusted, monitored: monitored, hostname: name), severity);

void main() {
  test('every online device precedes offline devices regardless of attention', () {
    for (final severity in [null, ...Severity.values]) {
      for (final trusted in [true, false]) {
        for (final monitored in [true, false]) {
          final online = signal('online', name: 'Z');
          final offline = signal('offline', online: false, trusted: trusted,
              monitored: monitored, severity: severity, name: 'A');
          expect(DeviceSignal.compare(online, offline), lessThan(0));
          expect(DeviceSignal.compare(offline, online), greaterThan(0));
        }
      }
    }
  });

  test('attention priority is preserved within each presence group', () {
    for (final online in [true, false]) {
      final devices = [
        signal('clear', online: online),
        signal('unmonitored', online: online, monitored: false),
        signal('unrecognized', online: online, trusted: false),
        for (final severity in Severity.values)
          signal(severity.name, online: online, severity: severity),
      ]..sort(DeviceSignal.compare);
      expect(devices.map((s) => s.device.mac),
          ['critical', 'high', 'medium', 'low', 'unrecognized', 'unmonitored', 'clear']);
    }
  });

  test('equal names have a stable MAC order regardless of input order', () {
    final a = signal('aa', name: 'Phone');
    final b = signal('bb', name: 'phone');
    for (final devices in [[b, a], [a, b]]) {
      devices.sort(DeviceSignal.compare);
      expect(devices.map((s) => s.device.mac), ['aa', 'bb']);
    }
    expect(DeviceSignal.compare(a, a), 0);
  });

  test('going offline moves an unrecognized device below online trusted devices', () {
    final trusted = signal('trusted');
    final before = [trusted, signal('new', trusted: false)]..sort(DeviceSignal.compare);
    expect(before.first.device.mac, 'new');
    final after = [signal('new', trusted: false, online: false), trusted]
      ..sort(DeviceSignal.compare);
    expect(after.first.device.mac, 'trusted');
  });
}
