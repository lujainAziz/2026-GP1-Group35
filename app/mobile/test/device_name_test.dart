import 'package:assas_core/assas_core.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const device = Device(
    mac: 'aa:bb:cc:dd:ee:ff',
    hostname: 'detected-phone',
    userName: 'My phone',
    presence: Presence.online,
    trusted: false,
  );

  test('custom name takes precedence without changing the detected name', () {
    expect(device.displayName, 'My phone');
    expect(device.detectedName, 'detected-phone');
    expect(device.hasUserName, isTrue);
  });

  test('trust changes preserve the custom name and clearing restores detection', () {
    expect(device.copyWith(trusted: true).displayName, 'My phone');
    final cleared = device.copyWith(userName: '');
    expect(cleared.userName, isNull);
    expect(cleared.displayName, 'detected-phone');
    expect(cleared.hasUserName, isFalse);
  });

  test('API user_name is used and blank names fall back to detection', () {
    final parsed = Device.fromApi({
      'mac': device.mac,
      'hostname': 'detected-phone',
      'user_name': ' Kitchen phone ',
    });
    expect(parsed.displayName, 'Kitchen phone');
    expect(parsed.copyWith(userName: '   ').displayName, 'detected-phone');
  });
}
