import 'package:assas_core/assas_core.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  _ipv6();
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

void _ipv6() {
  group('displayIpv6 excludes the unspecified address', () {
    test('drops :: and empties, keeps fe80:: and global', () {
      const d = Device(
        mac: 'aa:bb:cc:dd:ee:ff',
        presence: Presence.online,
        trusted: false,
        ipv6: [
          '::',
          'fe80::1ff:fe23:4567:890a',
          '0:0:0:0:0:0:0:0',
          '  ',
          '2001:16a2:c83e:5700:78f5:8a3d:cbf4:b5fe',
        ],
      );
      expect(d.displayIpv6, [
        'fe80::1ff:fe23:4567:890a',
        '2001:16a2:c83e:5700:78f5:8a3d:cbf4:b5fe',
      ]);
    });
  });
}
