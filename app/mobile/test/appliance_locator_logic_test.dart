import 'package:assas_mobile/services/appliance_locator_logic.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const fallback = 'http://assas-pi.local:8000';

  group('staticBaseUrl precedence', () {
    test('non-empty override always wins (native)', () {
      expect(
        staticBaseUrl(
          override: 'http://192.168.1.20:8000',
          isWeb: false,
          fallback: fallback,
        ),
        'http://192.168.1.20:8000',
      );
    });

    test('override wins even on web', () {
      expect(
        staticBaseUrl(
          override: 'http://192.168.1.20:8000',
          isWeb: true,
          fallback: fallback,
        ),
        'http://192.168.1.20:8000',
      );
    });

    test('empty override on web uses the fallback (no DNS-SD on web)', () {
      expect(
        staticBaseUrl(override: '', isWeb: true, fallback: fallback),
        fallback,
      );
    });

    test('empty override on native returns null (caller runs discovery)', () {
      expect(
        staticBaseUrl(override: '', isWeb: false, fallback: fallback),
        isNull,
      );
    });
  });

  group('buildAssasBaseUrl', () {
    test('valid IPv4 + port builds the origin', () {
      expect(
        buildAssasBaseUrl(ipv4: '192.168.1.40', port: 8000, path: null),
        'http://192.168.1.40:8000',
      );
    });

    test('root path "/" does not add a trailing slash', () {
      expect(
        buildAssasBaseUrl(ipv4: '192.168.1.40', port: 8000, path: '/'),
        'http://192.168.1.40:8000',
      );
    });

    test('empty path yields just the origin', () {
      expect(
        buildAssasBaseUrl(ipv4: '192.168.1.40', port: 8000, path: ''),
        'http://192.168.1.40:8000',
      );
    });

    test('non-root path is appended with one leading slash', () {
      expect(
        buildAssasBaseUrl(ipv4: '10.0.0.5', port: 8000, path: '/api'),
        'http://10.0.0.5:8000/api',
      );
      expect(
        buildAssasBaseUrl(ipv4: '10.0.0.5', port: 8000, path: 'api'),
        'http://10.0.0.5:8000/api',
      );
    });

    test('missing IPv4 falls back (null)', () {
      expect(buildAssasBaseUrl(ipv4: null, port: 8000, path: '/'), isNull);
      expect(buildAssasBaseUrl(ipv4: '', port: 8000, path: '/'), isNull);
    });

    test('missing or non-positive port falls back (null)', () {
      expect(buildAssasBaseUrl(ipv4: '192.168.1.40', port: null), isNull);
      expect(buildAssasBaseUrl(ipv4: '192.168.1.40', port: 0), isNull);
      expect(buildAssasBaseUrl(ipv4: '192.168.1.40', port: -1), isNull);
    });
  });
}
