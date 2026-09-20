import 'package:assas_app/services/assas_api_service.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  test('uses the real Sprint 0 API paths', () async {
    final requestedPaths = <String>[];
    final client = MockClient((request) async {
      requestedPaths.add(request.url.path);

      switch (request.url.path) {
        case '/healthz':
          return http.Response(
            '{"status":"ok","db_available":true,"daemon_stale":false}',
            200,
          );
        case '/summary':
          return http.Response(
            '{"total_known":80,"current_subnet":13,"traffic_runtime":3,'
            '"traffic_inventory":2,"traffic_only_hidden":1,"ap_current":0,'
            '"historical":64,"by_status":[],"by_device_type":[]}',
            200,
          );
        case '/devices':
          return http.Response(
            '[{"mac":"aa:bb:cc:dd:ee:ff","status":"online"}]',
            200,
          );
        case '/devices/aa%3Abb%3Acc%3Add%3Aee%3Aff':
        case '/devices/aa:bb:cc:dd:ee:ff':
          return http.Response(
            '{"mac":"aa:bb:cc:dd:ee:ff","status":"online",'
            '"classification":{"device_type":"Laptop"}}',
            200,
          );
      }

      return http.Response('not found', 404);
    });

    final api = AssasApiService(
      baseUrl: 'http://example.local:8000/',
      client: client,
    );

    expect(api.baseUrl, 'http://example.local:8000');
    await api.getHealth();
    await api.getSummary();
    await api.getDevices();
    await api.getDevice('aa:bb:cc:dd:ee:ff');

    expect(requestedPaths, contains('/healthz'));
    expect(requestedPaths, contains('/summary'));
    expect(requestedPaths, contains('/devices'));
    expect(
      requestedPaths.any((path) => path.startsWith('/devices/aa')),
      isTrue,
    );
  });

  test('throws a typed exception for non-success responses', () async {
    final client = MockClient((request) async {
      return http.Response('{"detail":"db unavailable"}', 503);
    });

    final api = AssasApiService(
      baseUrl: 'http://example.local:8000',
      client: client,
    );

    expect(
      api.getHealth(),
      throwsA(
        isA<AssasApiException>().having(
          (error) => error.statusCode,
          'statusCode',
          503,
        ),
      ),
    );
  });
}
