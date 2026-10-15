import 'dart:convert';
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/config/data_source.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  test('normal builds use the real backend', () {
    expect(kUseDemoBackend, isFalse);
    expect(kShowPairingSkip, isFalse);
  });
  for (final count in [0, 500, 1201]) {
    test('loads the complete inventory of $count devices', () async {
      final offsets = <int>[];
      final client = ApiClient(baseUrl: 'http://localhost', client: MockClient((r) async {
        final offset = int.parse(r.url.queryParameters['offset']!);
        offsets.add(offset);
        final end = (offset + 500).clamp(0, count);
        return http.Response(jsonEncode([
          for (var i = offset; i < end; i++) {'mac': 'device-$i'},
        ]), 200);
      }));
      addTearDown(client.dispose);
      final devices = await ApiRepository(client).getDevices();
      expect(devices.length, count);
      expect(offsets, [for (var i = 0; i <= count ~/ 500; i++) i * 500]);
    });
  }
  test('later page failure does not return a partial inventory', () async {
    final client = ApiClient(baseUrl: 'http://localhost', client: MockClient((r) async {
      if (r.url.queryParameters['offset'] != '0') return http.Response('', 503);
      return http.Response(jsonEncode([for (var i = 0; i < 500; i++) {'mac': '$i'}]), 200);
    }));
    addTearDown(client.dispose);
    await expectLater(ApiRepository(client).getDevices(), throwsA(isA<AssasApiException>()));
  });
  test('server repeating a full page terminates with an error', () async {
    final client = ApiClient(baseUrl: 'http://localhost', client: MockClient((r) async =>
      http.Response(jsonEncode([for (var i = 0; i < 500; i++) {'mac': '$i'}]), 200)));
    addTearDown(client.dispose);
    await expectLater(ApiRepository(client).getDevices(), throwsFormatException);
  });
}
