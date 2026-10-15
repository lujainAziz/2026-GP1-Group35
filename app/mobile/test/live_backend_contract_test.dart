import 'package:assas_core/assas_core.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const url = String.fromEnvironment('ASSAS_INTEGRATION_URL');
  test('Flutter repositories interoperate with the real local FastAPI backend', () async {
    final client = ApiClient(baseUrl: url);
    addTearDown(client.dispose);
    final repo = ApiRepository(client);
    final code = await repo.getCurrentPairingCode();
    final token = await repo.pair(code.code, deviceName: 'Flutter integration phone');
    repo.setAuthToken(token);
    expect(repo.applianceId, isNotEmpty);
    expect(await ApiRepository.identityAt(url), repo.applianceId);
    var resolutions = 0;
    final reconnecting = ApiClient(baseUrl: url, resolveBaseUrl: () async {
      resolutions++;
      return resolutions == 1 ? 'http://127.0.0.1:1' : url;
    });
    addTearDown(reconnecting.dispose);
    await expectLater(reconnecting.get('/healthz'), throwsA(anything));
    expect((await reconnecting.get('/healthz')).statusCode, 200);
    expect(resolutions, 2);
    final devices = await repo.getDevices();
    final mac = devices.first.mac;
    await repo.renameDevice(mac, 'Kitchen phone');
    expect((await repo.getDevice(mac)).displayName, 'Kitchen phone');
    expect((await repo.getDevices()).first.userName, 'Kitchen phone');
    await repo.renameDevice(mac, null);
    expect((await repo.getDevice(mac)).displayName, 'detected-phone');
    final trustedBefore = (await repo.getDevice(mac)).trusted;
    await repo.setTrusted(mac, !trustedBefore);
    expect((await repo.getDevice(mac)).trusted, !trustedBefore);
    expect((await repo.getDevices()).first.trusted, !trustedBefore);
    await repo.setTrusted(mac, trustedBefore);
    final settingsBefore = await repo.getSettings();
    await repo.updateSettings(settingsBefore.copyWith(activeProbes: !settingsBefore.activeProbes));
    expect((await repo.getSettings()).activeProbes, !settingsBefore.activeProbes);
    await repo.updateSettings(settingsBefore);
    final phones = await repo.getPairedPhones();
    expect(phones!.last.deviceName, 'Flutter integration phone');
    await repo.unpair();
  }, skip: url.isEmpty ? 'Requires isolated local backend fixture' : false);
}
