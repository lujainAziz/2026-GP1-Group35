import 'package:assas_mobile/services/session_store.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
  });
  test('invalid session field types are treated as unpaired', () async {
    for (final raw in [
      '{"token":123,"appliance_id":"pi"}',
      '{"token":"valid","appliance_id":123}',
      '{"token":"","appliance_id":"pi"}',
      '{"appliance_id":"pi"}',
    ]) {
      FlutterSecureStorage.setMockInitialValues({'assas_session_v2': raw});
      expect(await SessionStore.getToken(), isNull);
      expect(await SessionStore.getApplianceId(), isNull);
    }
  });
  test('migrates token and identity before removing plaintext', () async {
    SharedPreferences.setMockInitialValues({'assas_session_token': 'old', 'assas_appliance_id': 'pi'});
    expect(await SessionStore.getToken(), 'old');
    expect(await SessionStore.getApplianceId(), 'pi');
    final prefs = await SharedPreferences.getInstance();
    expect(prefs.containsKey('assas_session_token'), isFalse);
    expect(prefs.containsKey('assas_appliance_id'), isFalse);
    await SessionStore.clear();
    expect(await SessionStore.getToken(), isNull);
  });
  test('saving without identity never keeps the previous appliance', () async {
    await SessionStore.saveToken('first', applianceId: 'pi');
    await SessionStore.saveToken('second');
    expect(await SessionStore.getToken(), 'second');
    expect(await SessionStore.getApplianceId(), isNull);
  });
}
