import 'package:assas_mobile/services/session_store.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
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
