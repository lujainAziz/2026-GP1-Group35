import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:flutter_test/flutter_test.dart';

class _RejectedRepository extends DemoRepository {
  _RejectedRepository(this.status);
  final int status;
  int deviceRequests = 0;
  int alertRequests = 0;

  @override
  Future<ConnectionStatus> checkHealth() async => ConnectionStatus.live;

  @override
  Future<List<Device>> getDevices() async {
    deviceRequests++;
    throw AssasApiException('Rejected', statusCode: status);
  }

  @override
  Future<List<SecurityAlert>?> getAlerts({int? limit}) async {
    alertRequests++;
    return [];
  }

  @override
  Future<RiskInfo?> getRiskLevel() async => null;
}

void main() {
  testWidgets('401 ends session despite healthy connection and stops polling', (tester) async {
    final repo = _RejectedRepository(401);
    final state = AppState(repo);
    var endedNotifications = 0;
    state.addListener(() {
      if (state.sessionEnded) endedNotifications++;
    });
    state.startPolling();
    await tester.pump();
    expect(state.sessionEnded, isTrue);
    expect(endedNotifications, 1);
    expect(repo.alertRequests, 0);
    await tester.pump(const Duration(seconds: 15));
    await state.refresh();
    state.startPolling();
    await tester.pump();
    expect(repo.deviceRequests, 1);
    state.dispose();
  });

  test('server errors preserve cached devices without ending the session', () async {
    final state = AppState(_RejectedRepository(500));
    const device = Device(mac: 'test', presence: Presence.online, trusted: true);
    state.devices = [device];
    await state.refresh();
    expect(state.sessionEnded, isFalse);
    expect(state.devices, [device]);
    expect(state.loadedOnce, isTrue);
    expect(state.connection, ConnectionStatus.stale);
    state.dispose();
  });
}
