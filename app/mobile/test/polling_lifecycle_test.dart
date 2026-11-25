import 'dart:async';
import 'package:flutter_test/flutter_test.dart';
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/state/app_state.dart';

class SlowRepo extends DemoRepository {
  final pending = Completer<List<Device>>();
  int calls = 0;
  @override
  Future<List<Device>> getDevices() {
    calls++;
    return calls == 1 ? pending.future : Future.value(const <Device>[]);
  }
}
void main() {
  test('refresh may finish safely after leaving the shell', () async {
    final repo = SlowRepo();
    final state = AppState(repo);
    final refresh = state.refresh();
    await Future<void>.delayed(Duration.zero);
    state.dispose();
    repo.pending.complete([]);
    await refresh;
  });
  test('restarting polling does not wait for a cancelled refresh', () async {
    final repo = SlowRepo();
    final state = AppState(repo);
    state.startPolling();
    await Future<void>.delayed(Duration.zero);
    expect(repo.calls, 1);
    state.stopPolling();
    state.startPolling();
    // The restart issues a fresh getDevices at once (calls == 2) without waiting
    // on the cancelled refresh; wait past the demo getAlerts delay (250 ms, now
    // in the refresh path since Sprint 2 enabled alerts) for loadedOnce.
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect(repo.calls, 2);
    expect(state.loadedOnce, isTrue);
    state.dispose();
    repo.pending.complete([]);
  });
}
