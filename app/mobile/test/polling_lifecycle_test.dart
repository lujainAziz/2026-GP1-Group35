import 'dart:async';
import 'package:flutter_test/flutter_test.dart';
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/state/app_state.dart';

class SlowRepo extends DemoRepository {
  final pending = Completer<List<Device>>();
  @override
  Future<List<Device>> getDevices() => pending.future;
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
}
