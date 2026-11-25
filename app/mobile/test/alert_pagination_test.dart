// "Load older" must surface older alerts instead of silently stopping at the
// cap, while the open-count stays the full DB aggregate (not the loaded length).
import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:flutter_test/flutter_test.dart';

SecurityAlert _mk(int i) => SecurityAlert(
      id: '$i',
      kind: AlertKind.threat,
      title: 'ET X $i',
      deviceName: 'Unknown device',
      time: DateTime(2026, 11, 2).add(Duration(seconds: i)),
      severity: Severity.medium,
      state: AlertState.newAlert,
    );

class _BulkRepo extends DemoRepository {
  _BulkRepo(this.n);
  final int n;
  late final List<SecurityAlert> _all =
      List.generate(n, _mk)..sort((a, b) => b.time.compareTo(a.time));

  @override
  Future<List<SecurityAlert>?> getAlerts({int? limit}) async =>
      limit != null && _all.length > limit ? _all.sublist(0, limit) : _all;

  @override
  Future<int?> getOpenAlertCount() async => n; // all New -> all open, full aggregate
}

void main() {
  test('load-older raises the cap; open-count stays the full DB aggregate', () async {
    final s = AppState(_BulkRepo(2500));
    addTearDown(s.dispose);

    await s.refresh();
    // First load is capped to the default 2000, and the screen knows there is more.
    expect(s.alerts!.length, 2000);
    expect(s.alertsHaveMore, isTrue);
    // The hero count is the true total, independent of the loaded page.
    expect(s.unresolvedAlertCount, 2500);

    await s.loadMoreAlerts();
    expect(s.alerts!.length, 2500);   // older alerts now loaded
    expect(s.alertsHaveMore, isFalse); // nothing left beyond the cap
    expect(s.unresolvedAlertCount, 2500);
  });
}
