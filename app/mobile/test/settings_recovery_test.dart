import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/screens/settings/settings_screen.dart';
import 'package:assas_mobile/services/session_store.dart';
import 'package:assas_mobile/state/app_state.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

class FailingRepo extends DemoRepository {
  int reads = 0;
  @override
  Future<void> unpair() async => throw const AssasApiException('offline', statusCode: 503);
  @override
  Future<ApplianceSettings> getSettings() async {
    reads++;
    if (reads == 1) throw const AssasApiException('offline', statusCode: 503);
    return super.getSettings();
  }
}

void main() {
  testWidgets('failed unpair retains token; settings recover automatically', (tester) async {
    SharedPreferences.setMockInitialValues({});
    await SessionStore.saveToken('keep-me');
    final repo = FailingRepo();
    final state = AppState(repo);
    expect(state.connection, ConnectionStatus.checking);
    await tester.binding.setSurfaceSize(const Size(600, 1000));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(MaterialApp(theme: MobileTheme.dark,
      home: Scaffold(body: SettingsScreen(state: state))));
    await tester.pump();
    expect(find.text('Could not load settings. Tap to retry.'), findsOneWidget);
    await tester.pump(const Duration(seconds: 6));
    await tester.pump();
    expect(repo.reads, greaterThan(1));
    expect(find.text('Could not load settings. Tap to retry.'), findsNothing);
    await tester.ensureVisible(find.text('Unpair this phone'));
    await tester.tap(find.text('Unpair this phone'));
    await tester.pump(const Duration(milliseconds: 300));
    await tester.tap(find.text('Unpair'));
    await tester.pump(const Duration(milliseconds: 300));
    expect(await SessionStore.getToken(), 'keep-me');
    expect(find.byType(SettingsScreen), findsOneWidget);
    expect(find.text('Could not unpair. Connect to ASSAS and try again.'), findsOneWidget);
    await tester.pump(const Duration(seconds: 2));
    await tester.pumpWidget(const SizedBox());
    state.dispose();
  });
  test('401 from any protected action ends session', () {
    final state = AppState(FailingRepo());
    expect(state.handleFailure(const AssasApiException('revoked', statusCode: 401)), isTrue);
    expect(state.sessionEnded, isTrue);
    state.dispose();
  });
}
