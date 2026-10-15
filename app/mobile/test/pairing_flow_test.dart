import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/config/data_source.dart';
import 'package:assas_mobile/screens/pairing/pairing_screen.dart';
import 'package:assas_mobile/screens/shell/main_shell.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

class _PairingRepository extends DemoRepository {
  int requests = 0;
  String? phoneName;

  @override
  Future<String> pair(String code, {String? deviceName}) async {
    requests++;
    phoneName = deviceName;
    return 'test-session';
  }
}

void main() {
  testWidgets('cancel sends nothing; confirm sends name; success waits for Continue', (tester) async {
    await tester.binding.setSurfaceSize(const Size(390, 844));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    SharedPreferences.setMockInitialValues({});
    final repo = _PairingRepository();
    repository = repo;
    await tester.pumpWidget(MaterialApp(theme: MobileTheme.light, home: const PairingScreen()));
    await tester.enterText(find.byType(TextField), 'ABC123');
    await tester.ensureVisible(find.text('Pair'));
    await tester.tap(find.text('Pair'));
    await tester.pump(const Duration(milliseconds: 300));
    await tester.tap(find.text('Cancel'));
    await tester.pump(const Duration(milliseconds: 300));
    expect(repo.requests, 0);

    await tester.tap(find.text('Pair'));
    await tester.pump(const Duration(milliseconds: 300));
    await tester.enterText(find.byType(TextField).last, 'Maraheb phone');
    await tester.tap(find.text('Pair').last);
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 400));
    expect(repo.requests, 1);
    expect(repo.phoneName, 'Maraheb phone');
    expect(find.text('Paired successfully.'), findsOneWidget);
    await tester.pump(const Duration(seconds: 4));
    expect(find.text('Continue'), findsOneWidget);
    expect(find.byType(MainShell), findsNothing);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });

  test('demo rejects short codes with the agreed message', () async {
    await expectLater(DemoRepository().pair('123'), throwsA(
      isA<PairingException>().having((e) => e.message, 'message', PairingException.wrongCode),
    ));
  });
}
