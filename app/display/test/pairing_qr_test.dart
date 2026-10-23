import 'package:assas_core/assas_core.dart';
import 'package:assas_display/display_ui.dart';
import 'package:assas_display/screens/pairing_qr.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

class _CodeRepository extends DemoRepository {
  PairingCode code = PairingCode(
    code: 'AAA222',
    expiresAt: DateTime.now().add(const Duration(seconds: 60)),
  );
  int requests = 0;
  @override
  Future<PairingCode> getCurrentPairingCode() async {
    requests++;
    return code;
  }
}

Future<void> _open(WidgetTester tester, _CodeRepository repo) async {
  await tester.binding.setSurfaceSize(const Size(1024, 600));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(MaterialApp(
    theme: DisplayUi.theme,
    home: Scaffold(body: PairingQrPanel(repo: repo)),
  ));
  await tester.pump();
}

double _ring(WidgetTester tester) =>
    tester.widget<CircularProgressIndicator>(find.byType(CircularProgressIndicator)).value!;

void main() {
  testWidgets('a code dropped by the backend is replaced within 3 seconds', (tester) async {
    final repo = _CodeRepository();
    await _open(tester, repo);
    expect(find.text('AAA 222'), findsOneWidget);

    // The backend consumed the code; the old one still had ~60 s left.
    repo.code = PairingCode(
      code: 'BBB333',
      expiresAt: DateTime.now().add(const Duration(seconds: 60)),
    );
    for (var i = 0; i < 3; i++) { await tester.pump(const Duration(seconds: 1)); }
    expect(find.text('BBB 333'), findsOneWidget);
    expect(find.text('AAA 222'), findsNothing);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('the same code again does not reset the countdown ring', (tester) async {
    final repo = _CodeRepository();
    await _open(tester, repo);
    expect(_ring(tester), 1.0);

    // DateTime.now() does not move in widget tests: let one real second pass.
    await tester.runAsync(() => Future.delayed(const Duration(milliseconds: 1100)));
    final before = repo.requests;
    for (var i = 0; i < 3; i++) { await tester.pump(const Duration(seconds: 1)); }
    expect(repo.requests, greaterThan(before));
    expect(find.text('AAA 222'), findsOneWidget);
    expect(_ring(tester), lessThan(1.0));
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });
}
