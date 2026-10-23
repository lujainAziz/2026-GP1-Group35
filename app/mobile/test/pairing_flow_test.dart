import 'package:assas_core/assas_core.dart';
import 'package:assas_mobile/config/data_source.dart';
import 'package:assas_mobile/screens/pairing/pairing_screen.dart';
import 'package:assas_mobile/screens/shell/main_shell.dart';
import 'package:assas_mobile/theme/assas_ui.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

class _PairingRepository extends DemoRepository {
  int requests = 0; // pair(code), the old one-step flow
  int verifyCalls = 0;
  int ticketCalls = 0;
  String? phoneName;

  bool wrongCode = false;
  bool oldAppliance = false; // verify returns null (no /pair/verify)
  bool ticketExpired = false;

  /// `repository` can be set only once per file, so tests share one fake.
  void reset() {
    requests = verifyCalls = ticketCalls = 0;
    phoneName = null;
    wrongCode = oldAppliance = ticketExpired = false;
  }

  @override
  Future<String> pair(String code, {String? deviceName}) async {
    requests++;
    phoneName = deviceName;
    return 'test-session';
  }

  @override
  Future<String?> verifyPairingCode(String code) async {
    verifyCalls++;
    if (wrongCode) throw const PairingException(PairingException.wrongCode);
    return oldAppliance ? null : 'test-ticket';
  }

  @override
  Future<String> pairWithTicket(String ticket, {String? deviceName}) async {
    ticketCalls++;
    phoneName = deviceName;
    if (ticketExpired) throw const PairingException(PairingException.ticketExpired);
    return 'test-session';
  }
}

void main() {
  final repo = _PairingRepository();

  Future<void> openScreen(WidgetTester tester) async {
    await tester.binding.setSurfaceSize(const Size(390, 844));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    SharedPreferences.setMockInitialValues({});
    await tester.pumpWidget(MaterialApp(theme: MobileTheme.light, home: const PairingScreen()));
    await tester.enterText(find.byType(TextField), 'ABC123');
  }

  Future<void> tapPair(WidgetTester tester) async {
    await tester.ensureVisible(find.text('Pair'));
    await tester.tap(find.text('Pair'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 300));
  }

  Future<void> confirmName(WidgetTester tester, String name) async {
    await tester.enterText(find.byType(TextField).last, name);
    await tester.tap(find.text('Pair').last);
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 400));
  }

  setUpAll(() => repository = repo);
  setUp(repo.reset);

  testWidgets('cancel sends nothing more; confirm sends name; success waits for Continue', (tester) async {
    await openScreen(tester);
    await tapPair(tester);
    await tester.tap(find.text('Cancel'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 300));
    expect(find.text('Pair this phone with ASSAS?'), findsNothing);
    expect(repo.verifyCalls, 1);
    expect(repo.ticketCalls, 0);
    expect(repo.requests, 0);

    await tapPair(tester);
    await confirmName(tester, 'Maraheb phone');
    expect(repo.verifyCalls, 2);
    expect(repo.ticketCalls, 1);
    expect(repo.requests, 0);
    expect(repo.phoneName, 'Maraheb phone');
    expect(find.text('Paired successfully.'), findsOneWidget);
    await tester.pump(const Duration(seconds: 4));
    expect(find.text('Continue'), findsOneWidget);
    expect(find.byType(MainShell), findsNothing);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('wrong code: rejected page, no name dialog, nothing paired', (tester) async {
    repo.wrongCode = true;
    await openScreen(tester);
    await tapPair(tester);
    expect(find.text('Pair this phone with ASSAS?'), findsNothing);
    expect(find.text('Pairing failed.'), findsOneWidget);
    expect(find.text(PairingException.wrongCode), findsOneWidget);
    expect(repo.verifyCalls, 1);
    expect(repo.ticketCalls, 0);
    expect(repo.requests, 0);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('expired ticket: rejected page with the ticketExpired message', (tester) async {
    repo.ticketExpired = true;
    await openScreen(tester);
    await tapPair(tester);
    await confirmName(tester, 'Maraheb phone');
    expect(repo.ticketCalls, 1);
    expect(find.text('Pairing failed.'), findsOneWidget);
    expect(find.text(PairingException.ticketExpired), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('older appliance (verify returns null): pair(code) after confirm', (tester) async {
    repo.oldAppliance = true;
    await openScreen(tester);
    await tapPair(tester);
    expect(find.text('Pair this phone with ASSAS?'), findsOneWidget);
    await confirmName(tester, 'Maraheb phone');
    expect(repo.verifyCalls, 1);
    expect(repo.ticketCalls, 0);
    expect(repo.requests, 1);
    expect(repo.phoneName, 'Maraheb phone');
    expect(find.text('Paired successfully.'), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });

  test('demo rejects short codes with the agreed message', () async {
    await expectLater(DemoRepository().pair('123'), throwsA(
      isA<PairingException>().having((e) => e.message, 'message', PairingException.wrongCode),
    ));
  });
}
