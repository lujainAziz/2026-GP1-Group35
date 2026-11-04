import 'dart:async';
import 'dart:io';
import 'dart:ui' as ui;

import 'package:assas_core/assas_core.dart';
import 'package:assas_display/display_ui.dart';
import 'package:assas_display/screens/status_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

class _PhonesRepository extends DemoRepository {
  int checks = 0;
  @override
  Future<List<PairedPhone>?> getPairedPhones() async => [
    const PairedPhone(id: 1, deviceName: 'Existing phone'),
    if (++checks >= 5) const PairedPhone(id: 2, deviceName: "Maraheb's iPhone"),
  ];
}

class _SlowRepository extends DemoRepository {
  final pending = Completer<List<Device>>();
  int deviceRequests = 0;
  int phoneRequests = 0;
  @override
  Future<List<Device>> getDevices() {
    deviceRequests++;
    return deviceRequests == 1 ? pending.future : Future.value([]);
  }
  @override
  Future<List<PairedPhone>?> getPairedPhones() async {
    phoneRequests++;
    return [];
  }
}

void main() {
  testWidgets('slow refresh does not overlap and recovers after failure', (tester) async {
    await tester.binding.setSurfaceSize(const Size(1024, 600));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    for (final font in ['BricolageGrotesque', 'JetBrainsMono']) {
      final loader = FontLoader(font == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
      loader.addFont(rootBundle.load('assets/fonts/$font.ttf'));
      await loader.load();
    }
    final repo = _SlowRepository();
    await tester.pumpWidget(MaterialApp(theme: DisplayUi.theme, home: StatusScreen(repo: repo)));
    await tester.pump();
    for (var i = 0; i < 16; i++) { await tester.pump(const Duration(seconds: 1)); }
    expect(repo.deviceRequests, 1);
    expect(repo.phoneRequests, 1);
    repo.pending.completeError(Exception('temporary failure'));
    await tester.pump();
    for (var i = 0; i < 5; i++) { await tester.pump(const Duration(seconds: 1)); }
    expect(repo.deviceRequests, 2);
    expect(repo.phoneRequests, 2);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 3));
  });

  testWidgets('7 inch layout, pairing QR and new phone notice', (tester) async {
    await tester.binding.setSurfaceSize(const Size(1024, 600));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    for (final font in ['BricolageGrotesque', 'JetBrainsMono']) {
      final loader = FontLoader(font == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
      loader.addFont(rootBundle.load('assets/fonts/$font.ttf'));
      await loader.load();
    }
    final icons = FontLoader('MaterialIcons');
    icons.addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'));
    await icons.load();
    final key = GlobalKey();
    await tester.pumpWidget(RepaintBoundary(key: key, child: MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: DisplayUi.theme,
      home: DisplayBackground(child: StatusScreen(repo: _PhonesRepository())),
    )));
    await tester.runAsync(() => precacheImage(
      const AssetImage('assets/images/logo_eye.png'),
      tester.element(find.byType(StatusScreen)),
    ));
    await tester.runAsync(() async {
      final context = tester.element(find.byType(StatusScreen));
      for (final name in ['01_upper_eyelid', '02_lower_eyelid', '03_iris_circuit', '04_left_accent', '05_right_accent', '06_center_pupil']) {
        await precacheImage(AssetImage('packages/assas_design/assets/images/eye_$name.png'), context);
      }
    });
    for (var i = 0; i < 6; i++) { await tester.pump(const Duration(milliseconds: 250)); }
    expect(find.text('Pair your phone'), findsOneWidget);
    expect(find.text('Soon'), findsOneWidget);
    expect(find.text('SOON · SPRINT 4'), findsOneWidget);
    expect(find.text('SOON · SPRINT 2'), findsOneWidget);
    expect(find.text('High'), findsNothing);
    expect(find.text('ONLINE'), findsWidgets);
    expect(find.textContaining('New phone paired:'), findsNothing);
    expect(tester.takeException(), isNull);
    await tester.runAsync(() async {
      final boundary = key.currentContext!.findRenderObject()! as RenderRepaintBoundary;
      final image = await boundary.toImage(pixelRatio: 1);
      final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
      await File('../../../../assas-display-preview.png').writeAsBytes(bytes!.buffer.asUint8List());
      image.dispose();
    });
    for (var i = 0; i < 25; i++) { await tester.pump(const Duration(seconds: 1)); }
    expect(find.text("New phone paired: Maraheb's iPhone"), findsOneWidget);
    for (var i = 0; i < 12; i++) { await tester.pump(const Duration(seconds: 1)); }
    expect(find.textContaining('New phone paired:'), findsNothing);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 3));
  });
}
