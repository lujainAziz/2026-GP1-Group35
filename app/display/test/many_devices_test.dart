import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:assas_core/assas_core.dart';
import 'package:assas_display/screens/status_screen.dart';
import 'package:assas_display/display_ui.dart';
class ManyRepo extends DemoRepository {
  @override
  Future<List<Device>> getDevices() async => List.generate(100, (i) => Device(mac: '$i', presence: Presence.online, trusted: false));
}
void main() {
  testWidgets('100 devices fit the 7 inch screen', (tester) async {
    await tester.binding.setSurfaceSize(const Size(1024,600));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    for (final font in ['BricolageGrotesque', 'JetBrainsMono']) {
      final loader = FontLoader(font == 'BricolageGrotesque' ? 'Bricolage Grotesque' : 'JetBrains Mono');
      loader.addFont(rootBundle.load('assets/fonts/$font.ttf'));
      await loader.load();
    }
    await tester.pumpWidget(MaterialApp(theme: DisplayUi.theme, home: StatusScreen(repo: ManyRepo())));
    await tester.pump();
    await tester.pump(const Duration(seconds: 1));
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });
}
