import 'package:assas_mobile/widgets/assas_nav_bar.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('all navigation labels fit at Large and Largest widths', (tester) async {
    for (final zoom in [1.12, 1.2]) {
      // Narrow phone, less page margins, in the design's zoomed coordinates.
      final width = 320 / zoom - 32;
      for (var tab = 0; tab < 4; tab++) {
        await tester.pumpWidget(MaterialApp(
          home: MediaQuery(
            data: const MediaQueryData(textScaler: TextScaler.linear(1.3)),
            child: Scaffold(
              body: Center(
                child: SizedBox(
                  width: width,
                  child: AssasNavBar(index: tab, unread: 12, onSelect: (_) {}),
                ),
              ),
            ),
          ),
        ));
        await tester.pump(const Duration(milliseconds: 400));
        expect(tester.takeException(), isNull, reason: 'zoom=$zoom, tab=$tab');
      }
    }
  });
}
