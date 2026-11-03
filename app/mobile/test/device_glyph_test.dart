import 'package:assas_core/assas_core.dart';
import 'package:assas_design/widgets/ui_icons.dart';
import 'package:flutter_test/flutter_test.dart';

Device device(String type) => Device(
      mac: 'aa:bb:cc:dd:ee:ff',
      presence: Presence.online,
      trusted: true,
      deviceType: type,
    );

void main() {
  test('tablets get their own glyph and label', () {
    final ipad = device('Tablet (Apple)');
    expect(UiIcons.glyphName(ipad), 'tablet');
    expect(UiIcons.shortLabel(ipad), 'Tablet');
    expect(UiIcons.forDevice(ipad), UiIcons.tablet);
  });

  test('phones still map to the phone glyph', () {
    final phone = device('Mobile Phone');
    expect(UiIcons.glyphName(phone), 'phone');
    expect(UiIcons.shortLabel(phone), 'Phone');
    expect(UiIcons.forDevice(phone), UiIcons.phone);
  });

  test('computers are labelled Computer but keep the laptop glyph', () {
    final pc = device('Computer / Server');
    expect(UiIcons.glyphName(pc), 'laptop');
    expect(UiIcons.shortLabel(pc), 'Computer');
    expect(UiIcons.forDevice(pc), UiIcons.laptop);
  });
}
