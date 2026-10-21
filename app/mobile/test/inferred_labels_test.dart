import 'package:assas_core/assas_core.dart';
import 'package:flutter_test/flutter_test.dart';

Device _device(Map<String, dynamic> extra) => Device.fromApi({
      'mac': 'aa:bb:cc:dd:ee:ff',
      'vendor': 'Samsung Electronics',
      'device_type': 'Phone',
      'model': 'SM-F711B',
      ...extra,
    });

void main() {
  group('typeInferred', () {
    test('hostname class source is inferred', () {
      expect(_device({'class_source': 'hostname'}).typeInferred, isTrue);
      expect(_device({'class_source': 'Hostname pattern'}).typeInferred, isTrue);
    });

    test('DHCP / mDNS / UPnP class sources are not inferred', () {
      for (final src in ['dhcp', 'mDNS advertisement', 'UPnP description']) {
        expect(_device({'class_source': src}).typeInferred, isFalse, reason: src);
      }
    });
  });

  group('modelInferred', () {
    test('hostname model code is inferred', () {
      expect(_device({'model_source': 'hostname model code'}).modelInferred, isTrue);
    });

    test('mDNS model is not inferred', () {
      expect(_device({'model_source': 'mDNS'}).modelInferred, isFalse);
    });
  });

  group('vendorInferred', () {
    test('vendor inferred from hostname', () {
      expect(_device({'vendor_source': 'inferred: hostname'}).vendorInferred, isTrue);
    });

    test('vendor inferred from a hostname-derived model', () {
      expect(
        _device({
          'vendor_source': 'inferred: model',
          'model_source': 'hostname model code',
        }).vendorInferred,
        isTrue,
      );
    });

    test('vendor inferred from an mDNS model is not marked', () {
      expect(
        _device({'vendor_source': 'inferred: model', 'model_source': 'mDNS'})
            .vendorInferred,
        isFalse,
      );
    });

    test('real OUI vendor (no source) is not inferred', () {
      expect(_device({}).vendorInferred, isFalse);
      expect(_device({'vendor_source': null}).vendorInferred, isFalse);
    });
  });

  test('JSON without the new fields still parses', () {
    final d = Device.fromApi({
      'mac': '11:22:33:44:55:66',
      'ip': '192.168.1.10',
      'hostname': 'Galaxy-S23-Ultra',
      'vendor': 'Samsung Electronics',
      'device_type': 'Phone',
      'status': 'online',
    });
    expect(d.vendorSource, isNull);
    expect(d.classSource, isNull);
    expect(d.modelSource, isNull);
    expect(d.typeInferred, isFalse);
    expect(d.modelInferred, isFalse);
    expect(d.vendorInferred, isFalse);
    expect(d.vendorLabel, 'Samsung Electronics');
    expect(d.typeLabel, 'Phone');
    expect(d.displayName, 'Galaxy-S23-Ultra');
  });
}
