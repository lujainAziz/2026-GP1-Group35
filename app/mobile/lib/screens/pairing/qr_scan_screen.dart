import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../theme/assas_ui.dart';
import '../../widgets/ui_kit.dart';

/// Opens the camera and returns the first QR value it reads.
class QrScanScreen extends StatefulWidget {
  const QrScanScreen({super.key});

  @override
  State<QrScanScreen> createState() => _QrScanScreenState();
}

class _QrScanScreenState extends State<QrScanScreen> {
  bool _done = false;

  void _onDetect(BarcodeCapture capture) {
    if (_done) return;
    for (final barcode in capture.barcodes) {
      final value = barcode.rawValue;
      if (value != null && value.isNotEmpty) {
        _done = true;
        Navigator.of(context).pop(value);
        return;
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Ui.black,
      appBar: AppBar(
        backgroundColor: Ui.black,
        foregroundColor: Ui.white,
        automaticallyImplyLeading: false,
        title: Row(
          children: [
            const BackPill(),
            const SizedBox(width: 12),
            Text('SCAN QR CODE', style: UiText.kicker.copyWith(color: Ui.white)),
          ],
        ),
      ),
      body: Stack(
        children: [
          MobileScanner(onDetect: _onDetect),
          Center(
            child: Container(
              width: 240,
              height: 240,
              decoration: BoxDecoration(
                border: Border.all(color: Ui.acc, width: 2),
                borderRadius: BorderRadius.circular(UiRadius.button),
                boxShadow: UiShadow.glow(Ui.glow, 22),
              ),
            ),
          ),
          Positioned(
            left: 24,
            right: 24,
            bottom: 48,
            child: Text(
              'Point the camera at the QR code on your ASSAS screen.',
              textAlign: TextAlign.center,
              style: UiText.pairBody.copyWith(color: Ui.white),
            ),
          ),
        ],
      ),
    );
  }
}
