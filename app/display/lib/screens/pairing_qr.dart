import 'dart:async';

import 'package:assas_core/assas_core.dart';
import '../display_ui.dart';
import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../config/data_source.dart';

/// Rotating pairing code: QR + typed code + countdown.
/// The phone scans it (or types it) on its Pairing screen.
class PairingQrPanel extends StatefulWidget {
  const PairingQrPanel({super.key, this.repo});
  final AssasRepository? repo;

  @override
  State<PairingQrPanel> createState() => _PairingQrPanelState();
}

class _PairingQrPanelState extends State<PairingQrPanel> {
  PairingCode? _code;
  bool _error = false;
  bool _loading = false;
  int _cycleSeconds = 60;
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    _load();
    // Tick every second for the countdown; fetch a new code when it expires.
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) {
      final c = _code;
      if (c == null || c.secondsLeft(DateTime.now()) == 0) {
        _load();
      } else {
        setState(() {});
      }
    });
  }

  @override
  void dispose() {
    _ticker?.cancel();
    super.dispose();
  }

  Future<void> _load() async {
    if (_loading) return;
    _loading = true;
    try {
      final c = await (widget.repo ?? repository).getCurrentPairingCode();
      if (mounted) {
        setState(() {
          _code = c;
          _cycleSeconds = c.secondsLeft(DateTime.now()).clamp(1, 86400);
          _error = false;
        });
      }
    } catch (_) {
      if (mounted) setState(() => _error = true);
    } finally {
      _loading = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = _code;
    return DisplayFrame(child: Container(
      decoration: DisplayUi.card(),
      padding: const EdgeInsets.all(20),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Row(mainAxisAlignment: MainAxisAlignment.center, children: [
            Container(width: 5, height: 5, decoration: BoxDecoration(
              color: _error ? DisplayUi.red : DisplayUi.green, shape: BoxShape.circle)),
            const SizedBox(width: 7),
            Text('CONNECT YOUR PHONE', style: DisplayUi.mono(9, color: DisplayUi.accent)),
          ]),
          const SizedBox(height: 10),
          Text(
            'Pair your phone',
            style: DisplayUi.sans(26),
          ),
          const SizedBox(height: 4),
          Text(
            'Scan with the ASSAS app',
            style: TextStyle(fontSize: 15, color: DisplayUi.mute),
          ),
          const SizedBox(height: 14),
          Expanded(
            child: Center(
              child: _error || c == null
                  ? _placeholder()
                  : LayoutBuilder(
                      builder: (context, box) {
                        final size = box.biggest.shortestSide;
                        return Container(
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(18)),
                          child: QrImageView(
                          data: c.qrPayload,
                          version: QrVersions.auto,
                          size: size - 20,
                          backgroundColor: Colors.white,
                          eyeStyle: QrEyeStyle(
                            eyeShape: QrEyeShape.square,
                            color: const Color(0xFF170F22),
                          ),
                          dataModuleStyle: QrDataModuleStyle(
                            dataModuleShape: QrDataModuleShape.square,
                            color: const Color(0xFF170F22),
                          ),
                        ));
                      },
                    ),
            ),
          ),
          const SizedBox(height: 12),
          Text(
            'or enter the code',
            style: TextStyle(fontSize: 14, color: DisplayUi.mute),
          ),
          const SizedBox(height: 6),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 9),
            decoration: DisplayUi.card(color: DisplayUi.raised, radius: 18),
            child: Text(
            c == null || _error ? '— — —' : c.pretty,
            style: TextStyle(
              fontFamily: 'JetBrains Mono',
              fontSize: 32,
              fontWeight: FontWeight.w800,
              letterSpacing: 4,
              color: DisplayUi.accent,
            ),
          )),
          const SizedBox(height: 6),
          Row(mainAxisAlignment: MainAxisAlignment.center, children: [
          if (c != null && !_error) ...[
            SizedBox.square(dimension: 22, child: CircularProgressIndicator(
              value: (c.secondsLeft(DateTime.now()) / _cycleSeconds).clamp(0.0, 1.0),
              strokeWidth: 2,
              backgroundColor: DisplayUi.line,
              color: c.secondsLeft(DateTime.now()) <= 10 ? DisplayUi.amber : DisplayUi.accent,
            )),
            const SizedBox(width: 9),
          ],
          Text(
            _error
                ? 'Pairing code unavailable'
                : c == null
                    ? 'Loading...'
                    : 'New code in ${c.secondsLeft(DateTime.now())} s',
            style: TextStyle(
              fontSize: 14,
              color: _error ? DisplayUi.red : DisplayUi.mute,
              fontWeight: FontWeight.w600,
            ),
          ),
          ]),
        ],
      ),
    ));
  }

  Widget _placeholder() => Container(
        width: 160,
        height: 160,
        decoration: BoxDecoration(
          color: DisplayUi.raised,
          borderRadius: BorderRadius.circular(16),
        ),
        child: Icon(
          _error ? Icons.error_outline : Icons.qr_code_2_rounded,
          size: 64,
          color: _error ? DisplayUi.red : DisplayUi.accent,
        ),
      );
}
