import 'dart:async';

import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../config/data_source.dart';

/// Rotating pairing code: QR + typed code + countdown.
/// The phone scans it (or types it) on its Pairing screen.
class PairingQrPanel extends StatefulWidget {
  const PairingQrPanel({super.key});

  @override
  State<PairingQrPanel> createState() => _PairingQrPanelState();
}

class _PairingQrPanelState extends State<PairingQrPanel> {
  PairingCode? _code;
  bool _error = false;
  bool _loading = false;
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
      final c = await repository.getCurrentPairingCode();
      if (mounted) {
        setState(() {
          _code = c;
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
    return GlassCard(
      blur: false, // cheaper on the Raspberry Pi
      opacity: 0.7,
      radius: 24,
      padding: const EdgeInsets.all(20),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(
            'Pair your phone',
            style: AssasText.statValue,
          ),
          const SizedBox(height: 4),
          Text(
            'Scan with the Assas app',
            style: TextStyle(fontSize: 15, color: AssasColors.muted),
          ),
          const SizedBox(height: 14),
          Expanded(
            child: Center(
              child: _error || c == null
                  ? _placeholder()
                  : LayoutBuilder(
                      builder: (context, box) {
                        final size = box.biggest.shortestSide;
                        return QrImageView(
                          data: c.qrPayload,
                          version: QrVersions.auto,
                          size: size,
                          eyeStyle: QrEyeStyle(
                            eyeShape: QrEyeShape.square,
                            color: AssasColors.primary,
                          ),
                          dataModuleStyle: QrDataModuleStyle(
                            dataModuleShape: QrDataModuleShape.square,
                            color: AssasColors.ink,
                          ),
                        );
                      },
                    ),
            ),
          ),
          const SizedBox(height: 12),
          Text(
            'or enter the code',
            style: TextStyle(fontSize: 14, color: AssasColors.muted),
          ),
          const SizedBox(height: 4),
          Text(
            c == null || _error ? '— — —' : c.pretty,
            style: TextStyle(
              fontSize: 34,
              fontWeight: FontWeight.w800,
              letterSpacing: 4,
              color: AssasColors.primary,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            _error
                ? 'Pairing code unavailable'
                : c == null
                    ? 'Loading...'
                    : 'New code in ${c.secondsLeft(DateTime.now())} s',
            style: TextStyle(
              fontSize: 14,
              color: _error ? AssasColors.danger : AssasColors.muted,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }

  Widget _placeholder() => Container(
        width: 160,
        height: 160,
        decoration: BoxDecoration(
          color: AssasColors.tintPurple,
          borderRadius: BorderRadius.circular(16),
        ),
        child: Icon(
          _error ? Icons.error_outline : Icons.qr_code_2_rounded,
          size: 64,
          color: _error ? AssasColors.danger : AssasColors.primary,
        ),
      );
}
