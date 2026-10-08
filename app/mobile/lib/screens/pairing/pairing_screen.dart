import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../config/data_source.dart';
import '../../services/session_store.dart';
import '../../widgets/assas_logo.dart';
import '../../widgets/common.dart';
import '../shell/main_shell.dart';
import 'qr_scan_screen.dart';

/// First-time pairing (PBI-08): scan the QR code or type the code shown on
/// the Assas 7-inch screen. The code changes every minute.
class PairingScreen extends StatefulWidget {
  const PairingScreen({super.key});

  @override
  State<PairingScreen> createState() => _PairingScreenState();
}

class _PairingScreenState extends State<PairingScreen> {
  final _codeController = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _codeController.dispose();
    super.dispose();
  }

  Future<void> _pair(String rawCode) async {
    final code = PairingCode.parseQr(rawCode);
    if (code.isEmpty) {
      setState(() => _error = 'Enter the pairing code shown on your Assas device.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final token = await repository.pair(code);
      await SessionStore.saveToken(token);
      repository.setAuthToken(token);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Paired successfully with your Assas device.')),
      );
      _openApp();
    } on PairingException catch (e) {
      setState(() => _error = e.message);
    } catch (_) {
      setState(() => _error = 'Could not reach your Assas device. Make sure you are on the same network.');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _scan() async {
    final raw = await Navigator.of(context).push<String>(
      MaterialPageRoute(builder: (_) => const QrScanScreen()),
    );
    if (raw != null && mounted) {
      _codeController.text = PairingCode.parseQr(raw);
      await _pair(raw);
    }
  }

  void _openApp() {
    Navigator.of(context).pushReplacement(
      MaterialPageRoute(builder: (_) => const MainShell()),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SingleChildScrollView(
        child: Column(
          children: [
            _header(),
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 20, 20, 32),
              child: Column(
                children: [
                  AppCard(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      children: [
                        Container(
                          width: 120,
                          height: 120,
                          decoration: BoxDecoration(
                            color: AssasColors.tintPurple,
                            borderRadius: BorderRadius.circular(16),
                          ),
                          child: Icon(
                            Icons.qr_code_2_rounded,
                            size: 84,
                            color: AssasColors.primary,
                          ),
                        ),
                        const SizedBox(height: 16),
                        FilledButton.icon(
                          onPressed: _busy ? null : _scan,
                          icon: const Icon(Icons.qr_code_scanner_rounded),
                          label: const Text('Scan QR code'),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 22),
                  Row(
                    children: [
                      Expanded(child: Divider()),
                      Padding(
                        padding: EdgeInsets.symmetric(horizontal: 10),
                        child: Text(
                          'or enter the code',
                          style: AssasText.caption,
                        ),
                      ),
                      Expanded(child: Divider()),
                    ],
                  ),
                  const SizedBox(height: 16),
                  Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: _codeController,
                          enabled: !_busy,
                          textCapitalization: TextCapitalization.characters,
                          textInputAction: TextInputAction.done,
                          onSubmitted: _busy ? null : _pair,
                          decoration: const InputDecoration(hintText: 'Enter pairing code'),
                        ),
                      ),
                      const SizedBox(width: 10),
                      SizedBox(
                        width: 90,
                        child: OutlinedButton(
                          onPressed: _busy ? null : () => _pair(_codeController.text),
                          child: _busy
                              ? const SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(strokeWidth: 2),
                                )
                              : const Text('Pair'),
                        ),
                      ),
                    ],
                  ),
                  if (_error != null) ...[
                    const SizedBox(height: 12),
                    Row(
                      children: [
                        Icon(Icons.error_outline, color: AssasColors.danger, size: 18),
                        const SizedBox(width: 6),
                        Expanded(
                          child: Text(
                            _error!,
                            style: TextStyle(
                              color: AssasColors.danger,
                              fontWeight: FontWeight.w600,
                              fontSize: 13,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _header() {
    return ClipPath(
      clipper: const WaveBottomClipper(depth: 24),
      child: Container(
      width: double.infinity,
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            AssasColors.header.withValues(alpha: 0.95),
            AssasColors.headerDark.withValues(alpha: 0.95),
          ],
        ),
      ),
      child: SafeArea(
        bottom: false,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(24, 8, 24, 48),
          child: Column(
            children: [
              // ---------- DEMO ONLY: skip pairing (controlled by kShowPairingSkip) ----------
              Align(
                alignment: Alignment.centerRight,
                child: kShowPairingSkip
                    ? TextButton(
                        onPressed: _busy ? null : _openApp,
                        child: const Text(
                          'Skip',
                          style: TextStyle(color: Colors.white, fontWeight: FontWeight.w700),
                        ),
                      )
                    : const SizedBox(height: 40),
              ),
              // -----------------------------------------------------------------------------
              const AssasLogo(size: 84),
              const SizedBox(height: 8),
              const Text(
                'A S S A S',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 12,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 2,
                ),
              ),
              const SizedBox(height: 14),
              const Text(
                'Pair with your Assas device',
                textAlign: TextAlign.center,
                style: AssasText.headerTitleSmall,
              ),
              const SizedBox(height: 6),
              Text(
                'Scan the QR code shown on your Assas screen, or enter the code displayed under it.',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Colors.white.withValues(alpha: 0.85),
                  fontSize: 13.5,
                ),
              ),
            ],
          ),
        ),
      ),
    ),
    );
  }
}
