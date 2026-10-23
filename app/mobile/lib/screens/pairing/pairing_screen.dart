import 'dart:math' as math;

import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../config/data_source.dart';
import '../../services/session_store.dart';
import '../../theme/assas_ui.dart';
import '../../widgets/assas_eye.dart';
import '../../widgets/pair_confirm_dialog.dart';
import '../../widgets/pairing_result.dart';
import '../../widgets/ui_icons.dart';
import '../../widgets/ui_kit.dart';
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
  void initState() {
    super.initState();
    _codeController.addListener(() => setState(() {}));
  }

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
      _error = null;
      _busy = true;
    });
    try {
      // Check the code first, so a wrong code never reaches the name dialog.
      // null = older appliance without /pair/verify: pair with the code below.
      final ticket = await repository.verifyPairingCode(code);
      if (!mounted) return;
      setState(() => _busy = false);
      // Confirm; Cancel sends nothing more (an unused ticket just expires).
      final name = await showPairConfirm(context);
      if (name == null || !mounted) return;
      setState(() => _busy = true);
      final token = ticket == null
          ? await repository.pair(code, deviceName: name)
          : await repository.pairWithTicket(ticket, deviceName: name);
      await _finishPairing(token);
    } on PairingException catch (e) {
      _showRejected(e.message);
    } catch (_) {
      _showRejected("We couldn't reach ASSAS. Make sure your phone is on the same network.");
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// Save the token, then the accepted page, then the app.
  Future<void> _finishPairing(String token) async {
    await SessionStore.saveToken(token, applianceId: repository is ApiRepository
        ? (repository as ApiRepository).applianceId : null);
    repository.setAuthToken(token);
    if (!mounted) return;
    Navigator.of(context).pushReplacement(
      MaterialPageRoute(
        builder: (ctx) => PairingResultScreen.accepted(
          onContinue: () => Navigator.of(ctx).pushReplacement(
            MaterialPageRoute(builder: (_) => const MainShell()),
          ),
        ),
      ),
    );
  }

  /// Rejected page with the reason; Try again comes back here.
  void _showRejected(String reason) {
    if (!mounted) return;
    Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => PairingResultScreen.rejected(reason: reason)),
    );
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
    final mq = MediaQuery.paddingOf(context);
    return Scaffold(
      body: CustomScrollView(
        slivers: [
          SliverFillRemaining(
            hasScrollBody: false,
            child: Padding(
                padding: EdgeInsets.fromLTRB(UiSpace.pagePair, mq.top, UiSpace.pagePair, mq.bottom + 24),
                child: FadeSlideIn(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Padding(
                        padding: const EdgeInsets.only(top: 8),
                        child: Row(
                          children: [
                            Text('ASSAS', style: UiText.wordmark),
                            const Spacer(),
                            // ---------- DEMO ONLY: skip pairing (controlled by kShowPairingSkip) ----------
                            if (kShowPairingSkip)
                              Pressable(
                                onTap: _busy ? null : _openApp,
                                child: Text('SKIP →', style: UiText.link.copyWith(color: Ui.acc)),
                              ),
                            // -----------------------------------------------------------------------------
                          ],
                        ),
                      ),
                      const SizedBox(height: 36),
                      const Center(child: _EyeBlock()),
                      const SizedBox(height: 34),
                      Text('Let ASSAS\nwatch your\nnetwork.', style: UiText.pairTitle),
                      const SizedBox(height: 14),
                      Text(
                        'Scan the QR code shown on your ASSAS screen, or enter the code displayed under it.',
                        style: UiText.pairBody.copyWith(color: Ui.mute),
                      ),
                      const Spacer(),
                      const SizedBox(height: 24),
                      PillButton(
                        label: 'Scan QR code',
                        busyLabel: 'Looking for ASSAS…',
                        busy: _busy,
                        icon: UiIcon(UiIcons.qr, size: 20, stroke: 1.8, color: Ui.accInk),
                        onTap: _scan,
                      ),
                      const SizedBox(height: 10),
                      Row(
                        children: [
                          Expanded(child: _codeField()),
                          const SizedBox(width: 8),
                          SizedBox(
                            width: 84,
                            child: PillButton(
                              label: 'Pair',
                              filled: false,
                              opacity: _codeController.text.length == 6 ? 1 : .4,
                              onTap: _busy ? null : () => _pair(_codeController.text),
                            ),
                          ),
                        ],
                      ),
                      if (_error != null)
                        Container(
                          width: double.infinity,
                          margin: const EdgeInsets.only(top: 9),
                          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                          decoration: BoxDecoration(
                            color: Ui.mix(Ui.crit, .08, Ui.surf),
                            borderRadius: BorderRadius.circular(15),
                            border: Border.all(color: Ui.mix(Ui.crit, .26, Ui.line)),
                          ),
                          child: Text(_error!, style: UiText.error.copyWith(color: Ui.crit)),
                        ),
                    ],
                  ),
                ),
              ),
          ),
        ],
      ),
    );
  }

  Widget _codeField() {
    return SizedBox(
      height: 56,
      child: TextField(
        controller: _codeController,
        enabled: !_busy,
        textCapitalization: TextCapitalization.characters,
        textInputAction: TextInputAction.done,
        onSubmitted: _busy ? null : _pair,
        inputFormatters: [
          FilteringTextInputFormatter.allow(RegExp('[A-Za-z0-9]')),
          LengthLimitingTextInputFormatter(6),
          _UpperCase(),
        ],
        style: UiText.codeInput,
        cursorColor: Ui.acc,
        textAlignVertical: TextAlignVertical.center,
        decoration: InputDecoration(
          hintText: 'PAIRING CODE',
          hintStyle: UiText.codeInput.copyWith(color: Ui.mute),
          contentPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 0),
        ),
      ),
    );
  }
}

class _UpperCase extends TextInputFormatter {
  @override
  TextEditingValue formatEditUpdate(TextEditingValue oldValue, TextEditingValue newValue) =>
      newValue.copyWith(text: newValue.text.toUpperCase());
}

/// 260px block: dashed ring (18s), inner ring with accent arc (3s, reverse),
/// rotating glow (3.2s), and the eye.
class _EyeBlock extends StatelessWidget {
  const _EyeBlock();

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: 260,
      height: 260,
      child: Stack(
        alignment: Alignment.center,
        children: [
          Positioned.fill(
            child: IgnorePointer(
              child: UiClock(builder: (context, t, _) => CustomPaint(painter: _RingsPainter(t))),
            ),
          ),
          const AssasEye(size: 208),
        ],
      ),
    );
  }
}

class _RingsPainter extends CustomPainter {
  _RingsPainter(this.t);

  final double t;

  @override
  void paint(Canvas canvas, Size size) {
    final c = size.center(Offset.zero);
    final r = size.width / 2;

    // Rotating glow: conic from glow to transparent at 20%.
    final glowRect = Rect.fromCircle(center: c, radius: r);
    canvas.drawCircle(
      c,
      r,
      Paint()
        ..shader = SweepGradient(
          colors: [Ui.glow, Ui.fade(Ui.glow, 0), Ui.fade(Ui.glow, 0)],
          stops: const [0, .2, 1],
          transform: GradientRotation(-math.pi / 2 + loop(t, 3.2) * 2 * math.pi),
        ).createShader(glowRect),
    );

    // Outer dashed ring.
    paintDashedCircle(canvas, c, r - .75, Ui.fade(Ui.acc, .5),
        width: 1.5, turns: loop(t, 18), pattern: const [5, 4]);

    // Inner ring (inset 26) with an accent arc on top, turning backwards.
    final ir = r - 26 - .5;
    paintCircle(canvas, c, ir, Ui.line);
    canvas.save();
    canvas.translate(c.dx, c.dy);
    canvas.rotate(-loop(t, 3) * 2 * math.pi);
    canvas.drawArc(
      Rect.fromCircle(center: Offset.zero, radius: ir),
      -3 * math.pi / 4,
      math.pi / 2,
      false,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1
        ..color = Ui.acc,
    );
    canvas.restore();
  }

  @override
  bool shouldRepaint(_RingsPainter old) => old.t != t;
}
