import 'package:flutter/material.dart';

import '../theme/assas_ui.dart';
import 'assas_eye.dart';
import 'ui_kit.dart';

/// Full-screen pairing result.
/// - Accepted: the eye with a check; Continue goes to the dashboard
///   (no automatic move).
/// - Rejected: the reason, and a Try again button that closes this screen.
class PairingResultScreen extends StatefulWidget {
  const PairingResultScreen.accepted({super.key, required this.onContinue})
      : accepted = true,
        reason = null;

  const PairingResultScreen.rejected({super.key, required this.reason})
      : accepted = false,
        onContinue = null;

  final bool accepted;
  final String? reason;
  final VoidCallback? onContinue;

  @override
  State<PairingResultScreen> createState() => _PairingResultScreenState();
}

class _PairingResultScreenState extends State<PairingResultScreen> {
  bool _left = false;

  void _continue() {
    if (_left || !mounted) return;
    _left = true;
    widget.onContinue?.call();
  }

  @override
  Widget build(BuildContext context) {
    final ok = widget.accepted;
    final color = ok ? Ui.low : Ui.crit;
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: UiSpace.pagePair),
          child: FadeSlideIn(
            child: Column(
              children: [
                const Spacer(),
                SizedBox(
                  width: 220,
                  height: 160,
                  child: Stack(
                    alignment: Alignment.center,
                    clipBehavior: Clip.none,
                    children: [
                      Opacity(opacity: ok ? 1 : .35, child: const AssasEye(size: 190)),
                      Positioned(
                        right: 6,
                        bottom: 4,
                        child: Container(
                          width: 54,
                          height: 54,
                          alignment: Alignment.center,
                          decoration: BoxDecoration(
                            color: color,
                            shape: BoxShape.circle,
                            border: Border.all(color: Ui.bg, width: 4),
                            boxShadow: UiShadow.glow(Ui.fade(color, .55), 22),
                          ),
                          child: Text(
                            ok ? '✓' : '✕',
                            style: UiText.sans(24, 800, color: Ui.bg),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 36),
                Text(
                  ok ? 'PAIRING ACCEPTED' : 'PAIRING REJECTED',
                  style: UiText.kicker.copyWith(color: color),
                ),
                const SizedBox(height: 10),
                Text(
                  ok ? 'Paired successfully.' : 'Pairing failed.',
                  textAlign: TextAlign.center,
                  style: UiText.pairTitle,
                ),
                const SizedBox(height: 14),
                Text(
                  ok
                      ? 'This phone is now paired with ASSAS. Only this phone can see your network.'
                      : (widget.reason ?? 'Pairing failed. Try again.'),
                  textAlign: TextAlign.center,
                  style: UiText.pairBody.copyWith(color: Ui.mute),
                ),
                const Spacer(),
                PillButton(
                  label: ok ? 'Continue' : 'Try again',
                  onTap: ok ? _continue : () => Navigator.of(context).maybePop(),
                ),
                const SizedBox(height: 24),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
