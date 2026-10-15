import 'dart:async';

import 'package:flutter/material.dart';

import '../theme/assas_ui.dart';
import 'assas_eye.dart';
import 'ui_kit.dart';

/// Splash screen from the design. Shows the opening eye and the wordmark for
/// 3.4 s (tap to skip), then fades to [child]. [child] is only built after the
/// splash ends, so nothing behind it starts early.
class SplashGate extends StatefulWidget {
  const SplashGate({super.key, required this.child});

  final Widget child;

  @override
  State<SplashGate> createState() => _SplashGateState();
}

class _SplashGateState extends State<SplashGate> {
  bool _done = false;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _timer = Timer(const Duration(milliseconds: 3400), _end);
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  void _end() {
    _timer?.cancel();
    if (mounted && !_done) setState(() => _done = true);
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedSwitcher(
      duration: const Duration(milliseconds: 450),
      child: _done
          ? KeyedSubtree(key: const ValueKey('app'), child: widget.child)
          : Scaffold(
              key: const ValueKey('splash'),
              body: GestureDetector(
                behavior: HitTestBehavior.opaque,
                onTap: _end,
                child: Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const AssasEye(size: 260, intro: true),
                      const SizedBox(height: 40),
                      FadeSlideIn(
                        duration: const Duration(milliseconds: 800),
                        delay: const Duration(milliseconds: 950),
                        child: Column(
                          children: [
                            Padding(
                              padding: const EdgeInsets.only(left: 13.2), // .55em
                              child: Text('ASSAS', style: UiText.splashWordmark),
                            ),
                            const SizedBox(height: 12),
                            Text(
                              'WATCHING OVER YOUR NETWORK',
                              style: UiText.mono(11, 500, em: .2, color: Ui.mute),
                            ),
                          ],
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
