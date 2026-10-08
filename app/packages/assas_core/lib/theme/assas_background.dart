import 'package:flutter/material.dart';

import 'assas_colors.dart';

/// Lavender background (light) or deep plum background (dark) with soft
/// waves and blurred color blobs. Put behind every screen (done once in
/// each app's MaterialApp.builder).
class AssasBackground extends StatelessWidget {
  const AssasBackground({super.key, required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Stack(
      fit: StackFit.expand,
      children: [
        DecoratedBox(
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [AssasColors.bgTop, AssasColors.bgMid, AssasColors.bgBottom],
            ),
          ),
        ),
        _blob(top: -90, left: -70, size: 300, color: AssasColors.blobPurple, alpha: 0.6),
        _blob(top: 220, right: -110, size: 280, color: AssasColors.blobPink, alpha: 0.45),
        _blob(bottom: -80, left: 20, size: 320, color: AssasColors.blobPeach, alpha: 0.4),
        IgnorePointer(
          child: CustomPaint(
            painter: _WavesPainter(
              purple: AssasColors.blobPurple,
              mist: AssasColors.waveTint,
              pink: AssasColors.blobPink,
            ),
          ),
        ),
        child,
      ],
    );
  }

  static Widget _blob({
    double? top,
    double? left,
    double? right,
    double? bottom,
    required double size,
    required Color color,
    required double alpha,
  }) {
    return Positioned(
      top: top,
      left: left,
      right: right,
      bottom: bottom,
      child: IgnorePointer(
        child: Container(
          width: size,
          height: size,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            gradient: RadialGradient(
              colors: [color.withValues(alpha: alpha), color.withValues(alpha: 0)],
            ),
          ),
        ),
      ),
    );
  }
}

class _WavesPainter extends CustomPainter {
  _WavesPainter({required this.purple, required this.mist, required this.pink});

  final Color purple;
  final Color mist;
  final Color pink;

  @override
  void paint(Canvas canvas, Size size) {
    void wave(double y, double amp, Color color) {
      final w = size.width;
      final path = Path()
        ..moveTo(0, y)
        ..cubicTo(w * 0.25, y - amp, w * 0.5, y + amp, w * 0.75, y)
        ..cubicTo(w * 0.88, y - amp * 0.6, w * 0.95, y - amp * 0.2, w, y - amp * 0.3)
        ..lineTo(w, size.height)
        ..lineTo(0, size.height)
        ..close();
      canvas.drawPath(path, Paint()..color = color);
    }

    wave(size.height * 0.52, 44, purple.withValues(alpha: 0.10));
    wave(size.height * 0.70, 32, mist.withValues(alpha: 0.18));
    wave(size.height * 0.86, 26, pink.withValues(alpha: 0.10));
  }

  @override
  bool shouldRepaint(covariant _WavesPainter old) =>
      old.purple != purple || old.mist != mist || old.pink != pink;
}
