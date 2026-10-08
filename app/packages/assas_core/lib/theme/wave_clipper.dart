import 'package:flutter/widgets.dart';

/// Cuts the bottom edge of a box into a soft wave (purple headers).
class WaveBottomClipper extends CustomClipper<Path> {
  const WaveBottomClipper({this.depth = 22});

  /// How deep the wave is, in pixels.
  final double depth;

  @override
  Path getClip(Size size) {
    final w = size.width;
    final h = size.height;
    return Path()
      ..lineTo(0, h - depth)
      ..cubicTo(w * 0.28, h + depth * 0.3, w * 0.58, h - depth * 1.6, w, h - depth * 0.5)
      ..lineTo(w, 0)
      ..close();
  }

  @override
  bool shouldReclip(covariant WaveBottomClipper oldClipper) => oldClipper.depth != depth;
}
