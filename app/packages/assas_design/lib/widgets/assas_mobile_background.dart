import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../theme/assas_ui.dart';

/// Screen background from the design (BACKGROUND_SPEC.md): solid `--bg`, two
/// soft ambient glows that slowly drift and rotate (26s), a 28px grid that
/// fades out toward the bottom, and a fine static grain. Placed once behind
/// every screen in main.dart.
class AssasMobileBackground extends StatefulWidget {
  const AssasMobileBackground({super.key, required this.child, this.ambientStrength = 1});

  final Widget child;
  final double ambientStrength;

  @override
  State<AssasMobileBackground> createState() => _AssasMobileBackgroundState();
}

class _AssasMobileBackgroundState extends State<AssasMobileBackground>
    with SingleTickerProviderStateMixin {
  late final AnimationController _drift = AnimationController(
    vsync: this,
    duration: const Duration(seconds: 26),
  )..repeat();

  @override
  void dispose() {
    _drift.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      fit: StackFit.expand,
      children: [
        // Theme switch: the screen colour fades over .4s, like the design
        // (`.assas-shell { transition: background .4s }`).
        TweenAnimationBuilder<Color?>(
          tween: ColorTween(end: Ui.bg),
          duration: const Duration(milliseconds: 400),
          builder: (context, color, _) => ColoredBox(color: color ?? Ui.bg),
        ),
        // Ambient glow: two soft radial glows orbiting the screen centre.
        // Drawn as plain gradient circles (no rotated layer, no blur filter),
        // because a rotated full-screen layer showed hard-edged shapes on
        // some renderers.
        IgnorePointer(
          child: AnimatedBuilder(
            animation: _drift,
            builder: (context, _) => LayoutBuilder(
              builder: (context, box) => Stack(
                clipBehavior: Clip.hardEdge,
                children: [
                  for (final g in _glows(box.biggest, _drift.value, widget.ambientStrength))
                    Positioned(
                      left: g.$1.dx - g.$2,
                      top: g.$1.dy - g.$2,
                      width: g.$2 * 2,
                      height: g.$2 * 2,
                      child: DecoratedBox(
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          gradient: RadialGradient(
                            colors: [g.$3, g.$3.withValues(alpha: 0)],
                          ),
                        ),
                      ),
                    ),
                ],
              ),
            ),
          ),
        ),
        IgnorePointer(
          child: ShaderMask(
            blendMode: BlendMode.dstIn,
            shaderCallback: (rect) => LinearGradient(
              begin: Alignment.topCenter,
              end: Alignment.bottomCenter,
              colors: [Ui.black.withValues(alpha: 0.42), Ui.black.withValues(alpha: 0)],
              stops: const [0, 0.72],
            ).createShader(rect),
            child: Opacity(
              opacity: 0.72,
              child: CustomPaint(painter: _GridPainter(Ui.grid)),
            ),
          ),
        ),
        // Grain: 7px dots, opacity .095, fades in at 14% and out after 88%.
        IgnorePointer(
          child: RepaintBoundary(
            child: ShaderMask(
              blendMode: BlendMode.dstIn,
              shaderCallback: (rect) => LinearGradient(
                begin: Alignment.topCenter,
                end: Alignment.bottomCenter,
                colors: [
                  Ui.black.withValues(alpha: 0),
                  Ui.black,
                  Ui.black,
                  Ui.black.withValues(alpha: 0),
                ],
                stops: const [0, .14, .88, 1],
              ).createShader(rect),
              child: const CustomPaint(painter: _GrainPainter()),
            ),
          ),
        ),
        widget.child,
      ],
    );
  }
}

/// `.assas-ambient` (BACKGROUND_SPEC.md): a layer 140% of the screen with
/// two radial glows, drifting and turning once every 26s. Turning the layer
/// is the same as moving each glow's centre around the screen centre, so the
/// glows are placed directly: (centre, radius, colour incl. the .82 opacity).
List<(Offset, double, Color)> _glows(Size size, double t, double strength) {
  final box = Rect.fromLTWH(
    -0.2 * size.width,
    -0.2 * size.height,
    1.4 * size.width,
    1.4 * size.height,
  );
  // drift: 0% (-2%,0) 0deg -> 50% (2%,-1%) 180deg -> 100% (-2%,0) 360deg
  final half = t < 0.5 ? t * 2 : (1 - t) * 2;
  final shift = Offset((-0.02 + 0.04 * half) * box.width, (-0.01 * half) * box.height);
  final angle = t * 2 * math.pi;
  final pivot = box.center;

  (Offset, double, Color) glow(Offset at, double stop, Color color) {
    final p = Offset(box.left + at.dx * box.width, box.top + at.dy * box.height);
    // CSS circle size = distance to the farthest corner of the layer.
    final far = [box.topLeft, box.topRight, box.bottomLeft, box.bottomRight]
        .map((c) => (c - p).distance)
        .reduce(math.max);
    final v = p - pivot;
    final turned = Offset(
      v.dx * math.cos(angle) - v.dy * math.sin(angle),
      v.dx * math.sin(angle) + v.dy * math.cos(angle),
    );
    return (pivot + turned + shift, far * stop,
      color.withValues(alpha: (color.a * .82 * strength).clamp(0.0, 1.0)));
  }

  return [
    glow(const Offset(0.25, 0.15), 0.34, Ui.ambientA),
    glow(const Offset(0.78, 0.72), 0.30, Ui.ambientB),
  ];
}

/// `.assas-grid`: 1px lines every 28px.
class _GridPainter extends CustomPainter {
  _GridPainter(this.color);

  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()..color = color;
    for (double y = 0; y < size.height; y += 28) {
      canvas.drawRect(Rect.fromLTWH(0, y, size.width, 1), paint);
    }
    for (double x = 0; x < size.width; x += 28) {
      canvas.drawRect(Rect.fromLTWH(x, 0, 1, size.height), paint);
    }
  }

  @override
  bool shouldRepaint(_GridPainter old) => old.color != color;
}

/// `.assas-shell-grain`: in every 7 x 7 tile a thin ring (1px to 1.35px from
/// the tile corner) of rgba(255,255,255,.16); the whole layer at opacity .095.
/// The design blends it with soft-light; at this strength a plain blend looks
/// the same, and it keeps the layer from repainting with the moving glow.
class _GrainPainter extends CustomPainter {
  const _GrainPainter();

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = .35
      ..color = const Color(0x29FFFFFF).withValues(alpha: .16 * .095);
    for (double y = 0; y < size.height + 7; y += 7) {
      for (double x = 0; x < size.width + 7; x += 7) {
        canvas.drawCircle(Offset(x, y), 1.175, paint);
      }
    }
  }

  @override
  bool shouldRepaint(_GrainPainter old) => false;
}
