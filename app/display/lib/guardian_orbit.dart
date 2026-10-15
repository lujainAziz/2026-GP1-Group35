import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:assas_design/widgets/assas_eye.dart';
import 'display_ui.dart';

/// Decorative orbital frame; not a chart of network activity.
class GuardianOrbit extends StatefulWidget {
  const GuardianOrbit({super.key, required this.live});
  final bool live;
  @override
  State<GuardianOrbit> createState() => _GuardianOrbitState();
}

class _GuardianOrbitState extends State<GuardianOrbit> with SingleTickerProviderStateMixin {
  late final _clock = AnimationController(vsync: this, duration: const Duration(seconds: 28));
  @override
  void initState() { super.initState(); if (widget.live) _clock.repeat(); }
  @override
  void didUpdateWidget(GuardianOrbit oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.live != oldWidget.live) { widget.live ? _clock.repeat() : _clock.stop(); }
  }
  @override
  void dispose() { _clock.dispose(); super.dispose(); }
  @override
  Widget build(BuildContext context) => ExcludeSemantics(child: RepaintBoundary(
    child: SizedBox.square(dimension: 210, child: Stack(alignment: Alignment.center, children: [
      Positioned.fill(child: CustomPaint(painter: _OrbitPainter(_clock))),
      Container(width: 124, height: 124,
        decoration: BoxDecoration(shape: BoxShape.circle, gradient: RadialGradient(
          colors: [DisplayUi.accent.withValues(alpha: .14), Colors.transparent])),
        child: const Center(child: AssasEye(size: 156))),
    ])),
  ));
}

class _OrbitPainter extends CustomPainter {
  _OrbitPainter(this.clock) : super(repaint: clock);
  final Animation<double> clock;
  @override
  void paint(Canvas canvas, Size size) {
    final c = size.center(Offset.zero);
    final p = Paint()..style = PaintingStyle.stroke..strokeWidth = 1;
    for (final radius in [64.0, 84.0, 102.0]) {
      canvas.drawCircle(c, radius, p..color = DisplayUi.line);
    }
    final angle = clock.value * math.pi * 2;
    for (var i = 0; i < 3; i++) {
      final radius = 64.0 + i * 19;
      final start = (i.isEven ? angle : -angle) + i * 2;
      final color = i == 1 ? DisplayUi.green : DisplayUi.accent;
      canvas.drawArc(Rect.fromCircle(center: c, radius: radius), start, .65, false,
          p..color = color.withValues(alpha: .6)..strokeWidth = 2);
      final dot = c + Offset(math.cos(start), math.sin(start)) * radius;
      canvas.drawCircle(dot, 3, Paint()..color = color);
    }
  }
  @override
  bool shouldRepaint(_OrbitPainter oldDelegate) => oldDelegate.clock != clock;
}
