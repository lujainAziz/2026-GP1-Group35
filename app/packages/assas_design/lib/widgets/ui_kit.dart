import 'dart:math' as math;
import 'package:flutter/material.dart';
import '../theme/assas_ui.dart';
BoxDecoration glassCard(double radius) => BoxDecoration(
      borderRadius: BorderRadius.circular(radius),
      border: Border.all(color: Ui.line),
      gradient: LinearGradient(
        begin: Alignment.topLeft,
        end: Alignment.bottomRight,
        colors: [Ui.fade(Ui.surf, 0.88), Ui.fade(Ui.surf2, 0.74)],
      ),
      boxShadow: UiShadow.glass,
    );

/// Plain card: surface, 1px line, radius.
BoxDecoration surfCard(double radius, {Color? color}) => BoxDecoration(
      color: color ?? Ui.surf,
      borderRadius: BorderRadius.circular(radius),
      border: Border.all(color: Ui.line),
    );

/// Splits a path into dashes. [phase] works like SVG stroke-dashoffset.
Path dashPath(Path source, List<double> dashes, {double phase = 0}) {
  // Like SVG: an odd list is repeated to make it even.
  final pattern = dashes.length.isOdd ? [...dashes, ...dashes] : dashes;
  final out = Path();
  final total = pattern.fold<double>(0, (a, b) => a + b);
  if (total <= 0) return source;
  for (final m in source.computeMetrics()) {
    var s = -(phase % total);
    var i = 0;
    while (s < m.length) {
      final seg = pattern[i % pattern.length];
      if (i.isEven) {
        final a = math.max(s, 0.0), b = math.min(s + seg, m.length);
        if (b > a) out.addPath(m.extractPath(a, b), Offset.zero);
      }
      s += seg;
      i++;
    }
  }
  return out;
}

/// Circle path starting at 3 o'clock, clockwise (like an SVG circle).
Path circlePath(Offset c, double r) {
  final rect = Rect.fromCircle(center: c, radius: r);
  return Path()
    ..addArc(rect, 0, math.pi)
    ..arcTo(rect, math.pi, math.pi, false);
}

class UiClock extends StatefulWidget {
  const UiClock({super.key, required this.builder, this.child});

  final Widget Function(BuildContext context, double seconds, Widget? child) builder;
  final Widget? child;

  @override
  State<UiClock> createState() => _UiClockState();
}

class _UiClockState extends State<UiClock> with SingleTickerProviderStateMixin {
  // Seconds since this widget appeared. Never wraps, so effects that keep
  // moving (dashes flowing along a line) never jump back.
  double _t = 0;
  late final _ticker = createTicker((elapsed) {
    setState(() => _t = elapsed.inMicroseconds / 1e6);
  });

  @override
  void initState() {
    super.initState();
    _ticker.start();
  }

  @override
  void dispose() {
    _ticker.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => widget.builder(context, _t, widget.child);
}

/// 0..1 progress of a looping animation of [period] seconds.
double loop(double t, double period, {double delay = 0}) {
  final v = ((t - delay) / period) % 1;
  return v < 0 ? v + 1 : v;
}

/// Smooth 0 -> 1 -> 0 wave (ease-in-out keyframes 0%,100% / 50%).
double wave(double t, double period, {double delay = 0}) =>
    0.5 - 0.5 * math.cos(2 * math.pi * loop(t, period, delay: delay));

void paintSweepRing(
  Canvas canvas,
  Offset c,
  double inner,
  double outer,
  Color color,
  double turns, {
  double from = 0.80,
  double peak = 0.91,
  double to = 0.99,
}) {
  final rect = Rect.fromCircle(center: c, radius: outer);
  final shader = SweepGradient(
    colors: [Colors.transparent, Colors.transparent, color, color.withValues(alpha: 0), Colors.transparent],
    stops: [0, from, peak, to, 1],
    transform: GradientRotation(-math.pi / 2 + turns * 2 * math.pi),
  ).createShader(rect);
  final ring = Path()
    ..fillType = PathFillType.evenOdd
    ..addOval(rect)
    ..addOval(Rect.fromCircle(center: c, radius: inner));
  canvas.drawPath(ring, Paint()..shader = shader);
}

/// Dashed circle outline (CSS `border: 1px dashed`), rotated by [turns].
void paintDashedCircle(Canvas canvas, Offset c, double r, Color color,
    {double turns = 0, double width = 1, List<double> pattern = const [3, 3]}) {
  canvas.save();
  canvas.translate(c.dx, c.dy);
  canvas.rotate(turns * 2 * math.pi);
  canvas.drawPath(
    dashPath(circlePath(Offset.zero, r), pattern),
    Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = width
      ..color = color,
  );
  canvas.restore();
}

void paintCircle(Canvas canvas, Offset c, double r, Color color, {double width = 1}) {
  canvas.drawCircle(
    c,
    r,
    Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = width
      ..color = color,
  );
}

class Pressable extends StatefulWidget {
  const Pressable({
    super.key,
    required this.child,
    this.onTap,
    this.enabled = true,
    this.semanticLabel,
  });

  final Widget child;
  final VoidCallback? onTap;
  final bool enabled;

  /// What a screen reader says for this button.
  final String? semanticLabel;

  @override
  State<Pressable> createState() => _PressableState();
}

class _PressableState extends State<Pressable> {
  bool _down = false;

  void _set(bool v) {
    if (_down != v) setState(() => _down = v);
  }

  @override
  Widget build(BuildContext context) {
    final active = widget.enabled && widget.onTap != null;
    final button = GestureDetector(
      behavior: HitTestBehavior.opaque,
      onTap: active ? widget.onTap : null,
      onTapDown: active ? (_) => _set(true) : null,
      onTapUp: active ? (_) => _set(false) : null,
      onTapCancel: active ? () => _set(false) : null,
      child: AnimatedOpacity(
        duration: const Duration(milliseconds: 90),
        opacity: _down ? 0.82 : 1,
        child: widget.child,
      ),
    );
    if (widget.semanticLabel == null) return button;
    return Semantics(
      button: true,
      enabled: active,
      label: widget.semanticLabel,
      excludeSemantics: true,
      child: button,
    );
  }
}


class PingRing extends StatelessWidget {
  const PingRing({
    super.key,
    required this.t,
    required this.size,
    required this.color,
    this.period = 2.4,
    this.delay = 0,
    this.maxScale = 1.9,
    this.startOpacity = 0.7,
  });

  final double t;
  final double size;
  final Color color;
  final double period;
  final double delay;
  final double maxScale;
  final double startOpacity;

  @override
  Widget build(BuildContext context) {
    final p = Curves.easeOut.transform(loop(t, period, delay: delay));
    return IgnorePointer(
      child: Transform.scale(
        scale: 1 + (maxScale - 1) * p,
        child: Opacity(
          opacity: (startOpacity * (1 - p)).clamp(0.0, 1.0),
          child: Container(
            width: size,
            height: size,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              border: Border.all(color: color),
            ),
          ),
        ),
      ),
    );
  }
}

/// "← BACK" glass pill (detail screens).
