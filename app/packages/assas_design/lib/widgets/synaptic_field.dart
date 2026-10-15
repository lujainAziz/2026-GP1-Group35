import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../theme/assas_ui.dart';
import 'assas_eye.dart';
import 'device_signals.dart';
import 'ui_icons.dart';
import 'ui_kit.dart';

/// Six fixed slots around the eye (node top-left, wire path, wire end).
class _Slot {
  const _Slot(this.sx, this.sy, this.cx, this.cy, this.px, this.py);
  final double sx, sy; // node position
  final double cx, cy; // quadratic control point
  final double px, py; // wire end
}

const _slots = [
  _Slot(189.0, 39.8, 195.7, 111.9, 224.0, 62.8),
  _Slot(248.0, 142.0, 226.4, 165.0, 283.0, 165.0),
  _Slot(189.0, 244.2, 195.7, 218.1, 224.0, 267.2),
  _Slot(71.0, 244.2, 134.3, 218.1, 106.0, 267.2),
  _Slot(12.0, 142.0, 103.6, 165.0, 47.0, 165.0),
  _Slot(71.0, 39.8, 134.3, 111.9, 106.0, 62.8),
];

/// `.assas-synaptic` (330 x 330): the eye with the top 6 devices around it,
/// ordered by priority (Critical > High > Medium > Low > Unrecognized > Not monitored).
class SynapticField extends StatelessWidget {
  const SynapticField({super.key, required this.top, required this.onOpen});

  /// Already sorted by priority; only the first 6 are shown.
  final List<DeviceSignal> top;
  final ValueChanged<DeviceSignal> onOpen;

  @override
  Widget build(BuildContext context) {
    final nodes = top.take(6).toList();
    return SizedBox(
      width: 330,
      height: 330,
      child: UiClock(
        child: const Positioned(
          left: 80 + 7,
          top: 104 + 12,
          child: AssasEye(size: 156),
        ),
        builder: (context, t, eye) => Stack(
          clipBehavior: Clip.none,
          children: [
            Positioned.fill(
              child: IgnorePointer(
                child: CustomPaint(painter: _FieldPainter(t: t, nodes: nodes)),
              ),
            ),
            for (var i = 0; i < nodes.length; i++)
              _node(nodes[i], _slots[i], i, t),
            eye!,
          ],
        ),
      ),
    );
  }

  Widget _node(DeviceSignal d, _Slot s, int i, double t) {
    final hot = d.needsAttention;
    final signal = d.signalColor;
    final outer = hot ? signal : Color.lerp(Ui.acc, Ui.line, .74)!;
    final float = -3 * wave(t, 4.2, delay: -i * 0.7);
    final pulse = wave(t, 2.0);
    final badgeGlow = wave(t, 1.8);

    return Positioned(
      left: s.sx,
      top: s.sy,
      width: 70,
      child: Transform.translate(
        offset: Offset(0, float),
        child: Opacity(
          opacity: d.online ? 1 : 0.4,
          child: Pressable(
            onTap: () => onOpen(d),
            semanticLabel: '${d.device.displayName}, ${d.device.onlineLabel}${d.badge.isNotEmpty ? ', ${d.verdict.toLowerCase()}' : ''}',
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                SizedBox(
                  width: 48,
                  height: 48,
                  child: Stack(
                    clipBehavior: Clip.none,
                    children: [
                      // Orb
                      Container(
                        width: 48,
                        height: 48,
                        alignment: Alignment.center,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          border: Border.all(color: Ui.line),
                          gradient: LinearGradient(
                            begin: Alignment.topLeft,
                            end: Alignment.bottomRight,
                            colors: [Ui.fade(Ui.surf2, .95), Ui.fade(Ui.surf, .90)],
                          ),
                          boxShadow: UiShadow.orb,
                        ),
                        child: UiIcon(d.icon, size: 20, stroke: 1.8, color: Ui.ink),
                      ),
                      // Outer ring (state color). The glow is drawn outside the
                      // ring only, like a CSS box-shadow (never inside the orb).
                      Positioned(
                        left: -1,
                        top: -1,
                        right: -1,
                        bottom: -1,
                        child: IgnorePointer(
                          child: Opacity(
                            opacity: hot ? .6 + .4 * pulse : .88,
                            child: CustomPaint(
                              painter: _RingPainter(
                                color: outer,
                                glows: [
                                  (Ui.fade(outer, .14), 9.0),
                                  if (hot) (Ui.fade(signal, .5 * pulse), 5.0),
                                ],
                              ),
                            ),
                          ),
                        ),
                      ),
                      if (hot)
                        Positioned(
                          left: -1,
                          top: -1,
                          child: PingRing(
                            t: t,
                            size: 50,
                            color: signal,
                            period: 2.4,
                            maxScale: 1.45,
                            startOpacity: .75,
                          ),
                        ),
                      if (hot && d.badge.isNotEmpty)
                        Positioned(
                          right: -4,
                          top: -4,
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 3),
                            decoration: BoxDecoration(
                              color: signal,
                              borderRadius: BorderRadius.circular(UiRadius.pill),
                              boxShadow: [
                                BoxShadow(
                                  color: Ui.fade(signal, .35 + .65 * badgeGlow),
                                  blurRadius: 4 + 8 * badgeGlow,
                                ),
                              ],
                            ),
                            child: Text(d.badge, style: UiText.eyeBadge.copyWith(color: Ui.eyeBadgeInk)),
                          ),
                        ),
                    ],
                  ),
                ),
                const SizedBox(height: 8),
                SizedBox(
                  width: 70,
                  height: 10,
                  child: OverflowBox(
                    maxWidth: 82,
                    maxHeight: 10,
                    child: Text(
                    UiIcons.shortLabel(d.device),
                    maxLines: 1,
                    softWrap: false,
                    textAlign: TextAlign.center,
                    overflow: TextOverflow.visible,
                    style: UiText.eyeName.copyWith(
                      color: Ui.mute,
                      shadows: [
                        Shadow(color: Ui.bg, blurRadius: 5, offset: const Offset(0, 1)),
                        Shadow(color: Ui.bg, blurRadius: 8),
                      ],
                    ),
                    ),
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

class _FieldPainter extends CustomPainter {
  _FieldPainter({required this.t, required this.nodes});

  final double t;
  final List<DeviceSignal> nodes;

  static const _c = Offset(165, 165);

  @override
  void paint(Canvas canvas, Size size) {
    // ::before soft glow (inset 54).
    canvas.drawCircle(
      _c,
      97.3,
      Paint()
        ..shader = RadialGradient(colors: [Ui.fade(Ui.acc, .13 * .9), Ui.fade(Ui.acc, 0)])
            .createShader(Rect.fromCircle(center: _c, radius: 97.3))
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 4.5),
    );

    // Rings.
    paintCircle(canvas, _c, 158 - .5, Ui.fade(Ui.line, .8));
    paintDashedCircle(canvas, _c, 117 - .5, Color.lerp(Ui.line, Ui.acc, .2)!, turns: -loop(t, 30));
    paintCircle(canvas, _c, 69 - .5, Ui.fade(Ui.line, .9));

    // Sweep (inset 13, visible outside 58% of the farthest corner).
    paintSweepRing(canvas, _c, 152 * math.sqrt2 * .575, 152, Ui.fade(Ui.acc, .19 * .65), loop(t, 8.8));

    // Arc field (286 box): three layers turning backwards.
    final muted = Color.lerp(Ui.mute, Ui.ink, .34)!;
    final green = Color.lerp(Ui.mute, Ui.low, .44)!;
    final amber = Color.lerp(Ui.mute, Ui.med, .46)!;
    _arcLayer(canvas, 22, [
      _Arc(136, Ui.acc, const [6, 28, 5, 41, 7, 19, 5, 52, 6, 33, 7, 46, 5, 25, 6, 55], 0, false),
      _Arc(136, muted, const [4, 62, 5, 97, 4, 74, 5, 109], 97, true),
    ]);
    _arcLayer(canvas, 30, [
      _Arc(92, muted, const [6, 37, 5, 58, 7, 29, 5, 66, 6, 44, 5, 47, 6, 39], 0, false),
      _Arc(92, green, const [4, 83, 5, 121, 4, 143], 97, true),
    ]);
    _arcLayer(canvas, 40, [
      _Arc(64, Ui.acc, const [7, 46, 6, 71, 7, 38, 6, 89, 7, 83], 0, false),
      _Arc(64, amber, const [5, 117, 5, 233], 97, true),
    ]);

    // Wires to the nodes.
    for (var i = 0; i < nodes.length; i++) {
      final s = _slots[i];
      final d = nodes[i];
      final path = Path()
        ..moveTo(165, 165)
        ..quadraticBezierTo(s.cx, s.cy, s.px, s.py);
      if (d.needsAttention) {
        final c = d.signalColor;
        final dashed = dashPath(path, const [4, 8], phase: -54 / 2.8 * t);
        final p = Paint()
          ..style = PaintingStyle.stroke
          ..strokeCap = StrokeCap.round
          ..strokeWidth = 1.15;
        canvas.drawPath(
          dashed,
          p
            ..color = Ui.fade(c, .36)
            ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 1.5),
        );
        canvas.drawPath(dashed, p..maskFilter = null);
        // Pulsing end dot.
        final op = .2 + .8 * (1 - (2 * loop(t, 1.8) - 1).abs());
        canvas.drawCircle(
          Offset(s.px, s.py),
          2.2,
          Paint()
            ..color = Ui.fade(c, .8 * op)
            ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 2),
        );
        canvas.drawCircle(Offset(s.px, s.py), 2.2, Paint()..color = Ui.fade(c, .8 * op));
      } else {
        canvas.drawPath(
          dashPath(path, const [2, 7]),
          Paint()
            ..style = PaintingStyle.stroke
            ..strokeCap = StrokeCap.round
            ..strokeWidth = 1
            ..color = Ui.fade(Ui.acc, .24 * .36),
        );
      }
    }
  }

  void _arcLayer(Canvas canvas, double period, List<_Arc> arcs) {
    canvas.save();
    canvas.translate(_c.dx, _c.dy);
    canvas.rotate(-loop(t, period) * 2 * math.pi);
    for (final a in arcs) {
      final unit = 2 * math.pi * a.r / 360; // pathLength = 360
      final dur = a.slow ? 23.0 : 14.0;
      // Flows forever at the design's speed, with no jump when a loop restarts.
      final offset = a.start - (360 + a.start) / dur * t;
      final dashed = dashPath(
        circlePath(Offset.zero, a.r),
        [for (final v in a.pattern) v * unit],
        phase: offset * unit,
      );
      final width = a.slow ? 1.6 : 2.2;
      final op = a.slow ? .4 : .55;
      final p = Paint()
        ..style = PaintingStyle.stroke
        ..strokeCap = StrokeCap.round
        ..strokeWidth = width;
      canvas.drawPath(
        dashed,
        p
          ..color = Ui.fade(a.color, .35 * op)
          ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 1.5),
      );
      canvas.drawPath(dashed, p
        ..maskFilter = null
        ..color = Ui.fade(a.color, op));
    }
    canvas.restore();
  }

  @override
  bool shouldRepaint(_FieldPainter old) => true;
}

class _Arc {
  const _Arc(this.r, this.color, this.pattern, this.start, this.slow);
  final double r;
  final Color color;
  final List<double> pattern;
  final double start;
  final bool slow;
}

/// 1px ring with an outside-only glow.
class _RingPainter extends CustomPainter {
  _RingPainter({required this.color, required this.glows});

  final Color color;
  final List<(Color, double)> glows;

  @override
  void paint(Canvas canvas, Size size) {
    final c = size.center(Offset.zero);
    final r = size.shortestSide / 2;
    canvas.save();
    canvas.clipPath(
      Path()
        ..fillType = PathFillType.evenOdd
        ..addRect(Rect.fromCircle(center: c, radius: r + 40))
        ..addOval(Rect.fromCircle(center: c, radius: r)),
    );
    for (final g in glows) {
      canvas.drawCircle(
        c,
        r,
        Paint()
          ..color = g.$1
          ..maskFilter = MaskFilter.blur(BlurStyle.outer, g.$2 / 2),
      );
    }
    canvas.restore();
    paintCircle(canvas, c, r - .5, color);
  }

  @override
  bool shouldRepaint(_RingPainter old) => true;
}
