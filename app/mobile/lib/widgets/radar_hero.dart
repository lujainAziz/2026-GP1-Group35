import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../theme/assas_ui.dart';
import 'ui_icons.dart';
import 'ui_kit.dart';

/// Radar header from the design: glow, rings, rotating dashed ring and sweep,
/// a glowing orb with an icon, and ripples while something needs attention.
/// The bottom fades out from 72%.
class RadarHero extends StatelessWidget {
  /// Device detail (250 high, orb 92).
  const RadarHero.device({
    super.key,
    required this.color,
    required this.icon,
    required this.ripple,
    this.topLeft,
    this.topRight,
  }) : _alert = false;

  /// Alert detail (196 high, orb 76, bell in the severity color).
  const RadarHero.alert({
    super.key,
    required this.color,
    required this.ripple,
    this.topLeft,
    this.topRight,
  })  : _alert = true,
        icon = UiIcons.alerts;

  final Color color;
  final String icon;
  final bool ripple;
  final Widget? topLeft;
  final Widget? topRight;
  final bool _alert;

  @override
  Widget build(BuildContext context) {
    final height = _alert ? 196.0 : 250.0;
    final orbY = _alert ? 98.0 : 132.0;
    final orb = _alert ? 76.0 : 92.0;
    return Padding(
      padding: const EdgeInsets.only(top: 4),
      child: SizedBox(
        height: height,
        child: ShaderMask(
          blendMode: BlendMode.dstIn,
          shaderCallback: (r) => const LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Ui.black, Ui.black, Color(0x00000000)],
            stops: [0, .72, 1],
          ).createShader(r),
          child: ClipRect(
            child: UiClock(
              builder: (context, t, _) => Stack(
                clipBehavior: Clip.hardEdge,
                children: [
                  Positioned.fill(
                    child: CustomPaint(
                      painter: _RadarPainter(t: t, color: color, alert: _alert),
                    ),
                  ),
                  Positioned.fill(
                    child: LayoutBuilder(
                      builder: (context, box) {
                        final cx = box.maxWidth / 2;
                        return Stack(
                          clipBehavior: Clip.none,
                          children: [
                            if (ripple) ...[
                              Positioned(
                                left: cx - orb / 2,
                                top: orbY - orb / 2,
                                child: PingRing(
                                  t: t,
                                  size: orb,
                                  color: color,
                                  period: _alert ? 2.6 : 2.4,
                                ),
                              ),
                              if (!_alert)
                                Positioned(
                                  left: cx - orb / 2,
                                  top: orbY - orb / 2,
                                  child: PingRing(t: t, size: orb, color: color, delay: 1.2),
                                ),
                            ],
                            Positioned(
                              left: cx - orb / 2,
                              top: orbY - orb / 2,
                              child: Container(
                                width: orb,
                                height: orb,
                                alignment: Alignment.center,
                                decoration: BoxDecoration(
                                  shape: BoxShape.circle,
                                  gradient: LinearGradient(
                                    begin: Alignment.topLeft,
                                    end: Alignment.bottomRight,
                                    colors: [Ui.surf2, Ui.surf],
                                  ),
                                  border: Border.all(color: color, width: 1.5),
                                  boxShadow: [
                                    BoxShadow(
                                      color: Ui.fade(color, _alert ? .30 : .42),
                                      blurRadius: _alert ? 22 : 34,
                                    ),
                                  ],
                                ),
                                child: UiIcon(
                                  icon,
                                  size: _alert ? 30 : 36,
                                  stroke: _alert ? 1.8 : 1.7,
                                  color: _alert ? color : Ui.ink,
                                ),
                              ),
                            ),
                          ],
                        );
                      },
                    ),
                  ),
                  if (topLeft != null) Positioned(left: 22, top: _alert ? 18 : 22, child: topLeft!),
                  if (topRight != null) Positioned(right: 22, top: _alert ? 18 : 22, child: topRight!),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _RadarPainter extends CustomPainter {
  _RadarPainter({required this.t, required this.color, required this.alert});

  final double t;
  final Color color;
  final bool alert;

  @override
  void paint(Canvas canvas, Size size) {
    final cx = size.width / 2;
    if (alert) {
      const cy = 98.0;
      final c = Offset(cx, cy);
      final glowR = 150 * math.sqrt2 * .58;
      canvas.drawCircle(
        c,
        glowR,
        Paint()
          ..shader = RadialGradient(colors: [Ui.fade(color, .16), Ui.fade(color, 0)])
              .createShader(Rect.fromCircle(center: c, radius: glowR)),
      );
      paintDashedCircle(canvas, c, 92 - .5, Ui.fade(color, .28), turns: loop(t, 40));
      paintSweepRing(canvas, c, 92 * math.sqrt2 * .345, 92, Ui.fade(color, .18), loop(t, 8),
          from: .85, peak: .97, to: 1);
      paintCircle(canvas, c, 64 - .5, Color.lerp(Ui.line, color, .22)!);
    } else {
      final glowC = Offset(cx, 128 + 210);
      final glowR = 210 * math.sqrt2 * .55;
      canvas.drawCircle(
        glowC,
        glowR,
        Paint()
          ..shader = RadialGradient(colors: [Ui.fade(color, .20), Ui.fade(color, 0)])
              .createShader(Rect.fromCircle(center: glowC, radius: glowR)),
      );
      final c = Offset(cx, 218);
      paintCircle(canvas, c, 180 - .5, Color.lerp(Ui.line, color, .22)!);
      paintDashedCircle(canvas, c, 150 - .5, Ui.fade(color, .34), turns: loop(t, 40));
      paintSweepRing(canvas, c, 180 * math.sqrt2 * .405, 180, Ui.fade(color, .26), loop(t, 7),
          from: .82, peak: .96, to: 1);
      paintCircle(canvas, c, 114 - .5, Color.lerp(Ui.line, color, .30)!);
    }
  }

  @override
  bool shouldRepaint(_RadarPainter old) => old.t != t || old.color != color;
}
