import 'dart:math' as math;
import 'dart:ui' as ui;

import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import 'package:assas_design/widgets/ui_kit.dart' show surfCard;

export 'package:assas_design/widgets/ui_kit.dart' show glassCard, surfCard;

import '../theme/assas_ui.dart';
import 'coming_soon.dart';
import 'device_signals.dart';

/// The design's ease: cubic-bezier(.2,.8,.2,1).
const Curve kUiEase = Cubic(0.2, 0.8, 0.2, 1);

/// Tap target that dims slightly while pressed (design :active).
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

/// Scroll areas fade in over their top 10px (design mask), starting at [top].
class TopFade extends StatelessWidget {
  const TopFade({super.key, required this.child, this.top = 0});

  final Widget child;
  final double top;

  @override
  Widget build(BuildContext context) {
    return ShaderMask(
      blendMode: BlendMode.dstIn,
      shaderCallback: (rect) {
        final h = rect.height <= 0 ? 1.0 : rect.height;
        final a = (top / h).clamp(0.0, 1.0);
        final b = ((top + 10) / h).clamp(0.0, 1.0);
        return LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: const [Color(0x00000000), Color(0x00000000), Ui.black, Ui.black],
          stops: [0, a, b, 1],
        ).createShader(rect);
      },
      child: child,
    );
  }
}

/// Status dot with the design's `assas-pulse` (a ring that grows to 6px and
/// fades, every 2.3s).
class PulseDot extends StatelessWidget {
  const PulseDot(this.color, {super.key, this.size = 6});

  final Color color;
  final double size;

  @override
  Widget build(BuildContext context) {
    return UiClock(
      builder: (context, t, _) {
        final w = wave(t, 2.3);
        return Container(
          width: size,
          height: size,
          decoration: BoxDecoration(
            color: color,
            shape: BoxShape.circle,
            boxShadow: [BoxShadow(color: Ui.fade(color, 1 - w), spreadRadius: 6 * w)],
          ),
        );
      },
    );
  }
}

/// Loading spinner from the design: a 2px ring with an open top, .7s a turn.
class UiSpinner extends StatelessWidget {
  const UiSpinner({super.key, this.size = 16, this.color});

  final double size;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final c = color ?? Ui.acc;
    return Semantics(
      label: 'Loading',
      child: UiClock(
        builder: (context, t, _) => Transform.rotate(
          angle: loop(t, .7) * 2 * math.pi,
          child: CustomPaint(size: Size.square(size), painter: _SpinnerPainter(c)),
        ),
      ),
    );
  }
}

class _SpinnerPainter extends CustomPainter {
  _SpinnerPainter(this.color);

  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    final r = Rect.fromLTWH(1, 1, size.width - 2, size.height - 2);
    // Full ring minus the top quarter (border-top transparent).
    canvas.drawArc(
      r,
      -math.pi / 4,
      math.pi * 1.5,
      false,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 2
        ..color = color,
    );
  }

  @override
  bool shouldRepaint(_SpinnerPainter old) => old.color != color;
}

/// Frosted surface: color over a blurred backdrop, with border and shadow.
class Glass extends StatelessWidget {
  const Glass({
    super.key,
    required this.child,
    required this.color,
    required this.radius,
    this.blur = 14,
    this.border,
    this.padding,
    this.height,
    this.width,
    this.shadows,
  });

  final Widget child;
  final Color color;
  final double radius;
  final double blur;
  final Color? border;
  final EdgeInsetsGeometry? padding;
  final double? height;
  final double? width;
  final List<BoxShadow>? shadows;

  @override
  Widget build(BuildContext context) {
    final r = BorderRadius.circular(radius);
    return DecoratedBox(
      decoration: BoxDecoration(borderRadius: r, boxShadow: shadows),
      child: ClipRRect(
        borderRadius: r,
        child: BackdropFilter(
          filter: ui.ImageFilter.blur(sigmaX: blur / 2, sigmaY: blur / 2),
          child: Container(
            height: height,
            width: width,
            padding: padding,
            decoration: BoxDecoration(
              color: color,
              borderRadius: r,
              border: Border.all(color: border ?? Ui.line),
            ),
            child: child,
          ),
        ),
      ),
    );
  }
}

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

/// Box with a dashed 1px border (empty states).
class DashedBox extends StatelessWidget {
  const DashedBox({
    super.key,
    required this.child,
    required this.radius,
    this.color,
    this.fill,
    this.padding,
    this.margin,
  });

  final Widget child;
  final double radius;
  final Color? color;
  final Color? fill;
  final EdgeInsetsGeometry? padding;
  final EdgeInsetsGeometry? margin;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: margin,
      decoration: BoxDecoration(color: fill, borderRadius: BorderRadius.circular(radius)),
      child: CustomPaint(
        foregroundPainter: _DashedRRectPainter(color ?? Ui.line, radius),
        child: Padding(padding: padding ?? EdgeInsets.zero, child: child),
      ),
    );
  }
}

class _DashedRRectPainter extends CustomPainter {
  _DashedRRectPainter(this.color, this.radius);

  final Color color;
  final double radius;

  @override
  void paint(Canvas canvas, Size size) {
    final rr = RRect.fromRectAndRadius(
      (Offset.zero & size).deflate(0.5),
      Radius.circular(math.min(radius, size.shortestSide / 2)),
    );
    canvas.drawPath(
      dashPath(Path()..addRRect(rr), const [4, 3]),
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1
        ..color = color,
    );
  }

  @override
  bool shouldRepaint(_DashedRRectPainter old) => old.color != color || old.radius != radius;
}

/// Screen entrance: `scr` (fade in + 14px up), replayed when [replayKey] changes.
/// The child keeps its state when the animation replays.
class FadeSlideIn extends StatefulWidget {
  const FadeSlideIn({
    super.key,
    required this.child,
    this.duration = const Duration(milliseconds: 450),
    this.delay = Duration.zero,
    this.replayKey,
  });

  final Widget child;
  final Duration duration;
  final Duration delay;
  final Object? replayKey;

  @override
  State<FadeSlideIn> createState() => _FadeSlideInState();
}

class _FadeSlideInState extends State<FadeSlideIn> with SingleTickerProviderStateMixin {
  late final AnimationController _c = AnimationController(
    vsync: this,
    duration: widget.duration + widget.delay,
  )..forward();

  @override
  void didUpdateWidget(FadeSlideIn old) {
    super.didUpdateWidget(old);
    if (old.replayKey != widget.replayKey) _c.forward(from: 0);
  }

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final total = widget.duration + widget.delay;
    final start = total.inMicroseconds == 0 ? 0.0 : widget.delay.inMicroseconds / total.inMicroseconds;
    return AnimatedBuilder(
      animation: _c,
      builder: (context, child) {
        final t = start >= 1 ? 1.0 : ((_c.value - start) / (1 - start)).clamp(0.0, 1.0);
        final e = kUiEase.transform(t);
        return Opacity(
          opacity: e,
          child: Transform.translate(offset: Offset(0, 14 * (1 - e)), child: child),
        );
      },
      child: widget.child,
    );
  }
}

/// Mono kicker row ("ON YOUR NETWORK"), 30 high.
class KickerRow extends StatelessWidget {
  const KickerRow(this.text, {super.key});

  final String text;

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 30,
      alignment: Alignment.centerLeft,
      padding: const EdgeInsets.symmetric(horizontal: UiSpace.pageText),
      child: Text(text, style: UiText.kicker.copyWith(color: Ui.mute)),
    );
  }
}

/// Round status pill (New / Reviewed / Resolved).
class StatePill extends StatelessWidget {
  const StatePill(this.alert, {super.key, this.padding});

  final SecurityAlert alert;
  final EdgeInsetsGeometry? padding;

  @override
  Widget build(BuildContext context) {
    // Alert states arrive with alert management (Sprint 5).
    if (!Released.alertManagement) return const SizedBox.shrink();
    return Container(
      padding: padding ?? const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: stateBg(alert),
        borderRadius: BorderRadius.circular(UiRadius.pill),
      ),
      child: Text(alert.stateLabel, style: UiText.pill.copyWith(color: stateColor(alert))),
    );
  }
}

/// Glowing dot (status dots).
class GlowDot extends StatelessWidget {
  const GlowDot(this.color, {super.key, this.size = 6, this.glow = 10});

  final Color color;
  final double size;
  final double glow;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color: color,
        shape: BoxShape.circle,
        boxShadow: glow > 0 ? UiShadow.glow(color, glow) : null,
      ),
    );
  }
}

/// Repeating animation clock in seconds (for the design's looping effects).
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

/// Expanding ring: `ping` / `assasRipple` (scale up, fade out, ease-out).
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
class BackPill extends StatelessWidget {
  const BackPill({super.key});

  @override
  Widget build(BuildContext context) {
    return Pressable(
      onTap: () => Navigator.of(context).maybePop(),
      semanticLabel: 'Back',
      child: Glass(
        color: Ui.fade(Ui.bg, 0.62),
        radius: UiRadius.pill,
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        child: Text('← BACK', style: UiText.link.copyWith(color: Ui.mute)),
      ),
    );
  }
}

/// Floating header row over a detail screen (back on the left, [trailing] on the right).
class DetailHeader extends StatelessWidget {
  const DetailHeader({super.key, required this.trailing});

  final Widget trailing;

  @override
  Widget build(BuildContext context) {
    final top = MediaQuery.paddingOf(context).top;
    return Positioned(
      left: 0,
      right: 0,
      top: top,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 10),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [const BackPill(), trailing],
        ),
      ),
    );
  }
}

/// Section header ("Recent", "What happened", ...).
class SectionHeader extends StatelessWidget {
  const SectionHeader(this.text, {super.key, required this.padding, this.trailing});

  final String text;
  final EdgeInsetsGeometry padding;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: padding,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Expanded(child: Text(text, style: UiText.section, maxLines: 1)),
          if (trailing != null) trailing!,
        ],
      ),
    );
  }
}

/// Big round button (56 high): filled accent or accent outline.
class PillButton extends StatelessWidget {
  const PillButton({
    super.key,
    required this.label,
    required this.onTap,
    this.filled = true,
    this.opacity = 1,
    this.icon,
    this.busy = false,
    this.busyLabel,
    this.borderColor,
    this.textColor,
    this.background,
  });

  final String label;
  final VoidCallback? onTap;
  final bool filled;
  final double opacity;
  final Widget? icon;
  final bool busy;
  final String? busyLabel;
  final Color? borderColor;
  final Color? textColor;
  final Color? background;

  @override
  Widget build(BuildContext context) {
    final fg = textColor ?? (filled ? Ui.accInk : Ui.ink);
    return Pressable(
      onTap: busy ? null : onTap,
      child: AnimatedOpacity(
        duration: const Duration(milliseconds: 250),
        opacity: opacity,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 250),
          height: 56,
          alignment: Alignment.center,
          decoration: BoxDecoration(
            color: background ?? (filled ? Ui.acc : Colors.transparent),
            borderRadius: BorderRadius.circular(UiRadius.button),
            border: Border.all(color: borderColor ?? Ui.acc, width: 1.5),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (busy) ...[
                UiSpinner(size: 16, color: fg),
                const SizedBox(width: 10),
              ] else if (icon != null) ...[
                IconTheme(data: IconThemeData(color: fg), child: icon!),
                const SizedBox(width: 10),
              ],
              Text(busy ? (busyLabel ?? label) : label, style: UiText.button.copyWith(color: fg)),
            ],
          ),
        ),
      ),
    );
  }
}

/// Card with a rail and dotted rows (Signal details / device specs).
/// Insert zero-width spaces after `:`/`.` so long addresses (esp. IPv6) wrap at
/// group boundaries instead of being clipped or broken mid-group. Display only;
/// copy uses the raw value.
String breakAddress(String v) => v.replaceAllMapped(RegExp(r'[:./]'), (m) => '${m[0]}​');

/// Inserts invisible break opportunities (ZWSP) after a name's natural
/// separators so a long single token ("emulator (sdk_gphone64_x86_64)") wraps
/// at `_`/`-`/`(`/`.` instead of breaking mid-word. The visible text is
/// unchanged.
String breakName(String v) => v.replaceAllMapped(RegExp(r'[_\-(.]'), (m) => '${m[0]}​');

class SpecList extends StatelessWidget {
  const SpecList({
    super.key,
    required this.rows,
    required this.railColor,
    this.copyable = const <String>{},
    this.onCopy,
  });

  /// (label, value, value color)
  final List<(String, String, Color)> rows;
  final Color railColor;

  /// Labels whose value can be tapped to copy (e.g. IP addresses). The copied
  /// text is the raw value; [onCopy] lets the screen show its own feedback.
  final Set<String> copyable;
  final void Function(String value)? onCopy;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: UiSpace.pageCards),
      padding: const EdgeInsets.fromLTRB(40, 6, 18, 6),
      decoration: surfCard(UiRadius.card),
      child: Stack(
        clipBehavior: Clip.none,
        children: [
          Positioned(
            left: -18,
            top: 18,
            bottom: 18,
            child: Container(
              width: 1,
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.topCenter,
                  end: Alignment.bottomCenter,
                  colors: [Ui.fade(railColor, 0.6), Ui.line],
                ),
              ),
            ),
          ),
          Column(
            children: [
              for (final r in rows)
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 13),
                  child: Stack(
                    clipBehavior: Clip.none,
                    alignment: Alignment.centerLeft,
                    children: [
                      Row(
                        children: [
                          Text(r.$1.toUpperCase(), style: UiText.specLabel.copyWith(color: Ui.mute)),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Builder(builder: (context) {
                              final canCopy = copyable.contains(r.$1);
                              final text = Text(
                                canCopy ? breakAddress(r.$2) : r.$2,
                                textAlign: TextAlign.right,
                                // addresses may wrap to a few lines; no clipping
                                maxLines: canCopy ? 4 : 3,
                                overflow: TextOverflow.ellipsis,
                                style: UiText.specValue.copyWith(color: r.$3),
                              );
                              if (!canCopy) return text;
                              return Pressable(
                                semanticLabel: 'Copy ${r.$1}',
                                onTap: () {
                                  Clipboard.setData(ClipboardData(text: r.$2));
                                  onCopy?.call(r.$2);
                                },
                                child: text,
                              );
                            }),
                          ),
                        ],
                      ),
                      Positioned(
                        left: -21.5,
                        child: Container(
                          width: 7,
                          height: 7,
                          decoration: BoxDecoration(
                            color: Ui.bg,
                            shape: BoxShape.circle,
                            border: Border.all(color: r.$3, width: 1.5),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
            ],
          ),
        ],
      ),
    );
  }
}

/// Meta line "HIGH · ANOMALY" + time.
class AlertMetaRow extends StatelessWidget {
  const AlertMetaRow(this.alert, {super.key});

  final SecurityAlert alert;

  @override
  Widget build(BuildContext context) {
    final c = sevColor(alert.severity);
    return Row(
      children: [
        Expanded(
          child: Text(
            '${sevUpper(alert.severity)} · ${kindUpper(alert)}',
            maxLines: 1,
            overflow: TextOverflow.clip,
            style: UiText.alertMeta.copyWith(color: c),
          ),
        ),
        const SizedBox(width: 8),
        Text(TimeFormat.alertTime(alert.time), style: UiText.alertTime.copyWith(color: Ui.mute)),
      ],
    );
  }
}

/// Timeline alert row: glowing severity dot on the left, card on the right.
class TimelineAlertCard extends StatelessWidget {
  const TimelineAlertCard({
    super.key,
    required this.alert,
    required this.onTap,
    this.dotSize = 13,
    this.railWidth = 30,
    this.compact = false,
  });

  final SecurityAlert alert;
  final VoidCallback onTap;
  final double dotSize;
  final double railWidth;

  /// Device-detail variant: smaller title, status as text.
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final c = sevColor(alert.severity);
    return Pressable(
      onTap: onTap,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: railWidth,
            child: Padding(
              padding: const EdgeInsets.only(top: 18),
              child: Center(
                child: Container(
                  width: dotSize,
                  height: dotSize,
                  decoration: BoxDecoration(
                    color: c,
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(color: Ui.bg, spreadRadius: 4),
                      BoxShadow(color: c, blurRadius: 14),
                    ],
                  ),
                ),
              ),
            ),
          ),
          SizedBox(width: compact ? 12 : 14),
          Expanded(
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
              decoration: surfCard(UiRadius.alertCard),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  AlertMetaRow(alert),
                  SizedBox(height: compact ? 3 : 4),
                  Text(alert.title, style: compact ? UiText.recentTitle.copyWith(letterSpacing: 0) : UiText.alertCardTitle),
                  SizedBox(height: compact ? 3 : 4),
                  if (compact && Released.alertManagement)
                    Text(alert.stateLabel, style: UiText.pill.copyWith(color: stateColor(alert)))
                  else if (compact)
                    const SizedBox.shrink()
                  else
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            alert.displayDeviceName,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: UiText.secondary.copyWith(color: Ui.mute),
                          ),
                        ),
                        const SizedBox(width: 8),
                        StatePill(alert),
                      ],
                    ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// Empty state in a dashed box (title + hint, optional action).
class EmptyDashed extends StatelessWidget {
  const EmptyDashed({
    super.key,
    required this.title,
    required this.hint,
    this.radius = UiRadius.card,
    this.padding = const EdgeInsets.symmetric(horizontal: 20, vertical: 28),
    this.titleStyle,
    this.fill,
    this.action,
    this.margin,
  });

  final String title;
  final String hint;
  final double radius;
  final EdgeInsetsGeometry padding;
  final TextStyle? titleStyle;
  final Color? fill;
  final Widget? action;
  final EdgeInsetsGeometry? margin;

  @override
  Widget build(BuildContext context) {
    return DashedBox(
      radius: radius,
      fill: fill,
      margin: margin,
      padding: padding,
      child: SizedBox(
        width: double.infinity,
        child: Column(
          children: [
            Text(title, textAlign: TextAlign.center, style: titleStyle ?? UiText.cardTitle),
            const SizedBox(height: 4),
            Text(
              hint,
              textAlign: TextAlign.center,
              style: UiText.secondary.copyWith(color: Ui.mute),
            ),
            if (action != null) ...[const SizedBox(height: 14), action!],
          ],
        ),
      ),
    );
  }
}

/// Sweep (conic) ring: transparent until [from], [color] peak at [peak], gone at [to].
/// Drawn between [inner] and [outer] radius, rotated by [turns].
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
