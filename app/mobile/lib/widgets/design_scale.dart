import 'package:flutter/material.dart';

/// Scales the whole app so it keeps the design's proportions on any phone.
/// The design is drawn for a 390-wide screen: on a wider phone everything is
/// a little bigger, on a narrower one a little smaller (kept between 90% and
/// 120% so text never becomes too small or too large).
class DesignScale extends StatelessWidget {
  const DesignScale({super.key, required this.child, this.zoom = 1});

  static const double designWidth = 390;

  final Widget child;

  /// Extra zoom chosen in Settings → Text size (design: 1, 1.06, 1.12, 1.2).
  final double zoom;

  @override
  Widget build(BuildContext context) {
    final mq = MediaQuery.of(context);
    final s = (mq.size.width / designWidth).clamp(0.9, 1.2).toDouble() * zoom;
    if ((s - 1).abs() < 0.01) return child;
    return FittedBox(
      fit: BoxFit.contain,
      alignment: Alignment.topLeft,
      child: SizedBox(
        width: mq.size.width / s,
        height: mq.size.height / s,
        child: MediaQuery(
          // Same screen, described in design-size units.
          data: mq.copyWith(
            size: mq.size / s,
            padding: mq.padding / s,
            viewPadding: mq.viewPadding / s,
            viewInsets: mq.viewInsets / s,
            systemGestureInsets: mq.systemGestureInsets / s,
            devicePixelRatio: mq.devicePixelRatio * s,
          ),
          child: child,
        ),
      ),
    );
  }
}
