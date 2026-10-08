import 'dart:ui';

import 'package:flutter/material.dart';

import 'assas_colors.dart';

/// Frosted glass card: see-through, blurred, white edge, raised with a soft shadow.
///
/// [blur] = false skips the blur (cheaper; used on the Raspberry Pi screen).
class GlassCard extends StatelessWidget {
  const GlassCard({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(14),
    this.radius = 20,
    this.onTap,
    this.blur = true,
    this.opacity = 0.55,
    this.elevated = true,
  });

  final Widget child;
  final EdgeInsets padding;
  final double radius;
  final VoidCallback? onTap;
  final bool blur;

  /// How white the glass is (0 = clear, 1 = solid white).
  final double opacity;
  final bool elevated;

  @override
  Widget build(BuildContext context) {
    final r = BorderRadius.circular(radius);
    final top = (opacity + 0.15).clamp(0.0, 1.0).toDouble();
    final bottom = (opacity - 0.1).clamp(0.0, 1.0).toDouble();

    Widget surface = Container(
      decoration: BoxDecoration(
        borderRadius: r,
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            AssasColors.card.withValues(alpha: top),
            AssasColors.card.withValues(alpha: bottom),
          ],
        ),
        border: Border.all(color: AssasColors.border, width: 1),
      ),
      child: Material(
        type: MaterialType.transparency,
        child: InkWell(
          borderRadius: r,
          onTap: onTap,
          child: Padding(padding: padding, child: child),
        ),
      ),
    );

    if (blur) {
      surface = BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 16, sigmaY: 16),
        child: surface,
      );
    }

    return DecoratedBox(
      decoration: BoxDecoration(
        borderRadius: r,
        boxShadow: elevated
            ? [
                BoxShadow(
                  color: AssasColors.shadow,
                  blurRadius: 24,
                  offset: const Offset(0, 10),
                ),
              ]
            : null,
      ),
      child: ClipRRect(borderRadius: r, child: surface),
    );
  }
}
