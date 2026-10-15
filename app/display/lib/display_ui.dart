import 'package:flutter/material.dart';
import 'package:assas_core/assas_core.dart';
import 'package:assas_design/theme/assas_ui.dart';
import 'package:assas_design/widgets/assas_mobile_background.dart';
import 'package:assas_design/widgets/ui_kit.dart' show glassCard, surfCard;

/// Landscape adaptation of the supplied ASSAS design tokens.
abstract final class DisplayUi {
  static const bg = Color(0xFF0F0B16);
  static const surface = Color(0xFF18121F);
  static const raised = Color(0xFF231B2E);
  static const line = Color(0x17FFFFFF);
  static const ink = Color(0xFFF4EFF9);
  static const mute = Color(0xFFA99EB8);
  static const accent = Color(0xFFB88CFF);
  static const green = Color(0xFF5FDDA8);
  static const amber = Color(0xFFF2C14E);
  static const red = Color(0xFFFF6B81);

  static TextStyle sans(double size, {Color color = ink, FontWeight weight = FontWeight.w700}) =>
      TextStyle(fontFamily: 'Bricolage Grotesque', fontSize: size, color: color, fontWeight: weight, height: 1.1);
  static TextStyle mono(double size, {Color color = mute}) => TextStyle(
      fontFamily: 'JetBrains Mono', fontSize: size, color: color, letterSpacing: 1, height: 1.4);

  static BoxDecoration card({Color color = surface, double radius = 26}) =>
      color == surface ? glassCard(radius) : surfCard(radius, color: color);

  static ThemeData get theme {
    AssasColors.useDark(true);
    return MobileTheme.dark;
  }
}

/// The phone's background, with a little more ambient light for landscape.
class DisplayBackground extends StatelessWidget {
  const DisplayBackground({super.key, required this.child});
  final Widget child;

  @override
  Widget build(BuildContext context) => AssasMobileBackground(ambientStrength: 1.7, child: child);
}

class DisplayFrame extends StatelessWidget {
  const DisplayFrame({super.key, required this.child});
  final Widget child;
  @override
  Widget build(BuildContext context) => CustomPaint(
    foregroundPainter: const _FramePainter(), child: child);
}

class _FramePainter extends CustomPainter {
  const _FramePainter();
  @override
  void paint(Canvas canvas, Size size) {
    final p = Paint()..style = PaintingStyle.stroke..strokeWidth = 1.3;
    final top = Path()..moveTo(16, 64)..lineTo(16, 38)
      ..quadraticBezierTo(16, 16, 38, 16)..lineTo(64, 16);
    canvas.drawPath(top, p..color = DisplayUi.accent.withValues(alpha: .55));
    final bottom = Path()..moveTo(size.width - 64, size.height - 16)
      ..lineTo(size.width - 38, size.height - 16)
      ..quadraticBezierTo(size.width - 16, size.height - 16, size.width - 16, size.height - 38)
      ..lineTo(size.width - 16, size.height - 64);
    canvas.drawPath(bottom, p..color = DisplayUi.green.withValues(alpha: .3));
  }
  @override
  bool shouldRepaint(_FramePainter oldDelegate) => false;
}

