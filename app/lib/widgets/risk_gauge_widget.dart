import 'dart:math' as math;
import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

class RiskGaugeWidget extends StatelessWidget {
  final int riskScore; // 0 to 100

  const RiskGaugeWidget({
    Key? key,
    required this.riskScore,
  }) : super(key: key);

  Color _getRiskColor(int score) {
    if (score < 35) return AppColors.statusSafe;
    if (score < 70) return AppColors.statusWarning;
    return AppColors.statusDanger;
  }

  String _getRiskStatusLabel(int score) {
    if (score < 35) return "NORMAL • SECURE";
    if (score < 70) return "WARNING • SUSPICIOUS";
    return "CRITICAL • ALERT";
  }

  @override
  Widget build(BuildContext context) {
    final targetColor = _getRiskColor(riskScore);
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          SizedBox(
            width: 220,
            height: 220,
            child: Stack(
              alignment: Alignment.center,
              children: [
                // 1. Dynamic Animated Circular Gauge Track
                TweenAnimationBuilder<double>(
                  tween: Tween<double>(begin: 0.0, end: riskScore / 100.0),
                  duration: const Duration(milliseconds: 900),
                  curve: Curves.easeOutCubic,
                  builder: (context, value, child) {
                    return CustomPaint(
                      size: const Size(220, 220),
                      painter: _CircularGaugePainter(
                        progress: value,
                        activeColor: targetColor,
                        trackColor: isDark
                            ? Colors.white.withOpacity(0.08)
                            : AppColors.darkPurpleBase.withOpacity(0.08),
                      ),
                    );
                  },
                ),

                // 2. Soft Aura Ambient Glow behind the Eye Core
                TweenAnimationBuilder<Color?>(
                  tween: ColorTween(begin: AppColors.mediumPurple, end: targetColor),
                  duration: const Duration(milliseconds: 600),
                  curve: Curves.easeInOut,
                  builder: (context, animatedColor, child) {
                    return Container(
                      width: 95,
                      height: 95,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        boxShadow: [
                          BoxShadow(
                            color: (animatedColor ?? targetColor).withOpacity(0.35),
                            blurRadius: 28,
                            spreadRadius: 4,
                          ),
                        ],
                      ),
                    );
                  },
                ),

                // 3. High-Intensity Dynamic Eye Color Filter (Lifts Blacks & Tints Eyelashes)
                TweenAnimationBuilder<Color?>(
                  tween: ColorTween(begin: AppColors.mediumPurple, end: targetColor),
                  duration: const Duration(milliseconds: 600),
                  curve: Curves.easeInOut,
                  builder: (context, animatedColor, child) {
                    final activeColor = animatedColor ?? targetColor;
                    return Container(
                      width: 105,
                      height: 105,
                      padding: const EdgeInsets.all(4),
                      child: Tooltip(
                        message: "Assas Threat Core: ${_getRiskStatusLabel(riskScore)}",
                        // Layered filter: softly lifts the blacks and intensely tints the eye/eyelashes
                        child: ColorFiltered(
                          colorFilter: ColorFilter.mode(
                            activeColor.withOpacity(0.88),
                            BlendMode.srcATop,
                          ),
                          child: Image.asset(
                            'assets/images/logo_eye.png',
                            fit: BoxFit.contain,
                          ),
                        ),
                      ),
                    );
                  },
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),

          // Numeric Score
          Text(
            "$riskScore / 100",
            style: TextStyle(
              fontSize: 24,
              fontWeight: FontWeight.bold,
              color: isDark ? Colors.white : AppColors.darkPurpleBase,
            ),
          ),
          const SizedBox(height: 6),

          // Status Badge
          AnimatedContainer(
            duration: const Duration(milliseconds: 400),
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 5),
            decoration: BoxDecoration(
              color: targetColor.withOpacity(0.12),
              borderRadius: BorderRadius.circular(20),
              border: Border.all(color: targetColor.withOpacity(0.4), width: 1),
            ),
            child: Text(
              _getRiskStatusLabel(riskScore),
              style: TextStyle(
                color: targetColor,
                fontWeight: FontWeight.w700,
                fontSize: 11.5,
                letterSpacing: 0.8,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _CircularGaugePainter extends CustomPainter {
  final double progress;
  final Color activeColor;
  final Color trackColor;

  _CircularGaugePainter({
    required this.progress,
    required this.activeColor,
    required this.trackColor,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = (size.width - 22) / 2;
    const strokeWidth = 12.0;
    const startAngle = -math.pi / 2;
    const sweepTotal = 2 * math.pi;

    final trackPaint = Paint()
      ..color = trackColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.round;

    canvas.drawCircle(center, radius, trackPaint);

    final activePaint = Paint()
      ..color = activeColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.round;

    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      startAngle,
      sweepTotal * progress,
      false,
      activePaint,
    );
  }

  @override
  bool shouldRepaint(covariant _CircularGaugePainter oldDelegate) {
    return oldDelegate.progress != progress ||
        oldDelegate.activeColor != activeColor ||
        oldDelegate.trackColor != trackColor;
  }
}