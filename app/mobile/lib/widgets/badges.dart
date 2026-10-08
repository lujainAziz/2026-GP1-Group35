import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

/// Small rounded label (severity, state, Unrecognized...).
class LabelBadge extends StatelessWidget {
  const LabelBadge(this.text, this.colors, {super.key});

  final String text;
  final BadgeColors colors;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: colors.background,
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        text,
        style: TextStyle(
          color: colors.foreground,
          fontSize: 11.5,
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }
}

/// "● Online" / "● Offline" (text + color, not color alone).
class OnlineIndicator extends StatelessWidget {
  const OnlineIndicator({super.key, required this.online, this.onDark = false});

  final bool online;
  final bool onDark;

  @override
  Widget build(BuildContext context) {
    final color = onDark
        ? Colors.white
        : (online ? AssasColors.online : AssasColors.offline);
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 7,
          height: 7,
          decoration: BoxDecoration(
            color: online ? const Color(0xFF34C77B) : AssasColors.offline,
            shape: BoxShape.circle,
          ),
        ),
        const SizedBox(width: 5),
        Text(
          online ? 'Online' : 'Offline',
          style: TextStyle(color: color, fontSize: 12.5, fontWeight: FontWeight.w700),
        ),
      ],
    );
  }
}
