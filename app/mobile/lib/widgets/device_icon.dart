import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

/// Icon box chosen from the device type text (e.g. "Mobile (Apple)", "Camera").
/// Each type keeps its own color so the list is easy to scan.
class DeviceIcon extends StatelessWidget {
  const DeviceIcon({super.key, required this.device, this.size = 44});

  final Device device;
  final double size;

  @override
  Widget build(BuildContext context) {
    final (icon, colors) = _style(device);
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(size * 0.3),
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [AssasColors.iconBoxTop, colors.background],
        ),
        border: Border.all(color: AssasColors.border, width: 1),
      ),
      child: Icon(icon, color: colors.foreground, size: size * 0.5),
    );
  }

  static (IconData, BadgeColors) _style(Device d) {
    final t = (d.deviceType ?? '').toLowerCase();
    if (t.isEmpty) return (Icons.question_mark_rounded, BadgeColors.amber);
    if (t.contains('tv')) return (Icons.tv_rounded, BadgeColors.purple);
    if (t.contains('camera')) return (Icons.videocam_outlined, BadgeColors.blue);
    if (t.contains('laptop') || t.contains('computer') || t.contains('pc') || t.contains('desktop')) {
      return (Icons.laptop_mac_rounded, BadgeColors.green);
    }
    if (t.contains('mobile') || t.contains('phone') || t.contains('tablet')) {
      return (Icons.smartphone_rounded, BadgeColors.pink);
    }
    if (t.contains('printer')) return (Icons.print_outlined, BadgeColors.slate);
    if (t.contains('router') || t.contains('gateway') || t.contains('access point') || t.contains('switch')) {
      return (Icons.router_outlined, BadgeColors.teal);
    }
    if (t.contains('plug') || t.contains('smart') || t.contains('iot')) {
      return (Icons.power_outlined, BadgeColors.orange);
    }
    if (t.contains('speaker') || t.contains('audio')) return (Icons.speaker_outlined, BadgeColors.purple);
    if (t.contains('console') || t.contains('game')) return (Icons.sports_esports_outlined, BadgeColors.blue);
    return (Icons.devices_other_rounded, BadgeColors.slate);
  }
}
