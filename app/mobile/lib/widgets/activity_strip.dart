import 'dart:math' as math;
import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';
import '../theme/assas_ui.dart';
import 'coming_soon.dart';

class ActivityTrace extends StatelessWidget {
  const ActivityTrace({super.key, required this.activity, required this.connected});
  final LiveActivity? activity;
  final bool connected;
  static bool get _released => false; // Sprint 5
  @override
  Widget build(BuildContext context) {
    final data = activity;
    final ready = connected && data != null && !data.stale && data.samples.isNotEmpty;
    final label = !connected ? 'SIGNAL UNAVAILABLE'
        : data?.stale == true ? 'SIGNAL STALE'
        : !ready ? 'WAITING FOR TRAFFIC DATA'
        : 'LIVE SIGNAL · ${data.samples.last.toStringAsFixed(1)} pkt/s';
    return Container(
      margin: const EdgeInsets.fromLTRB(22, 10, 22, 0),
      height: 58,
      decoration: BoxDecoration(border: Border.symmetric(horizontal: BorderSide(color: Ui.line))),
      child: !_released ? const Align(alignment: Alignment.centerRight, child: SoonTag(5))
        : Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
        const SizedBox(height: 4),
        Text(label, style: UiText.liveSignal.copyWith(color: Ui.mute)),
        Expanded(child: SizedBox.expand(child: ready
          ? CustomPaint(painter: _ActivityPainter(data.samples, Ui.acc))
          : const SizedBox.shrink())),
      ]),
    );
  }
}

class _ActivityPainter extends CustomPainter {
  _ActivityPainter(this.values, this.color);
  final List<double> values;
  final Color color;
  @override
  void paint(Canvas canvas, Size size) {
    if (values.isEmpty) return;
    final maximum = math.max(1.0, values.reduce(math.max));
    final path = Path();
    for (var i = 0; i < values.length; i++) {
      final x = values.length == 1 ? size.width : i * size.width / (values.length - 1);
      final y = size.height - 4 - (values[i] / maximum) * (size.height - 8);
      if (i == 0) { path.moveTo(x, y); } else { path.lineTo(x, y); }
      if (values.length == 1) canvas.drawCircle(Offset(x - 2, y), 2, Paint()..color = color);
    }
    canvas.drawPath(path, Paint()..color = color..style = PaintingStyle.stroke..strokeWidth = 1.5);
  }
  @override
  bool shouldRepaint(_ActivityPainter old) => old.values != values || old.color != color;
}

class ObservedProtocols extends StatelessWidget {
  const ObservedProtocols({super.key, required this.activity, required this.connected});
  final LiveActivity? activity;
  final bool connected;
  @override
  Widget build(BuildContext context) {
    final data = activity;
    final ready = connected && data != null && !data.stale;
    final tags = ready ? data.protocols : const <String>[];
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text('NOW WATCHING · LAST 60s', style: UiText.watchLead.copyWith(color: Ui.acc)),
        const SizedBox(height: 8),
        if (tags.isEmpty) Text(ready ? 'No protocols seen recently' : 'Waiting for capture data',
          style: UiText.watchTag.copyWith(color: Ui.mute)),
        Wrap(spacing: 7, runSpacing: 7, children: [for (final tag in tags)
          Container(padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
            decoration: BoxDecoration(borderRadius: BorderRadius.circular(UiRadius.pill),
              border: Border.all(color: Ui.line), color: Ui.fade(Ui.surf, .82)),
            child: Text(tag, style: UiText.watchTag.copyWith(color: Ui.mute))),
        ]),
      ]),
    );
  }
}
