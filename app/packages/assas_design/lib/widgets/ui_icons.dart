import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

// Icons copied from the design (`ICON` object in ASSAS.dc.html).
// They are 24x24 outline paths: no fill, round caps and joins.

String _n(double v) {
  final s = v.toString();
  return s.endsWith('.0') ? s.substring(0, s.length - 2) : s;
}

/// Rounded rectangle path (same as `rr` in the design).
String _rr(double x, double y, double w, double h, double r) =>
    'M${_n(x + r)},${_n(y)}h${_n(w - 2 * r)}a${_n(r)},${_n(r)} 0 0 1 ${_n(r)},${_n(r)}'
    'v${_n(h - 2 * r)}a${_n(r)},${_n(r)} 0 0 1 -${_n(r)},${_n(r)}h-${_n(w - 2 * r)}'
    'a${_n(r)},${_n(r)} 0 0 1 -${_n(r)},-${_n(r)}v-${_n(h - 2 * r)}'
    'a${_n(r)},${_n(r)} 0 0 1 ${_n(r)},-${_n(r)}z';

/// Circle path (same as `cc` in the design).
String _cc(double x, double y, double r) =>
    'M${_n(x - r)},${_n(y)}a${_n(r)},${_n(r)} 0 1 0 ${_n(2 * r)},0'
    'a${_n(r)},${_n(r)} 0 1 0 -${_n(2 * r)},0';

class UiIcons {
  UiIcons._();

  static final String home =
      'M2.5 12s3.5-6.5 9.5-6.5S21.5 12 21.5 12s-3.5 6.5-9.5 6.5S2.5 12 2.5 12Z${_cc(12, 12, 3)}';
  static final String devices =
      '${_rr(2.5, 4.5, 13, 10, 2)}M6.5 18.5h5${_rr(17.5, 8, 4, 12, 1.2)}';
  static const String alerts = 'M6 16v-5a6 6 0 0 1 12 0v5l1.5 2h-15ZM10 20.5a2.2 2.2 0 0 0 4 0';
  static final String settings = 'M4 7h9M17 7h3M4 17h3M11 17h9${_cc(15, 7, 2)}${_cc(9, 17, 2)}';
  static final String camera =
      'M3 5.5h18M4.5 9h15v1.5a7.5 7.5 0 0 1-15 0Z${_cc(12, 12.5, 2.4)}';
  static final String tv = '${_rr(2.5, 5, 19, 12, 2)}M8 20.5h8';
  static const String plug = 'M9 2.5v4.5M15 2.5v4.5M6 7h12v3.5a6 6 0 0 1-12 0ZM12 16.5v5';
  static final String unknown =
      '${_cc(12, 12, 9)}M9.6 9.3a2.5 2.5 0 0 1 4.8.9c0 1.7-2.4 2.2-2.4 3.8M12 17.2h.01';
  static final String laptop = '${_rr(4.5, 5, 15, 10, 1.5)}M2.5 19h19';
  static final String phone = '${_rr(7, 2.5, 10, 19, 2.5)}M11 18.5h2';
  static final String tablet = '${_rr(4.5, 3, 15, 18, 2.5)}M11 18h2';
  static final String speaker = '${_rr(6, 2.5, 12, 19, 3)}${_cc(12, 14, 3.2)}M12 7h.01';
  static final String qr = '${_rr(3.5, 3.5, 6.5, 6.5, 1)}${_rr(14, 3.5, 6.5, 6.5, 1)}'
      '${_rr(3.5, 14, 6.5, 6.5, 1)}M14 14h2.5v2.5M20.5 14v.01M14 20.5h.01'
      '${_rr(17.5, 17.5, 3, 3, .5)}';

  // Inline icons used in the screens.
  static final String filter = 'M4 7h10M18 7h2M4 17h4M12 17h8${_cc(16, 7, 2)}${_cc(10, 17, 2)}';
  static const String warning =
      'M12 8v5M12 16.5v.01M10.3 3.9 2.6 17.3A2 2 0 0 0 4.3 20.3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z';
  static const String eye =
      'M2.5 12s3.5-6.5 9.5-6.5S21.5 12 21.5 12s-3.5 6.5-9.5 6.5S2.5 12 2.5 12ZM12 9.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5Z';
  static const String chevron = 'M9 5l7 7-7 7';

  /// Device glyph chosen from the device type text.
  static String glyphName(Device d) {
    final t = (d.deviceType ?? '').toLowerCase();
    if (t.isEmpty || t == 'unknown') return 'unknown';
    if (t.contains('tv')) return 'tv';
    if (t.contains('camera')) return 'camera';
    if (t.contains('laptop') || t.contains('computer') || t.contains('pc') || t.contains('desktop')) {
      return 'laptop';
    }
    if (t.contains('tablet')) return 'tablet';
    if (t.contains('mobile') || t.contains('phone')) return 'phone';
    if (t.contains('plug') || t.contains('smart') || t.contains('iot')) return 'plug';
    if (t.contains('speaker') || t.contains('audio')) return 'speaker';
    return 'other';
  }

  static String forDevice(Device d) => switch (glyphName(d)) {
        'tv' => tv,
        'camera' => camera,
        'laptop' => laptop,
        'phone' => phone,
        'tablet' => tablet,
        'plug' => plug,
        'speaker' => speaker,
        'unknown' => unknown,
        _ => devices,
      };

  /// Short label under a device on the dashboard eye.
  static String shortLabel(Device d) => switch (glyphName(d)) {
        'tv' => 'TV',
        'camera' => 'Camera',
        'laptop' => 'Laptop',
        'phone' => 'Phone',
        'tablet' => 'Tablet',
        'plug' => 'Plug',
        'speaker' => 'Speaker',
        'unknown' => 'Unknown',
        _ => d.typeLabel,
      };
}

/// Stroke icon drawn from a 24x24 path string.
class UiIcon extends StatelessWidget {
  const UiIcon(
    this.data, {
    super.key,
    this.size = 20,
    this.stroke = 1.8,
    this.color,
    this.semanticLabel,
  });

  final String data;
  final double size;
  final double stroke;
  final Color? color;

  /// Read by screen readers; null = decorative.
  final String? semanticLabel;

  @override
  Widget build(BuildContext context) {
    final c = color ?? IconTheme.of(context).color ?? DefaultTextStyle.of(context).style.color;
    final icon = SizedBox(
      width: size,
      height: size,
      child: CustomPaint(painter: _IconPainter(svgPath(data), c ?? const Color(0xFF000000), stroke)),
    );
    return semanticLabel == null
        ? ExcludeSemantics(child: icon)
        : Semantics(image: true, label: semanticLabel, child: icon);
  }
}

class _IconPainter extends CustomPainter {
  _IconPainter(this.path, this.color, this.stroke);

  final Path path;
  final Color color;
  final double stroke;

  @override
  void paint(Canvas canvas, Size size) {
    canvas.save();
    canvas.scale(size.width / 24, size.height / 24);
    canvas.drawPath(
      path,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = stroke
        ..strokeCap = StrokeCap.round
        ..strokeJoin = StrokeJoin.round
        ..color = color,
    );
    canvas.restore();
  }

  @override
  bool shouldRepaint(_IconPainter old) =>
      old.path != path || old.color != color || old.stroke != stroke;
}

final Map<String, Path> _cache = {};

/// Minimal SVG path parser (M L H V C S Q A Z, absolute and relative).
Path svgPath(String d) => _cache.putIfAbsent(d, () => _parse(d));

Path _parse(String d) {
  final path = Path();
  final tokens = RegExp(r'[MmLlHhVvCcSsQqAaZz]|-?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?')
      .allMatches(d)
      .map((m) => m.group(0)!)
      .toList();
  final isCmd = RegExp(r'^[A-Za-z]$');

  var i = 0;
  var cmd = '';
  double cx = 0, cy = 0, sx = 0, sy = 0;
  double? lx, ly; // last cubic control point (for S)

  double next() => double.parse(tokens[i++]);

  while (i < tokens.length) {
    if (isCmd.hasMatch(tokens[i])) {
      cmd = tokens[i++];
    } else if (cmd == '' || cmd == 'Z' || cmd == 'z') {
      i++; // stray number, skip
      continue;
    }
    var cubic = false;
    switch (cmd) {
      case 'M':
        cx = next();
        cy = next();
        path.moveTo(cx, cy);
        sx = cx;
        sy = cy;
        cmd = 'L';
      case 'm':
        cx += next();
        cy += next();
        path.moveTo(cx, cy);
        sx = cx;
        sy = cy;
        cmd = 'l';
      case 'L':
        cx = next();
        cy = next();
        path.lineTo(cx, cy);
      case 'l':
        cx += next();
        cy += next();
        path.lineTo(cx, cy);
      case 'H':
        cx = next();
        path.lineTo(cx, cy);
      case 'h':
        cx += next();
        path.lineTo(cx, cy);
      case 'V':
        cy = next();
        path.lineTo(cx, cy);
      case 'v':
        cy += next();
        path.lineTo(cx, cy);
      case 'C':
      case 'c':
        final rel = cmd == 'c';
        final x1 = next() + (rel ? cx : 0), y1 = next() + (rel ? cy : 0);
        final x2 = next() + (rel ? cx : 0), y2 = next() + (rel ? cy : 0);
        final x = next() + (rel ? cx : 0), y = next() + (rel ? cy : 0);
        path.cubicTo(x1, y1, x2, y2, x, y);
        lx = x2;
        ly = y2;
        cx = x;
        cy = y;
        cubic = true;
      case 'S':
      case 's':
        final rel = cmd == 's';
        final x1 = lx != null ? 2 * cx - lx : cx;
        final y1 = ly != null ? 2 * cy - ly : cy;
        final x2 = next() + (rel ? cx : 0), y2 = next() + (rel ? cy : 0);
        final x = next() + (rel ? cx : 0), y = next() + (rel ? cy : 0);
        path.cubicTo(x1, y1, x2, y2, x, y);
        lx = x2;
        ly = y2;
        cx = x;
        cy = y;
        cubic = true;
      case 'Q':
      case 'q':
        final rel = cmd == 'q';
        final x1 = next() + (rel ? cx : 0), y1 = next() + (rel ? cy : 0);
        final x = next() + (rel ? cx : 0), y = next() + (rel ? cy : 0);
        path.quadraticBezierTo(x1, y1, x, y);
        cx = x;
        cy = y;
      case 'A':
      case 'a':
        final rel = cmd == 'a';
        final rx = next(), ry = next(), rot = next();
        final large = next() != 0, sweep = next() != 0;
        final x = next() + (rel ? cx : 0), y = next() + (rel ? cy : 0);
        path.arcToPoint(
          Offset(x, y),
          radius: Radius.elliptical(rx, ry),
          rotation: rot,
          largeArc: large,
          clockwise: sweep,
        );
        cx = x;
        cy = y;
      case 'Z':
      case 'z':
        path.close();
        cx = sx;
        cy = sy;
      default:
        i++;
    }
    if (!cubic) {
      lx = null;
      ly = null;
    }
  }
  return path;
}
