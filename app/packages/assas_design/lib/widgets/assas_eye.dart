import 'dart:async';
import 'dart:math' as math;
import 'dart:ui' as ui;

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';

import '../theme/assas_ui.dart';
import 'ui_kit.dart';

// The ASSAS eye from the design (`AssasEye` in ASSAS.dc.html):
// - open state: the iris layers inside a white aperture, eyelids on top
// - blink: the approved blink frames (1..9) with the live iris behind
// - the iris follows the finger anywhere on screen (eyes 100px and bigger)
// Artwork: assets/images/eye_*.png and blink_frame_*.png (exported from the
// design's SVG files).

const _img = 'packages/assas_design/assets/images/';
const _layers = ['04_left_accent', '05_right_accent', '03_iris_circuit', '06_center_pupil'];

/// Aperture outline: [segment, upper y, lower y] in the 483 x 400 artwork.
const List<List<double>> _shape = [
  [7, 177, 194], [8, 177, 193], [9, 177, 193], [10, 177, 193], [11, 176, 193],
  [12, 175, 194], [13, 174, 194], [14, 172, 196], [15, 170, 197], [16, 168, 199],
  [17, 165, 202], [18, 163, 204], [19, 159, 207], [20, 156, 211], [21, 153, 214],
  [22, 149, 218], [23, 146, 223], [24, 142, 227], [25, 138, 232], [26, 134, 237],
  [27, 130, 244], [28, 126, 249], [29, 122, 255], [30, 119, 260], [31, 115, 262],
  [32, 119, 256], [33, 122, 252], [34, 124, 251], [35, 124, 251], [36, 124, 251],
  [37, 123, 252], [38, 121, 255], [39, 117, 259], [40, 117, 257], [41, 121, 253],
  [42, 123, 251], [43, 124, 251], [44, 124, 251], [45, 123, 252], [46, 121, 255],
  [47, 117, 259], [48, 117, 260], [49, 121, 255], [50, 125, 250], [51, 129, 244],
  [52, 133, 239], [53, 138, 233], [54, 141, 229], [55, 145, 224], [56, 149, 220],
  [57, 153, 216], [58, 156, 212], [59, 159, 209], [60, 162, 206], [61, 164, 203],
  [62, 167, 200], [63, 169, 198], [64, 171, 197], [65, 173, 195], [66, 175, 194],
  [67, 176, 194], [68, 177, 193], [69, 177, 193], [70, 177, 193], [71, 177, 194],
  [72, 176, 195],
];
const double _segW = 483 / 80;
const double _mid = 185.5;

/// How closed the aperture is for each blink frame.
const List<double> _closed = [0, .17, .38, .62, .84, 1, .84, .62, .38, .17, 0];

class AssasEye extends StatefulWidget {
  const AssasEye({super.key, required this.size, this.intro = false});

  final double size;

  /// Splash: starts closed and opens.
  final bool intro;

  @override
  State<AssasEye> createState() => _AssasEyeState();
}

class _AssasEyeState extends State<AssasEye> {
  static bool _precached = false;
  final _rand = math.Random();

  late int _fr = widget.intro && _interactive ? 5 : 0;
  Offset _look = Offset.zero;
  Timer? _timer;
  Timer? _idle;
  bool _dead = false;

  bool get _interactive => widget.size >= 100;

  @override
  void initState() {
    super.initState();
    if (!_interactive) return;
    if (widget.intro) {
      _open();
    } else {
      _schedule(_blink, 1900 + _rand.nextInt(1300));
    }
    GestureBinding.instance.pointerRouter.addGlobalRoute(_onPointer);
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_precached) return;
    _precached = true;
    for (final n in [..._layers, '01_upper_eyelid', '02_lower_eyelid']) {
      precacheImage(AssetImage('${_img}eye_$n.png'), context);
    }
    for (var i = 0; i <= 10; i++) {
      precacheImage(AssetImage('${_img}blink_frame_$i.png'), context);
    }
  }

  @override
  void dispose() {
    _dead = true;
    _timer?.cancel();
    _idle?.cancel();
    if (_interactive) {
      GestureBinding.instance.pointerRouter.removeGlobalRoute(_onPointer);
    }
    super.dispose();
  }

  void _schedule(VoidCallback fn, int ms) {
    _timer?.cancel();
    _timer = Timer(Duration(milliseconds: ms), () {
      if (!_dead && mounted) fn();
    });
  }

  void _frame(int f) {
    if (!_dead && mounted) setState(() => _fr = f);
  }

  /// Same blink cadence as the design.
  void _blink() {
    const frames = [[1, 60], [2, 60], [3, 60], [4, 60], [5, 125], [6, 60], [7, 60], [8, 60], [9, 60]];
    var i = 0;
    void next() {
      if (i >= frames.length) {
        _frame(0);
        _schedule(_blink, 2450 + _rand.nextInt(1850));
        return;
      }
      _frame(frames[i][0]);
      _schedule(() {
        i++;
        next();
      }, frames[i][1]);
    }

    next();
  }

  /// Splash opening.
  void _open() {
    const opening = [[5, 460], [6, 65], [7, 65], [8, 65], [9, 65], [0, 0]];
    var i = 0;
    void next() {
      final f = opening[i][0], ms = opening[i][1];
      _frame(f);
      if (++i < opening.length) {
        _schedule(next, ms);
      } else {
        _schedule(_blink, 2550 + _rand.nextInt(1100));
      }
    }

    next();
  }

  void _onPointer(PointerEvent e) {
    if (e is! PointerMoveEvent && e is! PointerDownEvent && e is! PointerHoverEvent) return;
    if (_dead || !mounted) return;
    final box = context.findRenderObject();
    if (box is! RenderBox || !box.attached || !box.hasSize) return;
    final c = box.localToGlobal(box.size.center(Offset.zero));
    final dx = e.position.dx - c.dx, dy = e.position.dy - c.dy;
    final d = math.max(math.sqrt(dx * dx + dy * dy), 1.0);
    final reach = math.min(1.0, d / 235);
    setState(() => _look = Offset(dx / d * reach, dy / d * reach));
    _idle?.cancel();
    _idle = Timer(const Duration(milliseconds: 2300), () {
      if (!_dead && mounted) setState(() => _look = Offset.zero);
    });
  }

  @override
  Widget build(BuildContext context) {
    final pw = widget.size;
    final ph = (widget.size * 0.6).roundToDouble();
    final w = pw * 1.08;
    final k = w / 483;
    final hh = 400 * k;
    final left = (pw - w) / 2, top = (ph - hh) / 2;
    final decor = widget.size >= 190;
    final dark = Ui.p.brightness == Brightness.dark;

    // `--eyeGl` drop-shadow glow, per mode.
    final glows = dark
        ? const [(Color(0xF2E1CDFF), 2.0), (Color(0xBFB88CFF), 8.0), (Color(0x73B88CFF), 22.0)]
        : const [(Color(0x8C8C5ADC), 2.0), (Color(0x668C5ADC), 8.0), (Color(0x408C5ADC), 22.0)];

    Widget art(String name) => Image.asset(
          '$_img$name.png',
          width: w,
          height: hh,
          fit: BoxFit.fill,
          gaplessPlayback: true,
          filterQuality: FilterQuality.medium,
        );

    Widget inner(double closed) => ClipPath(
          clipper: _ApertureClipper(k, closed),
          child: Stack(
            children: [
              const Positioned.fill(child: ColoredBox(color: Ui.white)),
              TweenAnimationBuilder<Offset>(
                tween: Tween(end: Offset(_look.dx * 20.5 * k, _look.dy * 8.2 * k)),
                duration: const Duration(milliseconds: 180),
                curve: const Cubic(.22, .78, .24, 1),
                builder: (context, off, child) => Transform.translate(offset: off, child: child),
                child: Stack(children: [for (final n in _layers) art('eye_$n')]),
              ),
            ],
          ),
        );

    final silhouette = art('blink_frame_$_fr');

    return SizedBox(
      width: pw,
      height: ph,
      child: Stack(
        clipBehavior: Clip.none,
        children: [
          if (decor)
            Positioned(
              left: 0,
              top: 0,
              width: pw,
              height: ph,
              child: IgnorePointer(
                child: UiClock(
                  builder: (context, t, _) => CustomPaint(
                    painter: _DecorPainter(pw: pw, ph: ph, t: t, acc: Ui.acc),
                  ),
                ),
              ),
            ),
          // Glow behind the eye.
          for (final g in glows)
            Positioned(
              left: left,
              top: top,
              width: w,
              height: hh,
              child: IgnorePointer(
                child: ImageFiltered(
                  imageFilter: ui.ImageFilter.blur(sigmaX: g.$2 / 2, sigmaY: g.$2 / 2),
                  child: ColorFiltered(
                    colorFilter: ColorFilter.mode(g.$1, BlendMode.srcIn),
                    child: silhouette,
                  ),
                ),
              ),
            ),
          Positioned(
            left: left,
            top: top,
            width: w,
            height: hh,
            child: _fr == 0
                ? Stack(children: [
                    inner(0),
                    art('eye_01_upper_eyelid'),
                    art('eye_02_lower_eyelid'),
                  ])
                : Stack(children: [
                    silhouette,
                    if (_fr != 5) inner(_closed[_fr]),
                  ]),
          ),
          // Full closure seal (hides small artifacts in the closed frame).
          if (_fr == 5)
            Positioned(
              left: left + 7 * _segW * k,
              top: top + _mid * k - 3.2 * k,
              width: (73 - 7) * _segW * k,
              height: 6.4 * k,
              child: ClipPath(
                clipper: _SealClipper(),
                child: const ColoredBox(color: Color(0xFF29112F)),
              ),
            ),
        ],
      ),
    );
  }
}

class _ApertureClipper extends CustomClipper<Path> {
  _ApertureClipper(this.k, this.closed);

  final double k;
  final double closed;

  @override
  Path getClip(Size size) {
    final p = Path()..moveTo(7 * _segW * k, _mid * k);
    for (final s in _shape) {
      final y = s[1] + (_mid - s[1]) * closed;
      p.lineTo((s[0] + .5) * _segW * k, y * k);
    }
    p.lineTo(73 * _segW * k, _mid * k);
    for (final s in _shape.reversed) {
      final y = s[2] + (_mid - s[2]) * closed;
      p.lineTo((s[0] + .5) * _segW * k, y * k);
    }
    return p..close();
  }

  @override
  bool shouldReclip(_ApertureClipper old) => old.k != k || old.closed != closed;
}

class _SealClipper extends CustomClipper<Path> {
  static const _pts = [
    [0, 50], [4, 22], [12, 35], [25, 43], [50, 35], [75, 43], [88, 35], [96, 22],
    [100, 50], [96, 78], [88, 65], [75, 57], [50, 65], [25, 57], [12, 65], [4, 78],
  ];

  @override
  Path getClip(Size size) {
    final p = Path();
    for (var i = 0; i < _pts.length; i++) {
      final o = Offset(_pts[i][0] / 100 * size.width, _pts[i][1] / 100 * size.height);
      i == 0 ? p.moveTo(o.dx, o.dy) : p.lineTo(o.dx, o.dy);
    }
    return p..close();
  }

  @override
  bool shouldReclip(_SealClipper old) => false;
}

/// Decor for big eyes: dashed ring (24s) and breathing ring (4.6s).
class _DecorPainter extends CustomPainter {
  _DecorPainter({required this.pw, required this.ph, required this.t, required this.acc});

  final double pw;
  final double ph;
  final double t;
  final Color acc;

  @override
  void paint(Canvas canvas, Size size) {
    final c = Offset(pw / 2, ph / 2);

    // Dashed ring, 78% of the eye width, opacity .55.
    paintDashedCircle(
      canvas,
      c,
      pw * .78 / 2,
      Ui.fade(acc, 0.24 * 0.55),
      turns: loop(t, 24),
    );

    // Breathing ring: radial band 54%..68% of farthest corner, opacity .7.
    final b = wave(t, 4.6);
    final scale = .96 + (1.045 - .96) * b;
    final op = (.38 + (.9 - .38) * b) * .7;
    // CSS percentages are of the farthest corner (r * sqrt2).
    final r = pw * .54 / 2;
    final band = Paint()
      ..shader = RadialGradient(
        colors: [Colors.transparent, Colors.transparent, Ui.fade(acc, 0.07 * op), Colors.transparent],
        stops: const [0, .54 * math.sqrt2, .55 * math.sqrt2, .68 * math.sqrt2],
      ).createShader(Rect.fromCircle(center: c, radius: r * scale));
    canvas.drawCircle(c, r * scale, band);
  }

  @override
  bool shouldRepaint(_DecorPainter old) => old.t != t || old.acc != acc;
}
