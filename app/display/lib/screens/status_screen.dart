import 'dart:async';

import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../config/data_source.dart';
import 'pairing_qr.dart';

/// Glanceable status for the 7-inch screen (1024 x 600):
/// network risk level, devices online, unresolved alerts, system status,
/// and the rotating pairing QR code.
class StatusScreen extends StatefulWidget {
  const StatusScreen({super.key});

  @override
  State<StatusScreen> createState() => _StatusScreenState();
}

class _StatusScreenState extends State<StatusScreen> {
  ConnectionStatus _status = ConnectionStatus.live;
  RiskInfo? _risk;
  int? _online;
  int? _total;
  int? _unresolved;
  bool _alertsAvailable = false;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _refresh();
    _timer = Timer.periodic(const Duration(seconds: 5), (_) => _refresh());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _refresh() async {
    final status = await repository.checkHealth();
    RiskInfo? risk = _risk;
    int? online = _online, total = _total, unresolved = _unresolved;
    bool alertsAvailable = _alertsAvailable;

    try {
      final devices = await repository.getDevices();
      online = devices.where((d) => d.isOnline).length;
      total = devices.length;
    } catch (_) {}
    try {
      final alerts = await repository.getAlerts();
      alertsAvailable = alerts != null;
      unresolved = alerts?.where((a) => a.isUnresolved).length;
    } catch (_) {}
    try {
      risk = await repository.getRiskLevel();
    } catch (_) {}

    if (!mounted) return;
    setState(() {
      _status = status;
      _risk = risk;
      _online = online;
      _total = total;
      _unresolved = unresolved;
      _alertsAvailable = alertsAvailable;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.transparent,
      body: Padding(
        padding: const EdgeInsets.all(20),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Expanded(flex: 3, child: _leftPanel()),
            const SizedBox(width: 20),
            const Expanded(flex: 2, child: PairingQrPanel()),
          ],
        ),
      ),
    );
  }

  Widget _leftPanel() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Header: logo + system status
        Row(
          children: [
            Container(
              width: 44,
              height: 44,
              padding: const EdgeInsets.all(5),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AssasColors.border),
                boxShadow: [BoxShadow(color: AssasColors.shadow, blurRadius: 16, offset: Offset(0, 6))],
              ),
              child: Image.asset(
                'assets/images/logo_eye.png',
                errorBuilder: (_, __, ___) =>
                    Icon(Icons.shield_outlined, color: AssasColors.primary),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                'ASSAS',
                style: TextStyle(
                  fontSize: 22,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 3,
                  color: AssasColors.ink,
                ),
              ),
            ),
            _SystemStatusPill(status: _status),
          ],
        ),
        const SizedBox(height: 16),
        Expanded(flex: 3, child: _riskCard()),
        const SizedBox(height: 16),
        Expanded(
          flex: 2,
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Expanded(
                child: _Tile(
                  icon: Icons.devices_rounded,
                  value: _online?.toString() ?? '–',
                  caption: _total == null ? null : 'of $_total',
                  label: 'Devices online',
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: _Tile(
                  icon: Icons.notifications_none_rounded,
                  value: _alertsAvailable ? (_unresolved?.toString() ?? '–') : '–',
                  caption: _alertsAvailable ? null : 'Not available yet',
                  label: 'Unresolved alerts',
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _riskCard() {
    final risk = _risk;
    final accent = risk == null ? null : BadgeColors.riskOnPurple(risk.level);
    return Container(
      clipBehavior: Clip.antiAlias,
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [AssasColors.header, AssasColors.headerDark],
        ),
        borderRadius: BorderRadius.circular(24),
        boxShadow: [BoxShadow(color: AssasColors.shadow, blurRadius: 24, offset: Offset(0, 10))],
      ),
      child: Stack(
        fit: StackFit.expand,
        children: [
          // soft pink glow + white wave inside the card
          Positioned(
            right: -60,
            top: -60,
            child: Container(
              width: 220,
              height: 220,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: RadialGradient(colors: [
                  const Color(0xFFF2A9CB).withValues(alpha: 0.45),
                  const Color(0xFFF2A9CB).withValues(alpha: 0),
                ]),
              ),
            ),
          ),
          Positioned.fill(
            child: ClipPath(
              clipper: const _InverseWave(),
              child: Container(color: Colors.white.withValues(alpha: 0.08)),
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(24),
            child: Row(
        children: [
          Container(
            width: 96,
            height: 96,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              border: Border.all(color: accent ?? Colors.white54, width: 6),
              color: Colors.white.withValues(alpha: 0.1),
            ),
            child: Icon(
              Icons.shield_outlined,
              size: 44,
              color: accent ?? Colors.white70,
            ),
          ),
          const SizedBox(width: 24),
          Expanded(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Network risk level',
                  style: TextStyle(color: Colors.white70, fontSize: 20),
                ),
                const SizedBox(height: 4),
                FittedBox(
                  fit: BoxFit.scaleDown,
                  alignment: Alignment.centerLeft,
                  child: Text(
                    risk?.level ?? 'Not available yet',
                    style: TextStyle(
                      color: accent ?? Colors.white,
                      fontSize: risk == null ? 30 : 56,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
          ),
        ],
      ),
    );
  }
}

/// Bottom half wave used inside the risk card.
class _InverseWave extends CustomClipper<Path> {
  const _InverseWave();

  @override
  Path getClip(Size size) {
    final w = size.width, h = size.height;
    return Path()
      ..moveTo(0, h * 0.62)
      ..cubicTo(w * 0.3, h * 0.45, w * 0.6, h * 0.85, w, h * 0.6)
      ..lineTo(w, h)
      ..lineTo(0, h)
      ..close();
  }

  @override
  bool shouldReclip(covariant CustomClipper<Path> oldClipper) => false;
}

class _SystemStatusPill extends StatelessWidget {
  const _SystemStatusPill({required this.status});

  final ConnectionStatus status;

  @override
  Widget build(BuildContext context) {
    final (label, color) = switch (status) {
      ConnectionStatus.live => ('System running', AssasColors.online),
      ConnectionStatus.stale => ('Data may be outdated', AssasColors.warningFg),
      ConnectionStatus.unreachable => ('System offline', AssasColors.danger),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.6),
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: AssasColors.border),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 10,
            height: 10,
            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
          ),
          const SizedBox(width: 8),
          Text(
            label,
            style: TextStyle(color: color, fontWeight: FontWeight.w700, fontSize: 15),
          ),
        ],
      ),
    );
  }
}

class _Tile extends StatelessWidget {
  const _Tile({
    required this.icon,
    required this.value,
    required this.label,
    this.caption,
  });

  final IconData icon;
  final String value;
  final String label;
  final String? caption;

  @override
  Widget build(BuildContext context) {
    return GlassCard(
      blur: false, // cheaper on the Raspberry Pi
      opacity: 0.65,
      padding: const EdgeInsets.all(18),
      child: Row(
        children: [
          Container(
            width: 52,
            height: 52,
            decoration: BoxDecoration(
              color: AssasColors.tintPurple,
              borderRadius: BorderRadius.circular(14),
            ),
            child: Icon(icon, color: AssasColors.primary, size: 28),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    Text(
                      value,
                      style: const TextStyle(fontSize: 38, fontWeight: FontWeight.w800),
                    ),
                    if (caption != null) ...[
                      const SizedBox(width: 6),
                      Flexible(
                        child: Padding(
                          padding: const EdgeInsets.only(bottom: 7),
                          child: Text(
                            caption!,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(fontSize: 14, color: AssasColors.muted),
                          ),
                        ),
                      ),
                    ],
                  ],
                ),
                Text(
                  label,
                  style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
