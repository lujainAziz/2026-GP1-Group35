import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

/// Purple top area used by every screen: logo purples, soft glow,
/// and a wavy bottom edge.
class PurpleHeader extends StatelessWidget {
  const PurpleHeader({
    super.key,
    this.title,
    this.titleWidget,
    this.backLabel,
    this.trailing,
    this.bottom,
  });

  final String? title;
  final Widget? titleWidget;

  /// Shows "< backLabel" at the top-left (detail screens).
  final String? backLabel;
  final Widget? trailing;

  /// Extra content inside the purple area (search box, risk card...).
  final Widget? bottom;

  @override
  Widget build(BuildContext context) {
    return ClipPath(
      clipper: const WaveBottomClipper(depth: 20),
      child: Container(
        width: double.infinity,
        decoration: BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [
              AssasColors.header.withValues(alpha: 0.95),
              AssasColors.headerDark.withValues(alpha: 0.95),
            ],
          ),
        ),
        child: Stack(
          children: [
            // Soft glows (pink / lilac) like the reference designs
            Positioned(right: -40, top: -50, child: _glow(170, const Color(0xFFF2A9CB))),
            Positioned(left: -50, bottom: -60, child: _glow(160, const Color(0xFFC59ADF))),
            SafeArea(
              bottom: false,
              child: Padding(
                padding: const EdgeInsets.fromLTRB(20, 8, 20, 40),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    if (backLabel != null)
                      InkWell(
                        onTap: () => Navigator.of(context).maybePop(),
                        child: Padding(
                          padding: const EdgeInsets.symmetric(vertical: 6),
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              const Icon(Icons.chevron_left, color: Colors.white, size: 22),
                              Text(
                                backLabel!,
                                style: AssasText.headerBody,
                              ),
                            ],
                          ),
                        ),
                      ),
                    Row(
                      children: [
                        Expanded(
                          child: titleWidget ??
                              Text(
                                title ?? '',
                                style: AssasText.headerTitle,
                              ),
                        ),
                        if (trailing != null) trailing!,
                      ],
                    ),
                    if (bottom != null) ...[
                      const SizedBox(height: 14),
                      bottom!,
                    ],
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _glow(double size, Color color) => IgnorePointer(
        child: Container(
          width: size,
          height: size,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            gradient: RadialGradient(
              colors: [color.withValues(alpha: 0.45), color.withValues(alpha: 0)],
            ),
          ),
        ),
      );
}

/// "● Connected" pill in the header (PBI-09).
class ConnectionPill extends StatelessWidget {
  const ConnectionPill({super.key, required this.status});

  final ConnectionStatus status;

  @override
  Widget build(BuildContext context) {
    final dot = switch (status) {
      ConnectionStatus.live => const Color(0xFF6EE7A8),
      ConnectionStatus.stale => const Color(0xFFFCD34D),
      ConnectionStatus.unreachable => const Color(0xFFFCA5A5),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.18),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: Colors.white.withValues(alpha: 0.35)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 7,
            height: 7,
            decoration: BoxDecoration(color: dot, shape: BoxShape.circle),
          ),
          const SizedBox(width: 6),
          Text(
            status.label,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 12,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }
}
