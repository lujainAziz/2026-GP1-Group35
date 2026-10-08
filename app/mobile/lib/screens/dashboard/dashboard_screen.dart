import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../state/app_state.dart';
import '../../widgets/alert_tile.dart';
import '../../widgets/assas_logo.dart';
import '../../widgets/common.dart';
import '../../widgets/purple_header.dart';
import '../alerts/alert_details_screen.dart';

/// Dashboard (PBI-21): risk level, online / total devices, unresolved alerts,
/// unrecognized devices, recent alerts.
class DashboardScreen extends StatelessWidget {
  const DashboardScreen({
    super.key,
    required this.state,
    required this.onOpenDevices,
    required this.onOpenAlerts,
  });

  final AppState state;
  final VoidCallback onOpenDevices;
  final VoidCallback onOpenAlerts;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: state,
      builder: (context, _) {
        return RefreshIndicator(
          onRefresh: state.refresh,
          child: ListView(
            padding: EdgeInsets.zero,
            children: [
              PurpleHeader(
                titleWidget: const Row(
                  children: [
                    AssasLogo(size: 36),
                    SizedBox(width: 10),
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Assas',
                          style: TextStyle(color: Colors.white70, fontSize: 12),
                        ),
                        Text(
                          'Your network',
                          style: TextStyle(
                            color: Colors.white,
                            fontSize: 20,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
                trailing: ConnectionPill(status: state.connection),
                bottom: _RiskCard(risk: state.risk),
              ),
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 16, kBottomNavClearance),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: _StatTile(
                            icon: Icons.devices_rounded,
                            value: '${state.onlineCount}',
                            caption: 'of ${state.totalCount}',
                            label: 'Devices online',
                            tint: BadgeColors.blue,
                            onTap: onOpenDevices,
                          ),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: _StatTile(
                            icon: Icons.notifications_none_rounded,
                            value: state.unresolvedCount?.toString() ?? '–',
                            label: 'Unresolved alerts',
                            tint: BadgeColors.orange,
                            onTap: onOpenAlerts, // PBI-17
                          ),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: _StatTile(
                            icon: Icons.help_outline_rounded,
                            value: '${state.unrecognizedCount}',
                            label: 'Unrecognized',
                            tint: BadgeColors.amber,
                            onTap: onOpenDevices,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 18),
                    SectionTitle(
                      'Recent alerts',
                      actionLabel: (state.alerts?.isNotEmpty ?? false) ? 'See all' : null,
                      onAction: onOpenAlerts,
                    ),
                    const SizedBox(height: 6),
                    ..._recentAlerts(context),
                  ],
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  List<Widget> _recentAlerts(BuildContext context) {
    final alerts = state.alerts;
    if (alerts == null) {
      return const [
        EmptyState(
          icon: Icons.notifications_none_rounded,
          title: 'Alerts are not available yet',
          subtitle: 'Security alerts will appear here once detection is running.',
        ),
      ];
    }
    if (alerts.isEmpty) {
      return const [
        EmptyState(
          icon: Icons.verified_user_outlined,
          title: 'No alerts yet',
          subtitle: 'Assas has not detected any security events.',
        ),
      ];
    }
    return [
      for (final a in alerts.take(2)) ...[
        AlertTile(
          alert: a,
          onTap: () => Navigator.of(context).push(
            MaterialPageRoute(
              builder: (_) => AlertDetailsScreen(state: state, alertId: a.id),
            ),
          ),
        ),
        const SizedBox(height: 10),
      ],
    ];
  }
}

class _RiskCard extends StatelessWidget {
  const _RiskCard({required this.risk});

  final RiskInfo? risk;

  @override
  Widget build(BuildContext context) {
    final available = risk != null;
    final accent = available ? BadgeColors.riskOnPurple(risk!.level) : null;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: Colors.white.withValues(alpha: 0.25)),
      ),
      child: Row(
        children: [
          Container(
            width: 58,
            height: 58,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              border: Border.all(
                color: accent ?? Colors.white54,
                width: 4,
              ),
              color: Colors.white.withValues(alpha: 0.1),
            ),
            child: Icon(
              Icons.shield_outlined,
              color: accent ?? Colors.white70,
              size: 26,
            ),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Network risk level',
                  style: TextStyle(color: Colors.white70, fontSize: 13),
                ),
                const SizedBox(height: 2),
                Text(
                  available ? risk!.level : 'Not available yet',
                  style: TextStyle(
                    color: accent ?? Colors.white,
                    fontSize: available ? 34 : 20,
                    fontWeight: FontWeight.w800,
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

class _StatTile extends StatelessWidget {
  const _StatTile({
    required this.icon,
    required this.value,
    required this.label,
    required this.tint,
    this.caption,
    this.onTap,
  });

  final BadgeColors tint;
  final IconData icon;
  final String value;
  final String label;
  final String? caption;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    return AppCard(
      onTap: onTap,
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 30,
                height: 30,
                decoration: BoxDecoration(
                  color: tint.background,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Icon(icon, size: 17, color: tint.foreground),
              ),
              const SizedBox(width: 8),
              Text(
                value,
                style: AssasText.statValue,
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            label,
            style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600),
          ),
          if (caption != null)
            Text(
              caption!,
              style: TextStyle(fontSize: 11.5, color: AssasColors.muted),
            ),
        ],
      ),
    );
  }
}
