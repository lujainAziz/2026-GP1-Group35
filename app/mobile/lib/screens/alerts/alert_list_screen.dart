import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../state/app_state.dart';
import '../../widgets/alert_tile.dart';
import '../../widgets/common.dart';
import '../../widgets/purple_header.dart';
import 'alert_details_screen.dart';

/// One list for Threat and Anomaly alerts, newest first (PBI-19).
class AlertListScreen extends StatelessWidget {
  const AlertListScreen({super.key, required this.state});

  final AppState state;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: state,
      builder: (context, _) {
        final alerts = state.alerts;
        return Column(
          children: [
            PurpleHeader(
              title: 'Alerts',
              trailing: ConnectionPill(status: state.connection),
              bottom: Center(
                child: Container(
                  width: 150,
                  padding: const EdgeInsets.symmetric(vertical: 10),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.14),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(color: Colors.white.withValues(alpha: 0.25)),
                  ),
                  child: Column(
                    children: [
                      Text(
                        state.unresolvedCount?.toString() ?? '–',
                        style: AssasText.headerTitle,
                      ),
                      const Text(
                        'Unresolved',
                        style: AssasText.headerBody,
                      ),
                    ],
                  ),
                ),
              ),
            ),
            Expanded(
              child: RefreshIndicator(
                onRefresh: state.refresh,
                child: _body(context, alerts),
              ),
            ),
          ],
        );
      },
    );
  }

  Widget _body(BuildContext context, List<SecurityAlert>? alerts) {
    if (!state.loadedOnce) {
      return const Center(child: CircularProgressIndicator());
    }
    if (alerts == null || alerts.isEmpty) {
      return ListView(
        padding: const EdgeInsets.all(16),
        children: [
          alerts == null
              ? const EmptyState(
                  icon: Icons.notifications_none_rounded,
                  title: 'Alerts are not available yet',
                  subtitle: 'Threat and anomaly alerts will appear here once detection is running.',
                )
              : const EmptyState(
                  icon: Icons.verified_user_outlined,
                  title: 'No alerts yet',
                  subtitle: 'Assas has not detected any security events.',
                ),
        ],
      );
    }
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, kBottomNavClearance),
      children: [
        Padding(
          padding: EdgeInsets.only(left: 4, bottom: 8),
          child: Text(
            'Newest first',
            style: AssasText.mutedLabel,
          ),
        ),
        for (final a in alerts) ...[
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
      ],
    );
  }
}
