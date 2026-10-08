import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../state/app_state.dart';
import '../../widgets/badges.dart';
import '../../widgets/common.dart';
import '../../widgets/purple_header.dart';

/// Alert details: severity, state, plain-language explanation (PBI-18),
/// affected device, and review / resolve actions (PBI-19).
/// No raw SHAP values, model scores, or feature names are shown.
class AlertDetailsScreen extends StatefulWidget {
  const AlertDetailsScreen({super.key, required this.state, required this.alertId});

  final AppState state;
  final String alertId;

  @override
  State<AlertDetailsScreen> createState() => _AlertDetailsScreenState();
}

class _AlertDetailsScreenState extends State<AlertDetailsScreen> {
  bool _saving = false;

  Future<void> _setState(AlertState s) async {
    setState(() => _saving = true);
    try {
      await widget.state.setAlertState(widget.alertId, s);
    } catch (_) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Could not update the alert. Try again.')),
      );
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: ListenableBuilder(
        listenable: widget.state,
        builder: (context, _) {
          final a = widget.state.alertById(widget.alertId);
          if (a == null) {
            return Column(
              children: [
                const PurpleHeader(backLabel: 'Alerts', title: 'Alert'),
                const Padding(
                  padding: EdgeInsets.all(16),
                  child: EmptyState(
                    icon: Icons.search_off_rounded,
                    title: 'Alert not found',
                    subtitle: 'This alert is no longer available.',
                  ),
                ),
              ],
            );
          }
          return ListView(
            padding: EdgeInsets.zero,
            children: [
              PurpleHeader(
                backLabel: 'Alerts',
                titleWidget: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        LabelBadge(a.severityLabel, a.severityColors),
                        const SizedBox(width: 8),
                        LabelBadge(a.stateLabel, a.stateColors),
                      ],
                    ),
                    const SizedBox(height: 10),
                    Text(
                      '${a.title} on ${a.deviceName}',
                      style: AssasText.headerTitleSmall,
                    ),
                    const SizedBox(height: 6),
                    Text(
                      '${a.kindLabel}, ${TimeFormat.alertTimePhrase(a.time)}',
                      style: AssasText.headerBody,
                    ),
                  ],
                ),
              ),
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    _whatHappened(a),
                    const SizedBox(height: 12),
                    AppCard(
                      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                      child: Column(
                        children: [
                          InfoRow('Device', a.deviceName),
                          const Divider(height: 1),
                          InfoRow('Alert type', a.kindLabel),
                          const Divider(height: 1),
                          InfoRow(
                            'Severity',
                            a.severityLabel,
                            valueColor: a.severityColors.foreground,
                          ),
                          // Threat alerts only (PBI-11)
                          if (a.kind == AlertKind.threat && a.sourceIp != null) ...[
                            const Divider(height: 1),
                            InfoRow('Source IP', a.sourceIp!),
                          ],
                          if (a.kind == AlertKind.threat && a.destinationIp != null) ...[
                            const Divider(height: 1),
                            InfoRow('Destination IP', a.destinationIp!),
                          ],
                        ],
                      ),
                    ),
                    const SizedBox(height: 16),
                    Row(
                      children: [
                        Expanded(
                          child: FilledButton(
                            onPressed: _saving || a.state != AlertState.newAlert
                                ? null
                                : () => _setState(AlertState.reviewed),
                            child: const Text('Mark as reviewed'),
                          ),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: OutlinedButton(
                            onPressed: _saving || a.state == AlertState.resolved
                                ? null
                                : () => _setState(AlertState.resolved),
                            child: const Text('Mark as resolved'),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ],
          );
        },
      ),
    );
  }

  Widget _whatHappened(SecurityAlert a) {
    final note = a.displayNote;
    return AppCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 28,
                height: 28,
                decoration: BoxDecoration(
                  color: AssasColors.tintPurple,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Icon(Icons.info_outline, size: 17, color: AssasColors.primary),
              ),
              const SizedBox(width: 10),
              Text(
                'What happened',
                style: AssasText.cardTitle,
              ),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            a.explanation ?? 'A plain-language explanation is not available for this alert yet.',
            style: const TextStyle(fontSize: 14.5, fontWeight: FontWeight.w600, height: 1.4),
          ),
          if (note != null) ...[
            const SizedBox(height: 12),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AssasColors.tintPurple,
                borderRadius: BorderRadius.circular(10),
              ),
              child: Text(
                note,
                style: TextStyle(fontSize: 13, color: AssasColors.ink, height: 1.35),
              ),
            ),
          ],
        ],
      ),
    );
  }
}
