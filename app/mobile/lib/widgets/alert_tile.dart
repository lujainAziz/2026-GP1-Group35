import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import 'badges.dart';
import 'common.dart';

/// One alert row (Dashboard "Recent alerts" and the Alerts list).
class AlertTile extends StatelessWidget {
  const AlertTile({super.key, required this.alert, this.onTap});

  final SecurityAlert alert;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final sev = alert.severityColors;
    return AppCard(
      onTap: onTap,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              color: sev.background,
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(
              alert.kind == AlertKind.threat
                  ? Icons.gpp_maybe_outlined
                  : Icons.insights_outlined,
              color: sev.foreground,
              size: 22,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        alert.kindLabel,
                        style: TextStyle(
                          color: AssasColors.primary,
                          fontSize: 12.5,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ),
                    Text(
                      TimeFormat.alertTime(alert.time),
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        color: AssasColors.muted,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 2),
                Text(
                  alert.title,
                  style: AssasText.cardTitle,
                ),
                const SizedBox(height: 2),
                Text(
                  alert.deviceName,
                  style: AssasText.caption,
                ),
                const SizedBox(height: 8),
                Row(
                  children: [
                    LabelBadge(alert.severityLabel, sev),
                    const Spacer(),
                    LabelBadge(alert.stateLabel, alert.stateColors),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
