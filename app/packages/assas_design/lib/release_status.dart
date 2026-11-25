import 'package:flutter/material.dart';
import 'theme/assas_ui.dart';

/// Shared release gates: demo data must not present unfinished features as live.
abstract final class FeatureRelease {
  // Sprint 2 (PBI-13/14): Threat Alerts in the mobile app — the Alerts tab,
  // the alert-details screen, and alerts inside device details.
  static bool get alerts => true;
  static bool get risk => false; // Network Alert Level, Sprint 4
  static bool get baseline => false; // Sprint 3
  // PBI-22 (alert state management) is RELEASED. Surfaces: the single
  // newest-first alerts list with All/Open/Resolved tabs, the New/Resolved
  // badges, the Resolve action (New->Resolved; Resolved terminal; Release 1
  // removed Reviewed), and the live unresolved (New) counter in the hero. State
  // is persisted by the backend and a matching event after Resolved starts a
  // new alert.
  static bool get alertManagement => true;

  // PBI-09/PBI-10 (approved for Sprint 2): unresolved alerts feed the device
  // signals — Attention computation, Home device priority, and the per-row
  // alert-severity accent using the severity palette (never blended with the
  // trust/monitoring colours). Only LINKED alerts count; device_mac NULL ones
  // are attributed to no device.
  static bool get alertSeverityBadges => true;

  // Phone Home (dashboard) "Unresolved alerts" card (Release 1): the DB count
  // from GET /alerts/open_count, "No unresolved alerts" at 0, "Last known" /
  // "—" on failure (same as the display).
  static bool get alertsHome => true;
  // Still deferred: the Home recent-alerts summary, part of the Home
  // network-status summary (PBI-26, Sprint 5).
  static bool get alertsHomeRecent => false;
  // The 7-inch display's "Unresolved alerts" card (Sprint 2 feature, released in
  // Release 1): the DB count of New alerts from GET /alerts/open_count, read as a
  // local caller (no pairing needed on the appliance itself).
  static bool get alertDisplay => true;
  // Plain-language explanations per classtype (Sprint 2 decision, Option 2):
  // the "What happened" block with the explanation and device role line.
  static bool get alertExplanations => true;
}

class SoonTag extends StatelessWidget {
  const SoonTag(this.sprint, {super.key});
  final int sprint;
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
    decoration: BoxDecoration(color: Ui.fade(Ui.acc, .14),
      borderRadius: BorderRadius.circular(UiRadius.pill),
      border: Border.all(color: Ui.fade(Ui.acc, .35))),
    child: Text('SOON · SPRINT $sprint', style: UiText.mono(9.5, 600, em: .12, color: Ui.acc)),
  );
}
