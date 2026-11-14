import 'package:flutter/material.dart';
import 'theme/assas_ui.dart';

/// Shared release gates: demo data must not present unfinished features as live.
abstract final class FeatureRelease {
  // Sprint 2 (PBI-13/14): Threat Alerts in the mobile app — the Alerts tab,
  // the alert-details screen, and alerts inside device details.
  static bool get alerts => true;
  static bool get risk => false; // Sprint 4
  static bool get baseline => false; // Sprint 3
  // PBI-22 (alert state management) is RELEASED in Sprint 2 (team decision to
  // restore it). Surfaces: the single newest-first alerts list with All/Open/
  // Resolved tabs, the New/Reviewed/Resolved badges, the Review/Resolve actions
  // (New->Reviewed, New->Resolved, Reviewed->Resolved; Resolved terminal), and
  // the live unresolved counter (New+Reviewed) in the hero. State is persisted
  // by the backend and a matching event after Resolved starts a new alert.
  static bool get alertManagement => true;

  // PBI-09/PBI-10 (approved for Sprint 2): unresolved alerts feed the device
  // signals — Attention computation, Home device priority, and the per-row
  // alert-severity accent using the severity palette (never blended with the
  // trust/monitoring colours). Only LINKED alerts count; device_mac NULL ones
  // are attributed to no device.
  static bool get alertSeverityBadges => true;

  // Still-deferred surfaces (NOT part of the PBI-22/PBI-09/10 scope):
  //  - Home (dashboard) open-alerts count + recent-alerts summary (PBI-24),
  //  - the 7-inch display's alert count.
  static bool get alertsHome => false;
  static bool get alertDisplay => false;
  // Plain-language explanations per classtype (Dr. Luluah's decision, Option 2):
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
