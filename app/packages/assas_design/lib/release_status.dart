import 'package:flutter/material.dart';
import 'theme/assas_ui.dart';

/// Shared release gates: demo data must not present unfinished features as live.
abstract final class FeatureRelease {
  // Sprint 2 (PBI-13/14): Threat Alerts in the mobile app — the Alerts tab,
  // the alert-details screen, and alerts inside device details.
  static bool get alerts => true;
  static bool get risk => false; // Sprint 4
  static bool get baseline => false; // Sprint 3
  // PBI-22 (alert state management) moved into Sprint 2: New/Reviewed/Resolved
  // transitions, the Open/Resolved tabs, and the Review/Resolve actions. This
  // flag is independent of the deferred Home surfaces below.
  static bool get alertManagement => true;

  // Later-sprint surfaces kept hidden even though `alerts` + `alertManagement`
  // are live (PBI-24 and friends are NOT part of the PBI-22 move):
  //  - Home (dashboard) open-alerts count + recent-alerts summary,
  //  - device-list per-row alert-severity badges / alert-based sorting,
  //  - the 7-inch display's alert count.
  static bool get alertsHome => false;
  static bool get alertSeverityBadges => false;
  static bool get alertDisplay => false;
  // Plain-language explanations are a later sprint; hidden here (explanation is
  // NULL for Sprint 2 threat alerts).
  static bool get alertExplanations => false;
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
