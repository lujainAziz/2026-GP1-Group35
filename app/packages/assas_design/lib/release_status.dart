import 'package:flutter/material.dart';
import 'theme/assas_ui.dart';

/// Shared release gates: demo data must not present unfinished features as live.
abstract final class FeatureRelease {
  static bool get alerts => false; // Sprint 2 / 3
  static bool get risk => false; // Sprint 4
  static bool get baseline => false; // Sprint 3
  static bool get alertManagement => false; // Sprint 5
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
