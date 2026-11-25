import 'package:flutter/material.dart';

import '../theme/assas_ui.dart';
import 'ui_icons.dart';
import 'ui_kit.dart';

/// Icon-only filter button shared by the Devices and Alerts lists. Fixed size
/// in every state and at every text size, so it never pushes the search field
/// or the tabs around. Active (at least one filter selected): the selected-
/// control accent fill plus a small dot in the top corner. The selection count
/// is only spoken by screen readers, never shown.
class FilterButton extends StatelessWidget {
  const FilterButton({super.key, required this.selected, required this.onTap});

  /// Width and height of the button.
  static const double size = 44;

  /// Number of selected filters; 0 = none (All).
  final int selected;
  final VoidCallback onTap;

  static String semanticsFor(int selected) =>
      'Filter, ${selected == 0 ? 'none' : '$selected'} selected';

  @override
  Widget build(BuildContext context) {
    final active = selected > 0;
    return Pressable(
      onTap: onTap,
      semanticLabel: semanticsFor(selected),
      child: SizedBox.square(
        dimension: size,
        child: Stack(
          children: [
            Glass(
              color: active ? Ui.mix(Ui.acc, .22, Ui.surf) : Ui.fade(Ui.surf, .82),
              border: active ? Ui.mix(Ui.acc, .45, Ui.line) : Ui.line,
              radius: UiRadius.search,
              blur: 16,
              width: size,
              height: size,
              child: Center(child: UiIcon(UiIcons.filter, size: 18, stroke: 2, color: Ui.ink)),
            ),
            if (active)
              // Inside the button's bounds (not clipped by the glass, no growth).
              Positioned(
                key: const ValueKey('filterActiveDot'),
                top: 7,
                right: 7,
                child: Container(
                  width: 9,
                  height: 9,
                  decoration: BoxDecoration(
                    color: Ui.acc,
                    shape: BoxShape.circle,
                    border: Border.all(color: Ui.bg, width: 1.5),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}
