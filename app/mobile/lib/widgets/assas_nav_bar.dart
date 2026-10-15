import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../theme/assas_ui.dart';
import 'ui_icons.dart';
import 'ui_kit.dart';

/// Floating glass tab bar (`.assas-nav`). The active tab is an accent pill
/// with its label; the Alerts tab shows the count of New alerts.
class AssasNavBar extends StatelessWidget {
  const AssasNavBar({
    super.key,
    required this.index,
    required this.onSelect,
    required this.unread,
  });

  final int index;
  final ValueChanged<int> onSelect;
  final int unread;

  static final _tabs = [
    (UiIcons.home, 'Home'),
    (UiIcons.devices, 'Devices'),
    (UiIcons.alerts, 'Alerts'),
    (UiIcons.settings, 'Settings'),
  ];

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      height: 66,
      child: Stack(
        clipBehavior: Clip.none,
        children: [
          Positioned.fill(
            child: Glass(
              color: Ui.fade(Ui.surf2, 0.82),
              radius: UiRadius.nav,
              blur: 18,
              shadows: UiShadow.nav,
              padding: const EdgeInsets.symmetric(horizontal: 8),
              child: LayoutBuilder(
                builder: (context, box) {
                  const total = 3 + 1.9;
                  return Row(
                    children: [
                      for (var i = 0; i < _tabs.length; i++)
                        SizedBox(
                          width: box.maxWidth * (i == index ? 1.9 : 1) / total,
                          child: _item(i, box.maxWidth * (i == index ? 1.9 : 1) / total),
                        ),
                    ],
                  );
                },
              ),
            ),
          ),
          // Top hairline.
          Positioned(
            left: 22,
            right: 22,
            top: 0,
            height: 1,
            child: IgnorePointer(
              child: Opacity(
                opacity: .55,
                child: DecoratedBox(
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      colors: [Ui.fade(Ui.acc, 0), Ui.acc, Ui.fade(Ui.acc, 0)],
                    ),
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _item(int i, double width) {
    final active = i == index;
    final fg = active ? Ui.accInk : Ui.mute;
    final badge = i == 2 && unread > 0;
    return Pressable(
      onTap: () => onSelect(i),
      semanticLabel: '${_tabs[i].$2} tab${badge ? ', $unread new alerts' : ''}${active ? ', selected' : ''}',
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 350),
        curve: kUiEase,
        width: math.max(width, 0),
        height: 50,
        decoration: BoxDecoration(
          color: active ? Ui.acc : Ui.fade(Ui.acc, 0),
          borderRadius: BorderRadius.circular(UiRadius.navItem),
          boxShadow: active
              ? [
                  BoxShadow(color: Ui.fade(Ui.acc, .20), spreadRadius: 1),
                  BoxShadow(color: Ui.fade(Ui.acc, .24), blurRadius: 22),
                ]
              : null,
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Stack(
              clipBehavior: Clip.none,
              children: [
                UiIcon(_tabs[i].$1, size: 21, stroke: 1.8, color: fg),
                if (badge)
                  Positioned(
                    top: -7,
                    right: -9,
                    child: Container(
                      constraints: const BoxConstraints(minWidth: 17),
                      height: 17,
                      padding: const EdgeInsets.symmetric(horizontal: 4),
                      alignment: Alignment.center,
                      decoration: BoxDecoration(
                        color: Ui.crit,
                        borderRadius: BorderRadius.circular(UiRadius.pill),
                      ),
                      child: Text(
                        unread > 9 ? '9+' : '$unread',
                        style: UiText.navBadge.copyWith(color: Ui.white),
                      ),
                    ),
                  ),
              ],
            ),
            if (active) ...[
              const SizedBox(width: 8),
              Flexible(
                child: Text(
                  _tabs[i].$2,
                  maxLines: 1,
                  overflow: TextOverflow.clip,
                  softWrap: false,
                  style: UiText.navLabel.copyWith(color: fg),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
