import 'dart:math' as math;
import 'dart:ui' as ui;

import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../state/app_state.dart';
import '../../theme/assas_ui.dart';
import '../../widgets/coming_soon.dart';
import '../../widgets/ui_kit.dart';
import '../../widgets/ui_memory.dart';
import 'alert_details_screen.dart';

enum _AlertTab { all, open, resolved }

extension on _AlertTab {
  String get label => switch (this) {
        _AlertTab.all => 'All',
        _AlertTab.open => 'Open',
        _AlertTab.resolved => 'Resolved',
      };

  Color get color => switch (this) {
        _AlertTab.all => Ui.acc,
        _AlertTab.open => Ui.high,
        _AlertTab.resolved => Ui.low,
      };

  bool matches(SecurityAlert a) => switch (this) {
        _AlertTab.all => true,
        _AlertTab.open => a.isUnresolved,
        _AlertTab.resolved => !a.isUnresolved,
      };
}

/// One list for Threat and Anomaly alerts, newest first (PBI-19),
/// with All / Open / Resolved tabs.
class AlertListScreen extends StatefulWidget {
  const AlertListScreen({super.key, required this.state});

  final AppState state;

  @override
  State<AlertListScreen> createState() => _AlertListScreenState();
}

class _AlertListScreenState extends State<AlertListScreen> {
  _AlertTab _tab = _AlertTab.all;

  AppState get state => widget.state;

  @override
  void initState() {
    super.initState();
    // Bring back the tab from last time.
    UiMemory.alertTab().then((name) {
      for (final t in _AlertTab.values) {
        if (t.name == name && mounted) setState(() => _tab = t);
      }
    });
  }

  void _setTab(_AlertTab t) {
    setState(() => _tab = t);
    UiMemory.setAlertTab(t.name);
  }

  @override
  Widget build(BuildContext context) {
    final bottomPad = UiSpace.navBottomPad + math.max(0.0, MediaQuery.paddingOf(context).bottom - 14);
    return ListenableBuilder(
      listenable: state,
      builder: (context, _) {
        final alerts = Released.alertsOf(state);
        return SafeArea(
          bottom: false,
          child: TopFade(child: RefreshIndicator(
            onRefresh: state.refresh,
            color: Ui.acc,
            backgroundColor: Ui.surf,
            child: CustomScrollView(
              slivers: [
                SliverToBoxAdapter(child: _hero()),
                if (Released.alerts && Released.alertManagement)
                  SliverPersistentHeader(
                    pinned: true,
                    delegate: _TabsDelegate(child: _tabs(alerts)),
                  ),
                SliverToBoxAdapter(
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(16, 18, 16, 0),
                    child: _body(context, alerts),
                  ),
                ),
                SliverToBoxAdapter(child: SizedBox(height: bottomPad)),
              ],
            ),
          )),
        );
      },
    );
  }

  Widget _hero() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const KickerRow('NEEDS ATTENTION'),
        Padding(
          padding: const EdgeInsets.fromLTRB(UiSpace.pageText, 10, UiSpace.pageText, 0),
          child: Text(
            // Screen title (not a count). The open-alerts summary is a later
            // sprint; the list below is the Sprint-2 deliverable.
            Released.alerts ? 'Threat Alerts' : 'Soon',
            style: UiText.pairTitle.copyWith(color: Released.alerts ? Ui.ink : Ui.mute),
          ),
        ),
        const SizedBox(height: 14),
      ],
    );
  }

  Widget _tabs(List<SecurityAlert>? alerts) {
    final list = alerts ?? const <SecurityAlert>[];
    return ClipRect(
      child: BackdropFilter(
        filter: ui.ImageFilter.blur(sigmaX: 7, sigmaY: 7),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(22, 6, 22, 0),
          child: DecoratedBox(
            decoration: BoxDecoration(border: Border(bottom: BorderSide(color: Ui.line))),
            child: Row(
              children: [
                for (final tab in _AlertTab.values) ...[
                  if (tab != _AlertTab.all) const SizedBox(width: 26),
                  _tabItem(tab, list.where(tab.matches).length),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _tabItem(_AlertTab tab, int count) {
    final on = tab == _tab;
    return Pressable(
      onTap: () => _setTab(tab),
      child: Stack(
        clipBehavior: Clip.none,
        children: [
          Padding(
            padding: const EdgeInsets.only(top: 10, bottom: 12),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.baseline,
              textBaseline: TextBaseline.alphabetic,
              children: [
                AnimatedDefaultTextStyle(
                  duration: const Duration(milliseconds: 250),
                  style: UiText.tab.copyWith(color: on ? Ui.ink : Ui.mute),
                  child: Text(tab.label),
                ),
                const SizedBox(width: 6),
                Text('$count', style: UiText.tabCount.copyWith(color: on ? tab.color : Ui.mute)),
              ],
            ),
          ),
          Positioned(
            left: 0,
            right: 0,
            bottom: -1,
            child: AnimatedScale(
              duration: const Duration(milliseconds: 300),
              curve: const Cubic(.3, .8, .2, 1),
              scale: on ? 1 : 0,
              child: AnimatedOpacity(
                duration: const Duration(milliseconds: 300),
                opacity: on ? 1 : 0,
                child: Container(
                  height: 2,
                  decoration: BoxDecoration(
                    color: tab.color,
                    borderRadius: BorderRadius.circular(2),
                    boxShadow: UiShadow.glow(tab.color, 10),
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _body(BuildContext context, List<SecurityAlert>? alerts) {
    if (!state.loadedOnce) {
      return const Padding(
        padding: EdgeInsets.all(24),
        child: Center(child: UiSpinner(size: 22)),
      );
    }
    if (!Released.alerts) {
      return _empty(
        'Coming soon',
        'Threat alerts arrive in Sprint 2 and anomaly alerts in Sprint 3.',
        soon: true,
      );
    }
    if (alerts == null) {
      return _empty(
        'Alerts are not available yet',
        'Threat and anomaly alerts will appear here once detection is running.',
      );
    }
    // Without alert management there are no Open / Resolved tabs: show all.
    final tab = Released.alertManagement ? _tab : _AlertTab.all;
    final list = alerts.where(tab.matches).toList();
    if (list.isEmpty) {
      return _empty('All clear.', 'No alerts match this view.');
    }
    return Stack(
      children: [
        // Timeline rail.
        Positioned(
          left: 15,
          top: 12,
          bottom: 20,
          child: Container(width: 1, color: Ui.line),
        ),
        Column(
          children: [
            for (var i = 0; i < list.length; i++) ...[
              if (i > 0) const SizedBox(height: 10),
              TimelineAlertCard(
                alert: list[i],
                onTap: () => Navigator.of(context).push(
                  MaterialPageRoute(
                    builder: (_) => AlertDetailsScreen(state: state, alertId: list[i].id),
                  ),
                ),
              ),
            ],
          ],
        ),
      ],
    );
  }

  Widget _empty(String title, String hint, {bool soon = false}) => EmptyDashed(
        action: soon ? const SoonTag(2) : null,
        margin: const EdgeInsets.only(left: 30, top: 10),
        radius: UiRadius.explainCard,
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 30),
        fill: Ui.fade(Ui.surf, .65),
        titleStyle: UiText.sans(22, 800, em: -.02),
        title: title,
        hint: hint,
      );
}

class _TabsDelegate extends SliverPersistentHeaderDelegate {
  _TabsDelegate({required this.child});

  final Widget child;

  // 6 top padding + 10 + text + 12 + 1 line.
  @override
  double get minExtent => 58;

  @override
  double get maxExtent => 58;

  @override
  Widget build(BuildContext context, double shrinkOffset, bool overlapsContent) =>
      SizedBox(height: 58, child: Align(alignment: Alignment.topLeft, child: child));

  @override
  bool shouldRebuild(_TabsDelegate old) => true;
}
