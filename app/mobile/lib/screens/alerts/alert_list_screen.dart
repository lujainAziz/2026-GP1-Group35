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

String _severityLabel(Severity s) => switch (s) {
      Severity.critical => 'Critical',
      Severity.high => 'High',
      Severity.medium => 'Medium',
      Severity.low => 'Low',
    };

BadgeColors _severityColors(Severity s) => switch (s) {
      Severity.critical => BadgeColors.critical,
      Severity.high => BadgeColors.high,
      Severity.medium => BadgeColors.medium,
      Severity.low => BadgeColors.low,
    };

/// One list for Threat and Anomaly alerts with All / Open / Resolved tabs, a
/// severity filter, a newest/most-severe sort, and a back-to-top button.
class AlertListScreen extends StatefulWidget {
  const AlertListScreen({super.key, required this.state});

  final AppState state;

  @override
  State<AlertListScreen> createState() => _AlertListScreenState();
}

class _AlertListScreenState extends State<AlertListScreen> {
  _AlertTab _tab = _AlertTab.all;

  final ScrollController _scroll = ScrollController();
  bool _showTop = false;

  // Display preferences (persisted; display-only, never sent to the appliance).
  AlertSort _sort = AlertSort.newest;
  Set<Severity> _shown = Severity.values.toSet();
  bool _hideResolved = false;

  AppState get state => widget.state;

  @override
  void initState() {
    super.initState();
    _scroll.addListener(_onScroll);
    // Bring back the tab + sort/filter choices from last time.
    UiMemory.alertTab().then((name) {
      for (final t in _AlertTab.values) {
        if (t.name == name && mounted) setState(() => _tab = t);
      }
    });
    UiMemory.alertSort().then((name) {
      for (final s in AlertSort.values) {
        if (s.name == name && mounted) setState(() => _sort = s);
      }
    });
    UiMemory.alertSeverities().then((names) {
      if (names == null || !mounted) return;
      final set = {for (final s in Severity.values) if (names.contains(s.name)) s};
      // An empty stored set would hide everything; fall back to showing all.
      setState(() => _shown = set.isEmpty ? Severity.values.toSet() : set);
    });
    UiMemory.alertHideResolved().then((v) {
      if (mounted) setState(() => _hideResolved = v);
    });
  }

  @override
  void dispose() {
    _scroll.removeListener(_onScroll);
    _scroll.dispose();
    super.dispose();
  }

  void _onScroll() {
    final show = _scroll.hasClients && _scroll.offset > 520;
    if (show != _showTop) setState(() => _showTop = show);
  }

  void _setTab(_AlertTab t) {
    setState(() => _tab = t);
    UiMemory.setAlertTab(t.name);
  }

  void _toggleSort() {
    setState(() => _sort = _sort == AlertSort.newest ? AlertSort.severity : AlertSort.newest);
    UiMemory.setAlertSort(_sort.name);
  }

  bool get _filterActive => _shown.length != Severity.values.length || _hideResolved;

  @override
  Widget build(BuildContext context) {
    final bottomPad = UiSpace.navBottomPad + math.max(0.0, MediaQuery.paddingOf(context).bottom - 14);
    return ListenableBuilder(
      listenable: state,
      builder: (context, _) {
        final alerts = Released.alertsOf(state);
        final showControls = Released.alerts && (alerts?.isNotEmpty ?? false);
        return SafeArea(
          bottom: false,
          child: Stack(
            children: [
              TopFade(child: RefreshIndicator(
                onRefresh: state.refresh,
                color: Ui.acc,
                backgroundColor: Ui.surf,
                child: CustomScrollView(
                  controller: _scroll,
                  slivers: [
                    SliverToBoxAdapter(child: _hero()),
                    if (Released.alerts && Released.alertManagement)
                      SliverPersistentHeader(
                        pinned: true,
                        delegate: _TabsDelegate(child: _tabs(alerts)),
                      ),
                    if (showControls) SliverToBoxAdapter(child: _controls()),
                    SliverToBoxAdapter(
                      child: Padding(
                        padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
                        child: _body(context, alerts),
                      ),
                    ),
                    SliverToBoxAdapter(child: SizedBox(height: bottomPad)),
                  ],
                ),
              )),
              _backToTop(bottomPad + 8),
            ],
          ),
        );
      },
    );
  }

  Widget _hero() {
    // Original design: a big OPEN count on the left, "open alerts" on the right.
    final live = Released.alerts && Released.alertManagement;
    final count = live ? state.openAlertCount : null;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const KickerRow('NEEDS ATTENTION'),
        Padding(
          padding: const EdgeInsets.fromLTRB(UiSpace.pageText, 6, UiSpace.pageText, 0),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.baseline,
            textBaseline: TextBaseline.alphabetic,
            children: [
              Flexible(
                child: FittedBox(
                  fit: BoxFit.scaleDown,
                  alignment: Alignment.centerLeft,
                  child: Text(
                    count?.toString() ?? (live ? '—' : 'Soon'),
                    style: UiText.alertsHero.copyWith(color: live ? Ui.ink : Ui.mute),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: FittedBox(
                  fit: BoxFit.scaleDown,
                  alignment: Alignment.centerRight,
                  child: Text('open alerts', style: UiText.heroSuffix.copyWith(color: Ui.mute)),
                ),
              ),
            ],
          ),
        ),
        if (Released.alerts && state.alertsError)
          Padding(
            padding: const EdgeInsets.fromLTRB(UiSpace.pageText, 8, UiSpace.pageText, 0),
            child: Text(
              '⚠ SHOWING LAST KNOWN ALERTS — COULDN’T REFRESH',
              style: UiText.mono(10, 600, em: .08, color: Ui.med),
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
            child: SingleChildScrollView(
              scrollDirection: Axis.horizontal,
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

  // ---------- Sort + filter controls ----------
  Widget _controls() => Padding(
        padding: const EdgeInsets.fromLTRB(16, 14, 16, 0),
        child: Row(
          children: [
            _ctrlPill(
              icon: Icons.swap_vert_rounded,
              label: _sort == AlertSort.severity ? 'Most severe' : 'Newest',
              active: _sort == AlertSort.severity,
              onTap: _toggleSort,
              semantic: 'Sort order: ${_sort.label}. Tap to switch.',
            ),
            const SizedBox(width: 10),
            _ctrlPill(
              icon: Icons.tune_rounded,
              label: 'Filter',
              active: _filterActive,
              dot: _filterActive,
              onTap: _openFilterSheet,
              semantic: 'Filter alerts by severity',
            ),
          ],
        ),
      );

  Widget _ctrlPill({
    required IconData icon,
    required String label,
    required bool active,
    required VoidCallback onTap,
    String? semantic,
    bool dot = false,
  }) {
    final c = active ? Ui.acc : Ui.mute;
    return Pressable(
      semanticLabel: semantic,
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(UiRadius.pill),
          border: Border.all(color: active ? Ui.fade(Ui.acc, .5) : Ui.line),
          color: active ? Ui.fade(Ui.acc, .10) : null,
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 15, color: c),
            const SizedBox(width: 6),
            Text(label, style: UiText.mono(11, 600, em: .04, color: c)),
            if (dot) ...[
              const SizedBox(width: 6),
              Container(
                width: 6,
                height: 6,
                decoration: BoxDecoration(color: Ui.acc, shape: BoxShape.circle),
              ),
            ],
          ],
        ),
      ),
    );
  }

  void _openFilterSheet() {
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: Ui.surf,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setSheet) {
          void refresh() => setSheet(() {});
          void toggleSeverity(Severity s, bool on) {
            final next = Set<Severity>.from(_shown);
            on ? next.add(s) : next.remove(s);
            setState(() => _shown = next);
            UiMemory.setAlertSeverities([for (final x in _shown) x.name]);
            refresh();
          }

          return SafeArea(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(20, 12, 20, 18),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Center(
                    child: Container(
                      width: 40,
                      height: 4,
                      margin: const EdgeInsets.only(bottom: 16),
                      decoration: BoxDecoration(color: Ui.line, borderRadius: BorderRadius.circular(2)),
                    ),
                  ),
                  Text('SHOW SEVERITIES', style: UiText.mono(10, 700, em: .1, color: Ui.mute)),
                  const SizedBox(height: 6),
                  for (final s in const [Severity.critical, Severity.high, Severity.medium, Severity.low])
                    _severityRow(s, _shown.contains(s), (on) => toggleSeverity(s, on)),
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 10),
                    child: Divider(height: 1, color: Ui.line),
                  ),
                  _switchRow(
                    'Hide resolved alerts',
                    'They stay saved with their history — turn this off to see them again.',
                    _hideResolved,
                    (on) {
                      setState(() => _hideResolved = on);
                      UiMemory.setAlertHideResolved(on);
                      refresh();
                    },
                  ),
                ],
              ),
            ),
          );
        },
      ),
    );
  }

  Widget _severityRow(Severity s, bool on, ValueChanged<bool> onChanged) {
    final c = _severityColors(s);
    return Pressable(
      semanticLabel: '${_severityLabel(s)} alerts ${on ? 'shown' : 'hidden'}',
      onTap: () => onChanged(!on),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 9),
        child: Row(
          children: [
            Container(width: 9, height: 9, decoration: BoxDecoration(color: c.foreground, shape: BoxShape.circle)),
            const SizedBox(width: 11),
            Expanded(child: Text(_severityLabel(s), style: UiText.sans(14, 600))),
            _check(on),
          ],
        ),
      ),
    );
  }

  Widget _check(bool on) => Container(
        width: 22,
        height: 22,
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: on ? Ui.acc : Ui.line, width: 1.5),
          color: on ? Ui.fade(Ui.acc, .18) : null,
        ),
        child: on ? Icon(Icons.check_rounded, size: 15, color: Ui.acc) : null,
      );

  Widget _switchRow(String title, String sub, bool on, ValueChanged<bool> onChanged) => Pressable(
        semanticLabel: '$title ${on ? 'on' : 'off'}',
        onTap: () => onChanged(!on),
        child: Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title, style: UiText.sans(14, 600)),
                  const SizedBox(height: 2),
                  Text(sub, style: UiText.sans(11, 500, color: Ui.mute)),
                ],
              ),
            ),
            const SizedBox(width: 10),
            // Visual indicator; the whole row is the tap target (above).
            IgnorePointer(
              child: Switch(value: on, activeThumbColor: Ui.acc, onChanged: (_) {}),
            ),
          ],
        ),
      );

  // ---------- Body ----------
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
    Iterable<SecurityAlert> base = alerts.where(tab.matches);
    base = alertsWithSeverity(base, _shown);
    // "Hide resolved" is a display filter only (nothing is deleted or re-stated).
    // It is ignored on the Resolved tab, which is how the user gets back to them.
    if (_hideResolved && tab != _AlertTab.resolved) {
      base = base.where((a) => a.isUnresolved);
    }
    final list = sortedAlerts(base, _sort);

    if (list.isEmpty) {
      final (title, hint) = _emptyText(tab);
      return Column(
        children: [
          _empty(title, hint),
          // The current page may have nothing matching while OLDER alerts do:
          // keep the load-older affordance so the filter/sort reaches the whole
          // list, not just the loaded page.
          if (state.alertsHaveMore) _loadOlder(),
        ],
      );
    }
    return Stack(
      children: [
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
            if (state.alertsHaveMore) _loadOlder(),
          ],
        ),
      ],
    );
  }

  (String, String) _emptyText(_AlertTab tab) {
    final filtering = _shown.length != Severity.values.length || (_hideResolved && tab != _AlertTab.resolved);
    if (filtering) {
      return (
        'No alerts match the filter',
        state.alertsHaveMore
            ? 'Adjust the severities, or load older alerts to search the full list.'
            : 'Try showing more severities.',
      );
    }
    return switch (tab) {
      _AlertTab.resolved => ('No resolved alerts yet', 'Alerts you resolve will be kept here for context.'),
      _AlertTab.open => ('All clear.', 'No open alerts right now.'),
      _AlertTab.all => ('No alerts yet', 'Alerts will appear here once detection flags something.'),
    };
  }

  bool _loadingMore = false;

  Widget _loadOlder() => Padding(
        padding: const EdgeInsets.only(left: 30, top: 14),
        child: Pressable(
          onTap: _loadingMore
              ? null
              : () async {
                  setState(() => _loadingMore = true);
                  try {
                    await state.loadMoreAlerts();
                  } finally {
                    if (mounted) setState(() => _loadingMore = false);
                  }
                },
          child: Container(
            width: double.infinity,
            alignment: Alignment.center,
            padding: const EdgeInsets.symmetric(vertical: 13),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(UiRadius.pill),
              border: Border.all(color: Ui.line),
            ),
            child: _loadingMore
                ? const UiSpinner(size: 16)
                : Text('Load older alerts', style: UiText.clearSearch.copyWith(color: Ui.acc)),
          ),
        ),
      );

  Widget _empty(String title, String hint, {bool soon = false}) => EmptyDashed(
        action: soon ? const SoonTag(2) : null,
        margin: const EdgeInsets.only(top: 10),
        radius: UiRadius.explainCard,
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 30),
        fill: Ui.fade(Ui.surf, .65),
        titleStyle: UiText.sans(22, 800, em: -.02),
        title: title,
        hint: hint,
      );

  Widget _backToTop(double bottom) {
    // Built only while scrolled down, so it is cleanly absent (layout and
    // semantics) at the top; it pops in when it appears.
    if (!_showTop) return const SizedBox.shrink();
    return Positioned(
      right: 16,
      bottom: bottom,
      child: TweenAnimationBuilder<double>(
        tween: Tween(begin: 0, end: 1),
        duration: const Duration(milliseconds: 200),
        curve: Curves.easeOutBack,
        builder: (context, t, child) => Transform.scale(
          scale: t,
          child: Opacity(opacity: t.clamp(0.0, 1.0), child: child),
        ),
        child: Pressable(
          semanticLabel: 'Back to top',
          onTap: () => _scroll.animateTo(
            0,
            duration: const Duration(milliseconds: 420),
            curve: Curves.easeOutCubic,
          ),
          child: Container(
            width: 46,
            height: 46,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: Ui.acc,
              boxShadow: UiShadow.glow(Ui.acc, 12),
            ),
            child: Icon(Icons.arrow_upward_rounded, size: 22, color: Ui.bg),
          ),
        ),
      ),
    );
  }
}

class _TabsDelegate extends SliverPersistentHeaderDelegate {
  _TabsDelegate({required this.child});

  final Widget child;

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
