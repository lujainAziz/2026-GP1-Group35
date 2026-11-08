import 'dart:math' as math;
import 'dart:ui' as ui;

import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../state/app_state.dart';
import '../../theme/assas_ui.dart';
import '../../widgets/coming_soon.dart';
import '../../widgets/ui_icons.dart';
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

  // Severity filter dropdown (same pattern as the devices list filter).
  final _filterMenu = OverlayPortalController();
  final _filterLink = LayerLink();

  // Severities to show; EMPTY = all (no restriction), mirroring the devices filter.
  final Set<Severity> _shown = {};

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
    UiMemory.alertSeverities().then((names) {
      if (names == null || !mounted) return;
      // Stored set of severities to show; empty list = all (no restriction).
      setState(() => _shown
        ..clear()
        ..addAll([for (final s in Severity.values) if (names.contains(s.name)) s]));
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

  bool get _filterActive => _shown.isNotEmpty;

  // Active severities, strongest first — for a stable dot/summary.
  List<Severity> get _selectedBySeverity =>
      _shown.toList()..sort((a, b) => b.index.compareTo(a.index));

  // Count only on the button ("1 filter" / "2 filters"); the severity NAMES live
  // in the filter panel, so the button stays compact and fixed-width.
  String get _filterSummary => _shown.isEmpty
      ? ''
      : _shown.length == 1
          ? '1 filter'
          : '${_shown.length} filters';

  Color get _summaryDotColor =>
      _shown.isEmpty ? Ui.acc : _severityColors(_selectedBySeverity.first).foreground;

  // Fixed content width for the filter pill = the LONGEST possible state
  // ("4 filters" — all four severities — with the dot), measured at the current
  // font scale so the pill never resizes between "Filter" and any count. No
  // ghost widget, so no duplicate text.
  double _pillContentWidth(BuildContext context) {
    final tp = TextPainter(
      text: TextSpan(text: '4 filters', style: UiText.sans(11.5, 700)),
      textDirection: TextDirection.ltr,
      textScaler: MediaQuery.textScalerOf(context),
    )..layout();
    return 15 + 4 + 5 + 4 + tp.width; // icon + gap + dot + gap + text
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
                    // Tabs (left) + Filter (right) pinned at the top, always one
                    // row: the big title scrolls up while this row stays. When
                    // the system font makes the row tight, each tab stacks its
                    // count UNDER its name (narrower) so All/Open/Resolved and
                    // the Filter stay on the same line; the pinned height grows
                    // to match so the first alert is never covered.
                    if (Released.alerts && Released.alertManagement)
                      SliverPersistentHeader(
                        pinned: true,
                        delegate: _TabsDelegate(
                          extent: _tabsExtent(context, _stackedTabs(context)),
                          child: _tabs(alerts, _stackedTabs(context)),
                        ),
                      ),
                    // The list starts directly under the tabs row.
                    SliverToBoxAdapter(
                      child: Padding(
                        padding: const EdgeInsets.fromLTRB(16, 14, 16, 0),
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

  // Pinned header is tight enough to stack the tab counts under their names.
  double _systemScale(BuildContext context) => MediaQuery.textScalerOf(context).scale(1.0);
  bool _stackedTabs(BuildContext context) => _systemScale(context) >= 1.15;

  // Height the pinned header reserves, grown to the content so it never covers
  // the first alert. Stacked tabs (name over count) are ~two text lines tall.
  double _tabsExtent(BuildContext context, bool stacked) {
    final s = _systemScale(context);
    final tabH = stacked ? 30 + 28 * s : 22 + 18 * s;
    return math.max(tabH, 36) + 14; // max(tab, pill) + vertical padding + buffer
  }

  Widget _tabs(List<SecurityAlert>? alerts, bool stacked) {
    final list = alerts ?? const <SecurityAlert>[];
    // Frosted, pinned strip: fills the header height, content sits at the
    // bottom above the hairline; the big title scrolls away above it.
    return ClipRect(
      child: BackdropFilter(
        filter: ui.ImageFilter.blur(sigmaX: 7, sigmaY: 7),
        child: Container(
          alignment: Alignment.bottomCenter,
          decoration: BoxDecoration(
            // Near-opaque wash over the blur so pinned content masks the list
            // scrolling beneath it (pure blur let cards show through).
            color: Ui.fade(Ui.bg, .88),
            border: Border(bottom: BorderSide(color: Ui.line)),
          ),
          // Inset to the page text margin so the row lines up with the big title
          // and the Filter's right edge meets the end of "open alerts" above it.
          padding: const EdgeInsets.fromLTRB(UiSpace.pageText, 4, UiSpace.pageText, 6),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              // Tabs grouped on the left; Expanded (not Flexible) so the free
              // space lives HERE and the Filter is pushed to the far right even
              // when the tabs are narrow. Scrolls only as a last resort.
              Expanded(
                child: Align(
                  alignment: Alignment.bottomLeft,
                  child: SingleChildScrollView(
                    scrollDirection: Axis.horizontal,
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.end,
                      children: [
                        for (final tab in _AlertTab.values) ...[
                          if (tab != _AlertTab.all) SizedBox(width: stacked ? 8 : 14),
                          _tabItem(tab, list.where(tab.matches).length, stacked),
                        ],
                      ],
                    ),
                  ),
                ),
              ),
              // Free space between the tabs and the button; the button takes its
              // fixed width from here and stays pinned to the right edge.
              const SizedBox(width: 8),
              Padding(padding: const EdgeInsets.only(bottom: 4), child: _filterPill()),
            ],
          ),
        ),
      ),
    );
  }

  Widget _tabItem(_AlertTab tab, int count, bool stacked) {
    final on = tab == _tab;
    // Stacked (tight) tabs use a slightly smaller type so all three names and
    // counts + the Filter button genuinely fit on one row at the app's largest
    // font; the regular row keeps the designed tab size.
    final nameStyle = (stacked ? UiText.sans(13.5, 700, em: -0.01) : UiText.tab)
        .copyWith(color: on ? Ui.ink : Ui.mute);
    final name = AnimatedDefaultTextStyle(
      duration: const Duration(milliseconds: 250),
      style: nameStyle,
      child: Text(tab.label),
    );
    final countText = Text('$count',
        style: UiText.mono(stacked ? 10.5 : 11, 600).copyWith(color: on ? tab.color : Ui.mute));
    return Pressable(
      onTap: () => _setTab(tab),
      child: Stack(
        clipBehavior: Clip.none,
        children: [
          Padding(
            padding: const EdgeInsets.only(top: 8, bottom: 12),
            // Tight layout: count UNDER the name (narrower). Otherwise side by
            // side on one line.
            child: stacked
                ? Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [name, const SizedBox(height: 1), countText],
                  )
                : Row(
                    crossAxisAlignment: CrossAxisAlignment.baseline,
                    textBaseline: TextBaseline.alphabetic,
                    children: [name, const SizedBox(width: 6), countText],
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

  // ---------- Filter control (in the tabs row) ----------
  // Same shape, colours and font as the devices-list filter button: shows
  // "Filter" when inactive and the summary ("Critical" / "2 filters") with a
  // severity-coloured dot when active.
  Widget _pillRow(String text, {required bool dot}) => Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          UiIcon(UiIcons.filter, size: 15, stroke: 2, color: Ui.ink),
          const SizedBox(width: 4),
          if (dot) ...[GlowDot(_summaryDotColor, size: 5, glow: 0), const SizedBox(width: 4)],
          Text(text, style: UiText.sans(11.5, 700)),
        ],
      );

  Widget _filterPill() => CompositedTransformTarget(
        link: _filterLink,
        child: OverlayPortal(
          controller: _filterMenu,
          overlayChildBuilder: (context) => _filterOverlay(),
          child: Pressable(
            key: const ValueKey('alertFilterButton'),
            onTap: () => setState(_filterMenu.toggle),
            semanticLabel: 'Filter alerts by severity, ${_filterActive ? _filterSummary : 'off'}',
            child: Glass(
              color: _filterActive ? Ui.mix(Ui.acc, .22, Ui.surf) : Ui.fade(Ui.surf, .82),
              border: _filterActive ? Ui.mix(Ui.acc, .45, Ui.line) : Ui.line,
              radius: UiRadius.search,
              blur: 16,
              height: 36,
              padding: const EdgeInsets.symmetric(horizontal: 7),
              // Fixed, compact width across states: reserve the width of the
              // widest content ("2 filters"), so the pill never resizes between
              // "Filter" and any count and the tabs keep every spare pixel. The
              // icon+text are centred together within that width, so "Filter"
              // doesn't leave a gap on the right.
              child: SizedBox(
                width: _pillContentWidth(context),
                child: Center(
                  widthFactor: 1,
                  child: _filterActive
                      ? _pillRow(_filterSummary, dot: true)
                      : _pillRow('Filter', dot: false),
                ),
              ),
            ),
          ),
        ),
      );

  Widget _filterOverlay() {
    final alerts = Released.alertsOf(state) ?? const <SecurityAlert>[];
    int countFor(Severity s) => alerts.where((a) => a.severity == s).length;
    return Stack(
      children: [
        Positioned.fill(
          child: GestureDetector(
            behavior: HitTestBehavior.opaque,
            onTap: () => setState(_filterMenu.hide),
          ),
        ),
        CompositedTransformFollower(
          link: _filterLink,
          // Anchor to the right edge so the menu opens leftward and stays
          // on-screen (the Filter pill sits at the far right of the row).
          targetAnchor: Alignment.bottomRight,
          followerAnchor: Alignment.topRight,
          offset: const Offset(0, 7),
          child: FadeSlideIn(
            duration: const Duration(milliseconds: 250),
            child: SizedBox(
              width: 240,
              child: Glass(
                color: Ui.fade(Ui.surf2, .92),
                radius: UiRadius.dropdown,
                blur: 18,
                shadows: UiShadow.dropdown,
                padding: const EdgeInsets.all(6),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // All = show every severity (clears the restriction).
                    _severityAllRow(alerts.length),
                    const SizedBox(height: 4),
                    for (final s in const [Severity.critical, Severity.high, Severity.medium, Severity.low]) ...[
                      _severityChip(s, countFor(s)),
                      const SizedBox(height: 4),
                    ],
                  ],
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _severityAllRow(int count) {
    final on = _shown.isEmpty;
    return Pressable(
      onTap: () {
        setState(_shown.clear);
        UiMemory.setAlertSeverities(const []);
      },
      semanticLabel: 'All severities, $count alerts${on ? ', selected' : ''}',
      child: Container(
        height: 40,
        padding: const EdgeInsets.symmetric(horizontal: 12),
        decoration: BoxDecoration(
          color: on ? Ui.fade(Ui.acc, .16) : Colors.transparent,
          borderRadius: BorderRadius.circular(UiRadius.dropdownItem),
        ),
        child: Row(
          children: [
            GlowDot(Ui.acc, size: 8, glow: 0),
            const SizedBox(width: 10),
            Expanded(child: Text('All', style: UiText.menuItem)),
            Text('$count', style: UiText.tabCount.copyWith(color: Ui.mute)),
            const SizedBox(width: 10),
            SizedBox(width: 14, child: Text(on ? '✓' : '', style: UiText.sans(13, 800, color: Ui.acc))),
          ],
        ),
      ),
    );
  }

  Widget _severityChip(Severity s, int count) {
    final on = _shown.contains(s);
    final c = _severityColors(s);
    return Pressable(
      key: ValueKey('sevchip_${s.name}'),
      // Multi-select: tapping keeps the menu open so several can be set.
      onTap: () {
        setState(() => on ? _shown.remove(s) : _shown.add(s));
        UiMemory.setAlertSeverities([for (final x in _shown) x.name]);
      },
      semanticLabel: '${_severityLabel(s)}, $count alerts${on ? ', selected' : ''}',
      child: Container(
        height: 40,
        padding: const EdgeInsets.symmetric(horizontal: 12),
        decoration: BoxDecoration(
          color: on ? Ui.fade(Ui.acc, .16) : Colors.transparent,
          borderRadius: BorderRadius.circular(UiRadius.dropdownItem),
          border: Border.all(color: on ? Ui.mix(Ui.acc, .45, Ui.line) : Ui.line),
        ),
        child: Row(
          children: [
            GlowDot(c.foreground, size: 7, glow: 0),
            const SizedBox(width: 10),
            Expanded(child: Text(_severityLabel(s), style: UiText.menuItem)),
            Text('$count', style: UiText.tabCount.copyWith(color: Ui.mute)),
            const SizedBox(width: 10),
            SizedBox(width: 14, child: Text(on ? '✓' : '', style: UiText.sans(13, 800, color: Ui.acc))),
          ],
        ),
      ),
    );
  }

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
    // Newest first (the sort control now lives only in device details).
    final list = sortedAlerts(base, AlertSort.newest);

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
    final filtering = _shown.isNotEmpty;
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

/// Pinned tabs+filter header. Its [extent] is grown to the content (one or two
/// text lines of tabs) so the pinned strip never covers the first alert.
class _TabsDelegate extends SliverPersistentHeaderDelegate {
  _TabsDelegate({required this.child, required this.extent});

  final Widget child;
  final double extent;

  @override
  double get minExtent => extent;

  @override
  double get maxExtent => extent;

  @override
  Widget build(BuildContext context, double shrinkOffset, bool overlapsContent) =>
      SizedBox.expand(child: child);

  @override
  bool shouldRebuild(_TabsDelegate old) => true;
}
