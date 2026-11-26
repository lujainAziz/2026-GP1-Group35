import 'dart:math' as math;

import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../state/app_state.dart';
import '../../theme/assas_ui.dart';
import '../../widgets/coming_soon.dart';
import '../../widgets/filter_button.dart';
import '../../widgets/ui_kit.dart';
import '../../widgets/ui_memory.dart';
import 'alert_details_screen.dart';

// Release 1: All / Unread / Resolved. "Unread" = not opened on this phone and
// still unresolved; read is a per-phone marker, not a state.
enum _AlertTab { all, unread, resolved }

extension on _AlertTab {
  String get label => switch (this) {
        _AlertTab.all => 'All',
        _AlertTab.unread => 'Unread',
        _AlertTab.resolved => 'Resolved',
      };

  Color get color => switch (this) {
        _AlertTab.all => Ui.acc,
        _AlertTab.unread => Ui.high,
        _AlertTab.resolved => Ui.low,
      };

  bool matches(SecurityAlert a) => switch (this) {
        _AlertTab.all => true,
        _AlertTab.unread => a.isUnread && a.isUnresolved,
        _AlertTab.resolved => !a.isUnresolved,
      };
}

String _severityLabel(Severity s) => switch (s) {
      Severity.high => 'High',
      Severity.medium => 'Medium',
      Severity.low => 'Low',
    };

BadgeColors _severityColors(Severity s) => switch (s) {
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
                    // count UNDER its name (narrower) so All/Unread/Resolved and
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
    // Original design: a big count on the left, "unresolved alerts" on the right.
    final live = Released.alerts && Released.alertManagement;
    final count = live ? state.unresolvedAlertCount : null;
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
                  child: Text('unresolved alerts', style: UiText.heroSuffix.copyWith(color: Ui.mute)),
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
    // One tab: _tabPad above the label, the label (two lines when stacked),
    // _tabUnderlineGap + the 2px underline, then _tabPad below.
    final tabH = (stacked ? 10 + 28 * s : 2 + 18 * s) +
        2 * _tabPad + _tabUnderlineGap + 2;
    // max(tab, button) + the card's vertical padding + the card border (2 x 1)
    // + the gaps above and below the card, so the button keeps its full fixed
    // size and no alert is covered.
    return math.max(tabH, FilterButton.size) + 2 * _tabsCardPadV + 2 + 2 * _tabsCardGap;
  }

  // Gap above and below the tabs card inside the pinned header.
  static const double _tabsCardGap = 6;
  // Inner padding of the tabs card: the alert cards' own horizontal padding on
  // both sides, and an equal small padding above and below the row.
  static const double _tabsCardPadH = UiSpace.cardPadH;
  static const double _tabsCardPadV = 6;
  // Inside one tab: equal space above the label and below the underline, and a
  // small gap between the label and its underline.
  static const double _tabPad = 8;
  static const double _tabUnderlineGap = 4;

  Widget _tabs(List<SecurityAlert>? alerts, bool stacked) {
    final list = alerts ?? const <SecurityAlert>[];
    // Pinned strip: fills the header height; the big title scrolls away above
    // it. The full-width background is OPAQUE and the screen's own base colour
    // (no band, no hairline), so alerts never show through while scrolling.
    // The tabs row sits in a rounded card styled like the alert cards.
    return ClipRect(
      child: ColoredBox(
        color: Ui.bg,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(
              UiSpace.pageCards, _tabsCardGap, UiSpace.pageCards, _tabsCardGap),
          child: Container(
            // The row is centred vertically: equal space above and below.
            alignment: Alignment.center,
            clipBehavior: Clip.antiAlias,
            decoration: surfCard(UiRadius.alertCard),
            padding: const EdgeInsets.symmetric(horizontal: _tabsCardPadH, vertical: _tabsCardPadV),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                // Tabs grouped on the left; Expanded (not Flexible) so the free
                // space lives HERE and the Filter is pushed to the far right even
                // when the tabs are narrow. Shrinks slightly only as a last resort
                // (never clips "Resolved").
                Expanded(
                  child: Align(
                    alignment: Alignment.centerLeft,
                    child: FittedBox(
                      fit: BoxFit.scaleDown,
                      alignment: Alignment.centerLeft,
                      child: _tabsRow(list, stacked),
                    ),
                  ),
                ),
                // Free space between the tabs and the button; the button takes its
                // fixed width from here and stays pinned to the right edge.
                const SizedBox(width: 8),
                _filterPill(),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _tabsRow(List<SecurityAlert> list, bool stacked) {
    final row = Row(
      // Bottom-aligned so every underline sits on one line. Stacked tabs are
      // also stretched to one height (the Unread badge is a little taller than
      // a plain count), so every label starts at the same top.
      crossAxisAlignment: stacked ? CrossAxisAlignment.stretch : CrossAxisAlignment.end,
      children: [
        for (final tab in _AlertTab.values) ...[
          if (tab != _AlertTab.all) SizedBox(width: stacked ? 8 : 14),
          _tabItem(
            tab,
            // Unread: this phone's DB count (the badge), not the page.
            tab == _AlertTab.unread
                ? state.unreadCount ?? list.where(tab.matches).length
                : list.where(tab.matches).length,
            stacked,
          ),
        ],
      ],
    );
    return stacked ? IntrinsicHeight(child: row) : row;
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
    final Widget countText = tab == _AlertTab.unread && count > 0
        // Unread: a small filled count badge.
        ? Container(
            key: const ValueKey('unreadBadge'),
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
            decoration: BoxDecoration(
              color: Ui.high,
              borderRadius: BorderRadius.circular(UiRadius.pill),
            ),
            child: Text('$count', style: UiText.mono(stacked ? 10 : 10.5, 700).copyWith(color: Ui.bg)),
          )
        : Text('$count',
            style: UiText.mono(stacked ? 10.5 : 11, 600).copyWith(color: on ? tab.color : Ui.mute));
    return Pressable(
      onTap: () => _setTab(tab),
      child: Stack(
        clipBehavior: Clip.none,
        children: [
          Padding(
            // _tabPad above the label; below it, room for the underline and
            // then _tabPad again, so the tab is symmetric top to bottom.
            padding: const EdgeInsets.only(
                top: _tabPad, bottom: _tabUnderlineGap + 2 + _tabPad),
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
            bottom: _tabPad,
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
  // The same icon-only, fixed-size button as the devices list.
  Widget _filterPill() => CompositedTransformTarget(
        link: _filterLink,
        child: OverlayPortal(
          controller: _filterMenu,
          overlayChildBuilder: (context) => _filterOverlay(),
          child: FilterButton(
            key: const ValueKey('alertFilterButton'),
            selected: _shown.length,
            onTap: () => setState(_filterMenu.toggle),
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
                    for (final s in const [Severity.high, Severity.medium, Severity.low]) ...[
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
        'Security alerts will appear here once detection is running.',
      );
    }
    // Without alert management there are no Unread / Resolved tabs: show all.
    final tab = Released.alertManagement ? _tab : _AlertTab.all;
    // Unread comes from the appliance (this phone's unread, unresolved alerts),
    // so it is not limited to the loaded page; otherwise filter the loaded list.
    final unread = tab == _AlertTab.unread ? state.unreadAlerts : null;
    Iterable<SecurityAlert> base = unread ?? alerts.where(tab.matches);
    final haveMore = unread != null ? state.unreadHaveMore : state.alertsHaveMore;
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
          if (haveMore) _loadOlder(),
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
            if (haveMore) _loadOlder(),
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
      // Never "All clear": an empty Unread tab says nothing about safety.
      _AlertTab.unread => ('No unread alerts', 'Alerts you have not opened yet appear here.'),
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
