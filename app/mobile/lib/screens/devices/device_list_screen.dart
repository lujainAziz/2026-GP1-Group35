import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../../state/app_state.dart';
import '../../theme/assas_ui.dart';
import '../../widgets/device_signals.dart';
import '../../widgets/filter_button.dart';
import '../../widgets/ui_icons.dart';
import '../../widgets/ui_kit.dart';
import '../../widgets/ui_memory.dart';
import 'device_details_screen.dart';

/// Device filter poles, grouped into four mutually-exclusive pairs (one axis per
/// pair, pole index ^ 1 = the opposite pole in the same pair). "All" is the
/// empty set. Poles across different pairs combine (AND); the two poles of one
/// pair never apply together.
enum FilterPole {
  attention, notAttention,     // axis 0
  trusted, untrusted,          // axis 1
  online, offline,             // axis 2
  monitored, notMonitored,     // axis 3
}

extension FilterPoleX on FilterPole {
  FilterPole get opposite => FilterPole.values[index ^ 1];

  String get label => switch (this) {
        FilterPole.attention => 'Attention',
        FilterPole.notAttention => 'No attention',
        FilterPole.trusted => 'Trusted',
        FilterPole.untrusted => 'Untrusted',
        FilterPole.online => 'Online',
        FilterPole.offline => 'Offline',
        FilterPole.monitored => 'Monitored',
        FilterPole.notMonitored => 'Not monitored',
      };

  Color get dot => switch (this) {
        FilterPole.attention => Ui.high,
        FilterPole.notAttention => Ui.low,
        FilterPole.trusted => Ui.low,
        FilterPole.untrusted => Ui.med,
        FilterPole.online => Ui.low,
        FilterPole.offline => Ui.mute,
        FilterPole.monitored => Ui.low,
        FilterPole.notMonitored => Ui.high,
      };

  bool matches(DeviceSignal s) => switch (this) {
        FilterPole.attention => s.needsAttention,
        FilterPole.notAttention => !s.needsAttention,
        FilterPole.trusted => s.device.trusted,
        FilterPole.untrusted => !s.device.trusted,
        FilterPole.online => s.online,
        FilterPole.offline => !s.online,
        FilterPole.monitored => !s.notMonitored,
        FilterPole.notMonitored => s.notMonitored,
      };

  static FilterPole? byName(String name) {
    for (final p in FilterPole.values) {
      if (p.name == name) return p;
    }
    return null;
  }
}

/// Device inventory (PBI-04, PBI-06, PBI-07): all discovered devices,
/// online and offline, with search and filters. Online first, then attention.
class DeviceListScreen extends StatefulWidget {
  const DeviceListScreen({super.key, required this.state, this.filterRequest});

  final AppState state;

  /// Set by the dashboard to open this tab with a specific filter (empty = All).
  final ValueNotifier<Set<FilterPole>?>? filterRequest;

  @override
  State<DeviceListScreen> createState() => _DeviceListScreenState();
}

class _DeviceListScreenState extends State<DeviceListScreen> {
  final _search = TextEditingController();
  final _menu = OverlayPortalController();
  final _menuLink = LayerLink();
  // Selected poles, at most one per axis. Empty = All.
  final Set<FilterPole> _poles = {};
  bool _filterChanged = false;

  @override
  void initState() {
    super.initState();
    _search.addListener(() {
      setState(() {});
      UiMemory.setDeviceSearch(_search.text);
    });
    widget.filterRequest?.addListener(_onFilterRequest);
    _onFilterRequest();
    _restore();
  }

  /// Bring back the filter and search from last time.
  Future<void> _restore() async {
    final stored = await UiMemory.deviceFilter() ?? ''; // comma-joined pole names
    final q = await UiMemory.deviceSearch();
    if (!mounted) return;
    if (!_filterChanged && stored.isNotEmpty) {
      final restored = <FilterPole>{};
      for (final name in stored.split(',')) {
        final p = FilterPoleX.byName(name.trim());
        if (p != null) restored.add(p);
      }
      if (restored.isNotEmpty) setState(() => _poles..clear()..addAll(restored));
    }
    if (_search.text.isEmpty && q.isNotEmpty) _search.text = q;
  }

  void _persist() => UiMemory.setDeviceFilter(_poles.map((p) => p.name).join(','));

  /// Toggle a pole; selecting one clears the opposite pole in its pair.
  void _togglePole(FilterPole p) {
    _filterChanged = true;
    setState(() {
      if (!_poles.remove(p)) {
        _poles.remove(p.opposite);
        _poles.add(p);
      }
    });
    _persist();
  }

  void _selectAll() {
    _filterChanged = true;
    setState(_poles.clear);
    _persist();
  }

  void _applyPoles(Set<FilterPole> poles) {
    _filterChanged = true;
    setState(() => _poles..clear()..addAll(poles));
    _persist();
  }

  @override
  void didUpdateWidget(covariant DeviceListScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.filterRequest != widget.filterRequest) {
      oldWidget.filterRequest?.removeListener(_onFilterRequest);
      widget.filterRequest?.addListener(_onFilterRequest);
      _onFilterRequest();
    }
  }

  @override
  void dispose() {
    widget.filterRequest?.removeListener(_onFilterRequest);
    _search.dispose();
    super.dispose();
  }

  void _onFilterRequest() {
    final f = widget.filterRequest?.value;
    if (f == null) return;
    _applyPoles(f);
    widget.filterRequest?.value = null;
  }

  /// PBI-07: search by device name, IP address, or MAC address. Selected poles
  /// combine (AND); empty set = All.
  List<DeviceSignal> _visible(List<DeviceSignal> all) {
    final q = _search.text.trim().toLowerCase();
    return all.where((s) {
      if (!_poles.every((p) => p.matches(s))) return false;
      if (q.isEmpty) return true;
      final d = s.device;
      return [d.displayName, d.ip ?? '', d.mac].any((v) => v.toLowerCase().contains(q));
    }).toList()
      ..sort(DeviceSignal.compare);
  }

  void _clear() {
    _search.clear();
    _selectAll();
  }

  @override
  Widget build(BuildContext context) {
    final bottomPad = UiSpace.navBottomPad + math.max(0.0, MediaQuery.paddingOf(context).bottom - 14);
    return ListenableBuilder(
      listenable: widget.state,
      builder: (context, _) {
        final state = widget.state;
        final all = Signals.all(state);
        final list = _visible(all);
        return SafeArea(
          bottom: false,
          child: TopFade(child: RefreshIndicator(
            onRefresh: state.refresh,
            color: Ui.acc,
            backgroundColor: Ui.surf,
            child: CustomScrollView(
              slivers: [
                SliverToBoxAdapter(child: _top(state, all)),
                SliverPersistentHeader(
                  pinned: true,
                  delegate: _StickyDelegate(child: _searchBar(all)),
                ),
                SliverToBoxAdapter(child: _indexHead(list.length, state.totalCount)),
                ..._body(list),
                SliverToBoxAdapter(child: SizedBox(height: bottomPad)),
              ],
            ),
          )),
        );
      },
    );
  }

  Widget _top(AppState state, List<DeviceSignal> all) {
    final notMonitored = all.where((s) => s.notMonitored).length;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const KickerRow('ON YOUR NETWORK'),
        Padding(
          padding: const EdgeInsets.fromLTRB(22, 2, 22, 0),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.baseline,
            textBaseline: TextBaseline.alphabetic,
            children: [
              Text('${state.totalCount}', style: UiText.devicesHero),
              const SizedBox(width: 10),
              // The online count already lives in the stats card below, so it is
              // not repeated next to the title.
              Expanded(child: Text('devices', style: UiText.heroSuffix)),
            ],
          ),
        ),
        Container(
          margin: const EdgeInsets.fromLTRB(16, 10, 16, 0),
          padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 11),
          decoration: surfCard(UiRadius.overview),
          child: IntrinsicHeight(
            child: Row(
              children: [
                // Widths follow the longest single word of each label so
                // "UNRECOGNIZED" fits unbroken at the largest text size;
                // two-word labels wrap at their space.
                _overviewCell(92, '${state.totalCount}', 'TOTAL', Ui.ink),
                _divider(),
                _overviewCell(96, '${state.onlineCount}', 'ONLINE', Ui.low),
                _divider(),
                _overviewCell(136, '${state.unrecognizedCount}', 'UNRECOGNIZED', Ui.med),
                _divider(),
                _overviewCell(106, '$notMonitored', 'NOT MONITORED', Ui.high),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _overviewCell(int flex, String value, String label, Color color) => Expanded(
        flex: flex,
        child: Column(
          children: [
            Text(value, style: UiText.overviewNumber.copyWith(color: color)),
            const SizedBox(height: 5),
            // The label wraps to a second line at large text sizes instead of
            // being scaled down to an unreadable size; the card (IntrinsicHeight
            // row) grows with it.
            Text(
              label,
              textAlign: TextAlign.center,
              softWrap: true,
              style: UiText.overviewLabel.copyWith(color: Ui.mute),
            ),
          ],
        ),
      );

  Widget _divider() => Container(width: 1, color: Ui.line);

  Widget _searchBar(List<DeviceSignal> all) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 13, 16, 8),
      child: DecoratedBox(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(UiRadius.search),
          boxShadow: const [
            BoxShadow(color: Color(0x59000000), offset: Offset(0, 10), blurRadius: 18),
          ],
        ),
        child: Row(
          children: [
            Expanded(
              child: Glass(
                color: Ui.fade(Ui.surf, .82),
                radius: UiRadius.search,
                blur: 16,
                height: 50,
                padding: const EdgeInsets.symmetric(horizontal: 18),
                child: Row(
                  children: [
                    Text('/', style: UiText.mono(14, 600, color: Ui.mute)),
                    const SizedBox(width: 10),
                    Expanded(
                      child: TextField(
                        controller: _search,
                        style: UiText.input,
                        cursorColor: Ui.acc,
                        // No box of its own: the theme's input border must not
                        // show inside the glass search pill.
                        decoration: InputDecoration(
                          isCollapsed: true,
                          filled: false,
                          border: InputBorder.none,
                          enabledBorder: InputBorder.none,
                          focusedBorder: InputBorder.none,
                          contentPadding: EdgeInsets.zero,
                          // Shrinks instead of "…" at large text sizes.
                          hint: FittedBox(
                            fit: BoxFit.scaleDown,
                            alignment: Alignment.centerLeft,
                            child: Text('Search name, IP or MAC', style: UiText.input.copyWith(color: Ui.mute)),
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(width: 8),
            CompositedTransformTarget(
              link: _menuLink,
              child: OverlayPortal(
                controller: _menu,
                overlayChildBuilder: (context) => _menuOverlay(all),
                // Fixed-size, icon-only: the search field keeps its width.
                child: FilterButton(
                  key: const ValueKey('deviceFilterButton'),
                  selected: _poles.length,
                  onTap: () => setState(_menu.toggle),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _menuOverlay(List<DeviceSignal> all) {
    // Width of the longest option label at the current text size. Every label
    // is laid out in a box this wide, so when they must shrink (large text)
    // they all shrink by the same factor and stay the same size and weight.
    final scaler = MediaQuery.textScalerOf(context);
    final labelWidth = FilterPole.values.map((p) {
      final tp = TextPainter(
        text: TextSpan(text: p.label, style: UiText.menuItem),
        textDirection: TextDirection.ltr,
        textScaler: scaler,
        maxLines: 1,
      )..layout();
      final w = tp.width;
      tp.dispose();
      return w;
    }).reduce(math.max).ceilToDouble();
    return Stack(
      children: [
        Positioned.fill(
          child: GestureDetector(
            behavior: HitTestBehavior.opaque,
            onTap: () => setState(_menu.hide),
          ),
        ),
        CompositedTransformFollower(
          link: _menuLink,
          targetAnchor: Alignment.bottomRight,
          followerAnchor: Alignment.topRight,
          offset: const Offset(0, 7),
          child: FadeSlideIn(
            duration: const Duration(milliseconds: 250),
            child: SizedBox(
              width: 260,
              child: Glass(
                color: Ui.fade(Ui.surf2, .92),
                radius: UiRadius.dropdown,
                blur: 18,
                shadows: UiShadow.dropdown,
                padding: const EdgeInsets.all(6),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // All = full-width row; selecting it clears every pole.
                    _allRow(all.length),
                    const SizedBox(height: 4),
                    // Four mutually-exclusive pairs, two equal columns.
                    for (var axis = 0; axis < 4; axis++) ...[
                      if (axis > 0) const SizedBox(height: 4),
                      Row(
                        children: [
                          Expanded(child: _poleChip(FilterPole.values[axis * 2], all, labelWidth)),
                          const SizedBox(width: 4),
                          Expanded(child: _poleChip(FilterPole.values[axis * 2 + 1], all, labelWidth)),
                        ],
                      ),
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

  Widget _allRow(int count) {
    final on = _poles.isEmpty;
    return Pressable(
      onTap: () {
        _menu.hide();
        _selectAll();
      },
      semanticLabel: 'All, $count devices${on ? ', selected' : ''}',
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

  Widget _poleChip(FilterPole p, List<DeviceSignal> all, double labelWidth) {
    final on = _poles.contains(p);
    final count = all.where(p.matches).length;
    return Pressable(
      // Multi-select: tapping keeps the menu open so several pairs can be set.
      onTap: () => _togglePole(p),
      semanticLabel: '${p.label}, $count devices${on ? ', selected' : ''}',
      child: Container(
        height: 40,
        padding: const EdgeInsets.symmetric(horizontal: 10),
        decoration: BoxDecoration(
          color: on ? Ui.fade(Ui.acc, .16) : Colors.transparent,
          borderRadius: BorderRadius.circular(UiRadius.dropdownItem),
          border: Border.all(color: on ? Ui.mix(Ui.acc, .45, Ui.line) : Ui.line),
        ),
        child: Row(
          children: [
            GlowDot(p.dot, size: 7, glow: 0),
            const SizedBox(width: 7),
            // Full label always visible: shrink-to-fit instead of ellipsis, so
            // "Not monitored" is never clipped at large fonts while the
            // two-per-row layout is kept. Every label sits in a box as wide as
            // the longest one, so all labels scale by the same factor.
            Expanded(
              child: FittedBox(
                fit: BoxFit.scaleDown,
                alignment: Alignment.centerLeft,
                child: SizedBox(
                  width: labelWidth,
                  child: Text(p.label, maxLines: 1, softWrap: false, style: UiText.menuItem),
                ),
              ),
            ),
            const SizedBox(width: 4),
            // The check's space is always reserved, so selecting an option
            // never changes the room its label has.
            Visibility(
              visible: on,
              maintainSize: true,
              maintainAnimation: true,
              maintainState: true,
              child: Text('✓', style: UiText.sans(12, 800, color: Ui.acc)),
            ),
          ],
        ),
      ),
    );
  }

  Widget _indexHead(int shown, int total) {
    final style = UiText.indexHeader.copyWith(color: Ui.mute);
    return Padding(
      padding: const EdgeInsets.fromLTRB(18, 10, 18, 7),
      child: Row(
        children: [
          // Shrinks at narrow widths with 3-digit counts.
          Expanded(
            child: FittedBox(
              fit: BoxFit.scaleDown,
              alignment: Alignment.centerLeft,
              child: Text('DEVICES · $shown of $total', style: style),
            ),
          ),
          const SizedBox(width: 10),
          Text('NEEDS ATTENTION FIRST', style: style.copyWith(color: Ui.acc)),
        ],
      ),
    );
  }

  List<Widget> _body(List<DeviceSignal> list) {
    if (!widget.state.loadedOnce) {
      return [
        const SliverToBoxAdapter(
          child: Padding(
            padding: EdgeInsets.all(40),
            child: Center(child: UiSpinner(size: 22)),
          ),
        ),
      ];
    }
    if (list.isEmpty) {
      final noDevices = widget.state.devices.isEmpty;
      final q = _search.text.trim();
      final hint = noDevices
          ? 'Devices will appear here once ASSAS discovers them.'
          : q.isNotEmpty
              ? 'Nothing matches “$q”${_poles.isNotEmpty ? ' with the selected filters' : ''}.'
              : 'No devices match the selected filters.';
      return [
        SliverToBoxAdapter(
          child: EmptyDashed(
            margin: const EdgeInsets.fromLTRB(16, 11, 16, 0),
            title: noDevices ? 'No devices yet' : 'No devices found',
            hint: hint,
            action: noDevices
                ? null
                : Pressable(
                    onTap: _clear,
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(UiRadius.pill),
                        border: Border.all(color: Ui.acc),
                      ),
                      child: Text('Clear search', style: UiText.clearSearch.copyWith(color: Ui.acc)),
                    ),
                  ),
          ),
        ),
      ];
    }
    return [
      SliverPadding(
        padding: const EdgeInsets.fromLTRB(16, 5, 16, 0),
        sliver: SliverList.separated(
          itemCount: list.length,
          separatorBuilder: (_, __) => const SizedBox(height: 7),
          itemBuilder: (context, i) => _DeviceRow(
            signal: list[i],
            onTap: () => Navigator.of(context).push(
              MaterialPageRoute(
                builder: (_) => DeviceDetailsScreen(state: widget.state, mac: list[i].device.mac),
              ),
            ),
          ),
        ),
      ),
    ];
  }
}

class _StickyDelegate extends SliverPersistentHeaderDelegate {
  _StickyDelegate({required this.child});

  final Widget child;

  @override
  double get minExtent => 71;

  @override
  double get maxExtent => 71;

  @override
  Widget build(BuildContext context, double shrinkOffset, bool overlapsContent) =>
      SizedBox(height: 71, child: child);

  @override
  bool shouldRebuild(_StickyDelegate old) => true;
}

class _DeviceRow extends StatelessWidget {
  const _DeviceRow({required this.signal, required this.onTap});

  final DeviceSignal signal;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final s = signal;
    final d = s.device;
    final meta = UiText.listMeta.copyWith(color: Ui.mute);
    return Pressable(
      onTap: onTap,
      semanticLabel: '${d.displayName}, ${d.onlineLabel}, ${d.recognitionLabel}',
      child: Opacity(
        opacity: s.online ? 1 : 0.4,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 10),
          decoration: surfCard(UiRadius.row),
          child: Stack(
            clipBehavior: Clip.none,
            children: [
              Positioned(
                left: -11,
                top: -2,
                bottom: -2,
                child: Container(
                  width: 2,
                  decoration: BoxDecoration(
                    color: s.rowAccent,
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              ),
              Row(
                children: [
                  SizedBox(
                    width: 40,
                    child: Align(
                      alignment: Alignment.centerLeft,
                      child: Container(
                        width: 38,
                        height: 38,
                        alignment: Alignment.center,
                        decoration: BoxDecoration(
                          color: Ui.surf2,
                          border: Border.all(color: Ui.line),
                          borderRadius: const BorderRadius.only(
                            topLeft: Radius.circular(12),
                            topRight: Radius.circular(12),
                            bottomRight: Radius.circular(12),
                            bottomLeft: Radius.circular(5),
                          ),
                        ),
                        child: UiIcon(s.icon, size: 19, stroke: 1.8, color: Ui.ink),
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          d.displayName,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: UiText.deviceListName,
                        ),
                        const SizedBox(height: 2),
                        Text(
                          '${d.vendorLabel} · ${d.typeLabel}',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: meta,
                        ),
                        const SizedBox(height: 2),
                        Text(
                          '${d.ipLabel} · ${d.macLabel}',
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                          style: meta,
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 10),
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.end,
                    children: [
                      Text('● ${d.onlineLabel}', style: UiText.listStatus.copyWith(color: s.dotColor)),
                      // PBI-09/10: worst UNRESOLVED alert severity, in the
                      // severity palette (own line — never blended with the
                      // trust/monitoring flag colours below).
                      if (s.hasAlert) ...[
                        const SizedBox(height: 3),
                        Text('${sevUpper(s.alertSev!)} ALERT',
                            style: UiText.listFlag.copyWith(color: s.alertColor)),
                      ],
                      if (s.unrec) ...[
                        const SizedBox(height: 3),
                        Text('UNRECOGNIZED', style: UiText.listFlag.copyWith(color: Ui.med)),
                      ],
                      if (s.notMonitored) ...[
                        const SizedBox(height: 3),
                        Text('NOT MONITORED', style: UiText.listFlag.copyWith(color: Ui.high)),
                      ],
                    ],
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
