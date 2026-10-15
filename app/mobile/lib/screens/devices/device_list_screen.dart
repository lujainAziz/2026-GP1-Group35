import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../../state/app_state.dart';
import '../../theme/assas_ui.dart';
import '../../widgets/device_signals.dart';
import '../../widgets/ui_icons.dart';
import '../../widgets/ui_kit.dart';
import '../../widgets/ui_memory.dart';
import 'device_details_screen.dart';

enum DeviceFilter { all, attention, trusted, unrecognized, notMonitored, offline }

extension on DeviceFilter {
  String get label => switch (this) {
        DeviceFilter.all => 'All',
        DeviceFilter.attention => 'Attention',
        DeviceFilter.trusted => 'Trusted',
        DeviceFilter.unrecognized => 'Unrecognized',
        DeviceFilter.notMonitored => 'Not Monitored',
        DeviceFilter.offline => 'Offline',
      };

  Color get dot => switch (this) {
        DeviceFilter.all => Ui.acc,
        DeviceFilter.attention => Ui.high,
        DeviceFilter.trusted => Ui.low,
        DeviceFilter.unrecognized => Ui.med,
        DeviceFilter.notMonitored => Ui.high,
        DeviceFilter.offline => Ui.mute,
      };

  bool matches(DeviceSignal s) => switch (this) {
        DeviceFilter.all => true,
        DeviceFilter.attention => s.needsAttention,
        DeviceFilter.trusted => s.device.trusted,
        DeviceFilter.unrecognized => s.unrec,
        DeviceFilter.notMonitored => s.notMonitored,
        DeviceFilter.offline => !s.online,
      };
}

/// Device inventory (PBI-04, PBI-06, PBI-07): all discovered devices,
/// online and offline, with search and filters. Attention first.
class DeviceListScreen extends StatefulWidget {
  const DeviceListScreen({super.key, required this.state, this.filterRequest});

  final AppState state;

  /// Set by the dashboard to open this tab with a filter.
  final ValueNotifier<DeviceFilter?>? filterRequest;

  @override
  State<DeviceListScreen> createState() => _DeviceListScreenState();
}

class _DeviceListScreenState extends State<DeviceListScreen> {
  final _search = TextEditingController();
  final _menu = OverlayPortalController();
  final _menuLink = LayerLink();
  DeviceFilter _filter = DeviceFilter.all;

  @override
  void initState() {
    super.initState();
    _search.addListener(() {
      setState(() {});
      UiMemory.setDeviceSearch(_search.text);
    });
    widget.filterRequest?.addListener(_onFilterRequest);
    _restore();
  }

  /// Bring back the filter and search from last time.
  Future<void> _restore() async {
    final name = await UiMemory.deviceFilter();
    final q = await UiMemory.deviceSearch();
    if (!mounted) return;
    for (final f in DeviceFilter.values) {
      if (f.name == name && widget.filterRequest?.value == null) setState(() => _filter = f);
    }
    if (_search.text.isEmpty && q.isNotEmpty) _search.text = q;
  }

  void _setFilter(DeviceFilter f) {
    setState(() => _filter = f);
    UiMemory.setDeviceFilter(f.name);
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
    _setFilter(f);
    widget.filterRequest?.value = null;
  }

  /// PBI-07: search by device name, IP address, or MAC address.
  List<DeviceSignal> _visible(List<DeviceSignal> all) {
    final q = _search.text.trim().toLowerCase();
    return all.where((s) {
      if (!_filter.matches(s)) return false;
      if (q.isEmpty) return true;
      final d = s.device;
      return [d.displayName, d.ip ?? '', d.mac].any((v) => v.toLowerCase().contains(q));
    }).toList()
      ..sort(DeviceSignal.compare);
  }

  void _clear() {
    _search.clear();
    _setFilter(DeviceFilter.all);
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
              Text('devices', style: UiText.heroSuffix),
              const Spacer(),
              Text(
                '● ${state.onlineCount} online',
                style: UiText.mono(12, 500, color: Ui.low),
              ),
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
                _overviewCell(115, '${state.totalCount}', 'TOTAL', Ui.ink),
                _divider(),
                _overviewCell(100, '${state.onlineCount}', 'ONLINE', Ui.low),
                _divider(),
                _overviewCell(100, '${state.unrecognizedCount}', 'UNRECOGNIZED', Ui.med),
                _divider(),
                _overviewCell(115, '$notMonitored', 'NOT MONITORED', Ui.high),
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
            FittedBox(
              fit: BoxFit.scaleDown,
              child: Text(label, style: UiText.overviewLabel.copyWith(color: Ui.mute)),
            ),
          ],
        ),
      );

  Widget _divider() => Container(width: 1, color: Ui.line);

  Widget _searchBar(List<DeviceSignal> all) {
    final active = _filter != DeviceFilter.all || _menu.isShowing;
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
                          hintText: 'Search name, IP or MAC',
                          hintStyle: UiText.input.copyWith(color: Ui.mute),
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
                child: Pressable(
                  onTap: () => setState(_menu.toggle),
                  semanticLabel: 'Filter devices, ${_filter.label}',
                  child: Glass(
                    color: active ? Ui.mix(Ui.acc, .22, Ui.surf) : Ui.fade(Ui.surf, .82),
                    border: active ? Ui.mix(Ui.acc, .45, Ui.line) : Ui.line,
                    radius: UiRadius.search,
                    blur: 16,
                    height: 50,
                    padding: const EdgeInsets.fromLTRB(14, 0, 16, 0),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        UiIcon(UiIcons.filter, size: 18, stroke: 2, color: Ui.ink),
                        if (_filter != DeviceFilter.all) ...[
                          const SizedBox(width: 8),
                          GlowDot(_filter.dot, glow: 0),
                          const SizedBox(width: 6),
                          Text(_filter.label, style: UiText.sans(12, 700)),
                        ],
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _menuOverlay(List<DeviceSignal> all) {
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
              width: 236,
              child: Glass(
                color: Ui.fade(Ui.surf2, .92),
                radius: UiRadius.dropdown,
                blur: 18,
                shadows: UiShadow.dropdown,
                padding: const EdgeInsets.all(6),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    for (final f in DeviceFilter.values) _menuRow(f, all.where(f.matches).length),
                  ],
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _menuRow(DeviceFilter f, int count) {
    final on = f == _filter;
    return Pressable(
      onTap: () {
        _menu.hide();
        _setFilter(f);
      },
      semanticLabel: '${f.label}, $count devices${on ? ', selected' : ''}',
      child: Container(
        height: 42,
        padding: const EdgeInsets.symmetric(horizontal: 12),
        decoration: BoxDecoration(
          color: on ? Ui.fade(Ui.acc, .16) : Colors.transparent,
          borderRadius: BorderRadius.circular(UiRadius.dropdownItem),
        ),
        child: Row(
          children: [
            GlowDot(f.dot, size: 8, glow: 0),
            const SizedBox(width: 10),
            Expanded(child: Text(f.label, style: UiText.menuItem)),
            Text('$count', style: UiText.tabCount.copyWith(color: Ui.mute)),
            const SizedBox(width: 10),
            SizedBox(
              width: 14,
              child: Text(on ? '✓' : '', style: UiText.sans(13, 800, color: Ui.acc)),
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
          Text('DEVICE INDEX · $shown / $total', style: style),
          const Spacer(),
          Text('ATTENTION FIRST', style: style.copyWith(color: Ui.acc)),
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
              ? 'Nothing matches “$q”${_filter != DeviceFilter.all ? ' in ${_filter.label}' : ''}.'
              : 'No devices in ${_filter.label}.';
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
                          maxLines: 1,
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
