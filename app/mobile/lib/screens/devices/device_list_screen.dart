import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../state/app_state.dart';
import '../../widgets/badges.dart';
import '../../widgets/common.dart';
import '../../widgets/device_icon.dart';
import '../../widgets/purple_header.dart';
import 'device_details_screen.dart';

enum DeviceFilter { all, trusted, unrecognized }

/// Device inventory (PBI-04, PBI-06, PBI-07): all discovered devices,
/// online and offline, with search and recognition filters.
class DeviceListScreen extends StatefulWidget {
  const DeviceListScreen({super.key, required this.state});

  final AppState state;

  @override
  State<DeviceListScreen> createState() => _DeviceListScreenState();
}

class _DeviceListScreenState extends State<DeviceListScreen> {
  final _search = TextEditingController();
  DeviceFilter _filter = DeviceFilter.all;

  @override
  void initState() {
    super.initState();
    _search.addListener(() => setState(() {}));
  }

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  /// PBI-07: search by device name, IP address, or MAC address.
  List<Device> _visible(List<Device> all) {
    final q = _search.text.trim().toLowerCase();
    return all.where((d) {
      final matchesFilter = switch (_filter) {
        DeviceFilter.all => true,
        DeviceFilter.trusted => d.trusted,
        DeviceFilter.unrecognized => d.isUnrecognized,
      };
      if (!matchesFilter) return false;
      if (q.isEmpty) return true;
      return d.displayName.toLowerCase().contains(q) ||
          (d.ip ?? '').toLowerCase().contains(q) ||
          d.mac.toLowerCase().contains(q);
    }).toList()
      // Online first, then by name
      ..sort((a, b) {
        if (a.isOnline != b.isOnline) return a.isOnline ? -1 : 1;
        return a.displayName.toLowerCase().compareTo(b.displayName.toLowerCase());
      });
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: widget.state,
      builder: (context, _) {
        final state = widget.state;
        final list = _visible(state.devices);
        return Column(
          children: [
            PurpleHeader(
              title: 'Devices',
              trailing: ConnectionPill(status: state.connection),
              bottom: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  TextField(
                    controller: _search,
                    decoration: InputDecoration(
                      hintText: 'Search by name, IP or MAC',
                      prefixIcon: Icon(Icons.search, color: AssasColors.muted),
                      suffixIcon: _search.text.isEmpty
                          ? null
                          : IconButton(
                              icon: Icon(Icons.close, color: AssasColors.muted),
                              onPressed: _search.clear,
                            ),
                    ),
                  ),
                  const SizedBox(height: 10),
                  Row(
                    children: [
                      _chip('All', DeviceFilter.all),
                      const SizedBox(width: 8),
                      _chip('Trusted', DeviceFilter.trusted),
                      const SizedBox(width: 8),
                      _chip('Unrecognized', DeviceFilter.unrecognized),
                    ],
                  ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 12, 20, 4),
              child: Align(
                alignment: Alignment.centerLeft,
                child: Text(
                  '${state.totalCount} devices, ${state.onlineCount} online',
                  style: AssasText.mutedLabel,
                ),
              ),
            ),
            Expanded(
              child: RefreshIndicator(
                onRefresh: state.refresh,
                child: _body(context, list),
              ),
            ),
          ],
        );
      },
    );
  }

  Widget _body(BuildContext context, List<Device> list) {
    if (!widget.state.loadedOnce) {
      return const Center(child: CircularProgressIndicator());
    }
    if (list.isEmpty) {
      final noDevices = widget.state.devices.isEmpty;
      return ListView(
        padding: const EdgeInsets.all(16),
        children: [
          EmptyState(
            icon: noDevices ? Icons.devices_other_rounded : Icons.search_off_rounded,
            title: noDevices ? 'No devices yet' : 'No matching devices',
            subtitle: noDevices
                ? 'Devices will appear here once Assas discovers them.'
                : 'Try another search or filter.',
          ),
        ],
      );
    }
    return ListView.separated(
      padding: const EdgeInsets.fromLTRB(16, 6, 16, kBottomNavClearance),
      itemCount: list.length,
      separatorBuilder: (_, __) => const SizedBox(height: 10),
      itemBuilder: (context, i) => _DeviceCard(
        device: list[i],
        onTap: () => Navigator.of(context).push(
          MaterialPageRoute(
            builder: (_) => DeviceDetailsScreen(state: widget.state, mac: list[i].mac),
          ),
        ),
      ),
    );
  }

  Widget _chip(String label, DeviceFilter value) {
    final selected = _filter == value;
    return GestureDetector(
      onTap: () => setState(() => _filter = value),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 150),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
        decoration: BoxDecoration(
          color: selected ? Colors.white : Colors.white.withValues(alpha: 0.16),
          borderRadius: BorderRadius.circular(20),
        ),
        child: Text(
          label,
          style: TextStyle(
            color: selected ? AssasColors.button : Colors.white,
            fontWeight: FontWeight.w700,
            fontSize: 13,
          ),
        ),
      ),
    );
  }
}

class _DeviceCard extends StatelessWidget {
  const _DeviceCard({required this.device, required this.onTap});

  final Device device;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final d = device;
    return AppCard(
      onTap: onTap,
      child: Row(
        children: [
          DeviceIcon(device: d),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  d.displayName,
                  style: AssasText.cardTitle,
                ),
                const SizedBox(height: 2),
                Text(
                  '${d.vendorLabel}, ${d.typeLabel}',
                  style: AssasText.secondary,
                ),
                const SizedBox(height: 2),
                Text(
                  d.ipLabel,
                  style: AssasText.small,
                ),
                Text(
                  d.macLabel,
                  style: AssasText.small,
                ),
              ],
            ),
          ),
          Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              OnlineIndicator(online: d.isOnline),
              if (d.isUnrecognized) ...[
                const SizedBox(height: 6),
                LabelBadge('Unrecognized', BadgeColors.unrecognized),
              ],
              if (d.isNotMonitored) ...[
                const SizedBox(height: 6),
                LabelBadge('Not monitored', BadgeColors.notMonitored),
              ],
            ],
          ),
        ],
      ),
    );
  }
}
