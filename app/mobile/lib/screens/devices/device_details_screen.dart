import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../state/app_state.dart';
import '../../widgets/alert_tile.dart';
import '../../widgets/badges.dart';
import '../../widgets/common.dart';
import '../../widgets/device_icon.dart';
import '../../widgets/purple_header.dart';
import '../alerts/alert_details_screen.dart';

/// Device details (PBI-05): name, IP, MAC, vendor, type, recognition state,
/// online status, baseline status, last seen, and this device's alerts.
/// Mark as trusted (PBI-06).
class DeviceDetailsScreen extends StatefulWidget {
  const DeviceDetailsScreen({super.key, required this.state, required this.mac});

  final AppState state;
  final String mac;

  @override
  State<DeviceDetailsScreen> createState() => _DeviceDetailsScreenState();
}

class _DeviceDetailsScreenState extends State<DeviceDetailsScreen> {
  Device? _detail; // full record from GET /devices/{mac}
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    _loadDetail();
  }

  Future<void> _loadDetail() async {
    try {
      final d = await widget.state.repo.getDevice(widget.mac);
      if (mounted) setState(() => _detail = d);
    } catch (_) {
      // Keep showing the list data.
    }
  }

  Future<void> _markTrusted() async {
    setState(() => _saving = true);
    try {
      await widget.state.setTrusted(widget.mac, true);
      await _loadDetail();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Device marked as trusted.')),
      );
    } catch (_) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Could not update the device. Try again.')),
      );
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: ListenableBuilder(
        listenable: widget.state,
        builder: (context, _) {
          // Prefer the freshest record: list data is refreshed every 5 s,
          // the detail record has extra fields (baseline...).
          final fromList = widget.state.deviceByMac(widget.mac);
          final d = _merge(_detail, fromList);
          if (d == null) {
            return const Center(child: CircularProgressIndicator());
          }
          return ListView(
            padding: EdgeInsets.zero,
            children: [
              PurpleHeader(
                backLabel: 'Devices',
                titleWidget: Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(3),
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(14),
                      ),
                      child: DeviceIcon(device: d, size: 44),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            d.displayName,
                            style: AssasText.headerTitleSmall,
                          ),
                          const SizedBox(height: 6),
                          Wrap(
                            spacing: 8,
                            runSpacing: 6,
                            crossAxisAlignment: WrapCrossAlignment.center,
                            children: [
                              LabelBadge(
                                d.recognitionLabel,
                                d.trusted ? BadgeColors.trusted : BadgeColors.unrecognized,
                              ),
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                                decoration: BoxDecoration(
                                  color: Colors.white.withValues(alpha: 0.16),
                                  borderRadius: BorderRadius.circular(6),
                                ),
                                child: OnlineIndicator(online: d.isOnline, onDark: true),
                              ),
                              if (d.isNotMonitored)
                                LabelBadge('Not monitored', BadgeColors.notMonitored),
                            ],
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    AppCard(
                      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                      child: Column(
                        children: [
                          InfoRow('IP address', d.ipLabel),
                          const Divider(height: 1),
                          InfoRow('MAC address', d.macLabel),
                          const Divider(height: 1),
                          InfoRow('Vendor', d.vendorLabel),
                          const Divider(height: 1),
                          InfoRow('Device type', d.typeLabel),
                          const Divider(height: 1),
                          InfoRow('Last seen', TimeFormat.lastSeen(d.lastSeen)),
                          const Divider(height: 1),
                          InfoRow(
                            'Behavior baseline',
                            d.baselineLabel,
                            valueColor: d.baseline == BaselineStatus.established
                                ? AssasColors.online
                                : AssasColors.warningFg,
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 14),
                    if (!d.trusted)
                      FilledButton.icon(
                        onPressed: _saving ? null : _markTrusted,
                        icon: _saving
                            ? const SizedBox(
                                width: 18,
                                height: 18,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: Colors.white,
                                ),
                              )
                            : const Icon(Icons.verified_user_outlined),
                        label: const Text('Mark as trusted'),
                      ),
                    const SizedBox(height: 20),
                    const SectionTitle('Alerts for this device'),
                    const SizedBox(height: 6),
                    ..._deviceAlerts(context, d),
                  ],
                ),
              ),
            ],
          );
        },
      ),
    );
  }

  List<Widget> _deviceAlerts(BuildContext context, Device d) {
    final alerts = widget.state.alertsForDevice(d.mac);
    if (alerts == null) {
      return const [
        EmptyState(
          icon: Icons.notifications_none_rounded,
          title: 'Alerts are not available yet',
          subtitle: 'Alerts related to this device will appear here.',
        ),
      ];
    }
    if (alerts.isEmpty) {
      return const [
        EmptyState(
          icon: Icons.notifications_none_rounded,
          title: 'No alerts for this device',
          subtitle: 'Alerts related to this device will appear here.',
        ),
      ];
    }
    return [
      for (final a in alerts) ...[
        AlertTile(
          alert: a,
          onTap: () => Navigator.of(context).push(
            MaterialPageRoute(
              builder: (_) => AlertDetailsScreen(state: widget.state, alertId: a.id),
            ),
          ),
        ),
        const SizedBox(height: 10),
      ],
    ];
  }

  /// Detail record has more fields; list record is refreshed more often.
  Device? _merge(Device? detail, Device? fromList) {
    if (detail == null) return fromList;
    if (fromList == null) return detail;
    return Device(
      mac: detail.mac,
      ip: fromList.ip ?? detail.ip,
      hostname: fromList.hostname ?? detail.hostname,
      model: fromList.model ?? detail.model,
      vendor: fromList.vendor ?? detail.vendor,
      deviceType: fromList.deviceType ?? detail.deviceType,
      presence: fromList.presence,
      trusted: fromList.trusted || detail.trusted,
      monitored: fromList.monitored ?? detail.monitored,
      baseline: detail.baseline,
      lastSeen: fromList.lastSeen ?? detail.lastSeen,
    );
  }
}
