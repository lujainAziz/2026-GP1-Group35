import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import '../../state/app_state.dart';
import '../../theme/assas_ui.dart';
import '../../widgets/coming_soon.dart';
import '../../widgets/device_signals.dart';
import '../../widgets/radar_hero.dart';
import '../../widgets/rename_dialog.dart';
import '../../widgets/ui_kit.dart';
import '../../widgets/ui_memory.dart';
import '../../widgets/ui_overlays.dart';
import '../alerts/alert_details_screen.dart';

/// Device details (PBI-05): name, IP, MAC, vendor, type, recognition state,
/// online status, baseline status, last seen, and this device's alerts.
/// Mark as trusted / remove trust (PBI-06).
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
  bool _detailError = false;

  // This device's alerts, fetched independently (GET /devices/{mac}/alerts,
  // paginated) so older alerts are never hidden behind the global page limit.
  List<SecurityAlert>? _deviceAlertList;
  bool _alertsLoaded = false;

  // Order for this device's alerts — useful on devices with many alerts.
  AlertSort _alertSort = AlertSort.newest;

  @override
  void initState() {
    super.initState();
    _loadDetail();
    _loadAlerts();
    UiMemory.deviceAlertSort().then((name) {
      for (final s in AlertSort.values) {
        if (s.name == name && mounted) setState(() => _alertSort = s);
      }
    });
  }

  void _toggleAlertSort() {
    setState(() => _alertSort = _alertSort == AlertSort.newest ? AlertSort.severity : AlertSort.newest);
    UiMemory.setDeviceAlertSort(_alertSort.name);
  }

  /// Sort control for the "Alerts for this device" header. Shows the current
  /// mode in both colour and text: neutral for Newest, the active-button purple
  /// (`Ui.acc`) for Most severe.
  Widget _alertSortButton() {
    final severe = _alertSort == AlertSort.severity;
    final fg = severe ? Ui.acc : Ui.mute;
    Widget content(String label) => Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.swap_vert_rounded, size: 14, color: fg),
            const SizedBox(width: 6),
            Text(label, maxLines: 1, style: UiText.mono(10.5, 700, em: .04, color: fg)),
          ],
        );
    return Pressable(
      semanticLabel: 'Sort: ${_alertSort.label}. Tap to switch.',
      onTap: _toggleAlertSort,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 7),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(UiRadius.pill),
          color: severe ? Ui.fade(Ui.acc, .16) : null,
          border: Border.all(color: severe ? Ui.mix(Ui.acc, .45, Ui.line) : Ui.line),
        ),
        // Fixed to the WIDEST option ("Most severe") so the pill keeps one size
        // on toggle; the shown label is centred. IndexedStack measures both at
        // the current text scale, so the size adapts to the system font size and
        // stays equal for both options.
        child: IndexedStack(
          alignment: Alignment.center,
          index: severe ? 1 : 0,
          children: [content('Newest'), content('Most severe')],
        ),
      ),
    );
  }

  Future<void> _loadDetail() async {
    try {
      final d = await widget.state.repo.getDevice(widget.mac);
      if (mounted) {
        setState(() { _detail = d; _detailError = false; });
      }
    } catch (e) {
      if (!mounted) return;
      widget.state.handleFailure(e);
      setState(() => _detailError = true);
      // Keep the latest list data, but expose a retry for a failed detail read.
    }
  }

  Future<void> _loadAlerts() async {
    if (!Released.alerts) return;
    try {
      final list = await widget.state.repo.getDeviceAlerts(widget.mac);
      if (mounted) setState(() { _deviceAlertList = list; _alertsLoaded = true; });
    } catch (e) {
      if (!mounted) return;
      widget.state.handleFailure(e);
      setState(() => _alertsLoaded = true); // keep last; _deviceAlertList may be null
    }
  }

  /// Mark as trusted, or remove trust (design: one button that toggles).
  Future<void> _setTrusted(Device d, bool trusted) async {
    setState(() => _saving = true);
    try {
      await widget.state.setTrusted(widget.mac, trusted);
      await _loadDetail();
      if (!mounted) return;
      showToast(context, trusted ? '${d.displayName} is now trusted' : 'Trust removed');
    } catch (e) {
      if (widget.state.handleFailure(e) || !mounted) return;
      showToast(context, 'Could not update the device. Try again.');
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  /// Rename the device (empty = back to the detected name).
  Future<void> _rename(Device d) async {
    final name = await showRenameDialog(
      context,
      current: d.displayName,
      detected: d.detectedName,
      hasUserName: d.hasUserName,
    );
    if (name == null || !mounted) return;
    setState(() => _saving = true);
    try {
      await widget.state.repo.renameDevice(widget.mac, name.isEmpty ? null : name);
      await widget.state.refresh();
      await _loadDetail();
      if (!mounted) return;
      showToast(context, name.isEmpty ? 'Back to the detected name' : 'Renamed to $name');
    } catch (e) {
      if (widget.state.handleFailure(e) || !mounted) return;
      showToast(context, 'Could not rename the device. Try again.');
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final mq = MediaQuery.paddingOf(context);
    return Scaffold(
      body: ListenableBuilder(
        listenable: widget.state,
        builder: (context, _) {
          // Prefer the freshest record: list data is refreshed every 5 s,
          // the detail record has extra fields (baseline...).
          final fromList = widget.state.deviceByMac(widget.mac);
          final d = _merge(_detail, fromList);
          if (d == null) {
            return Center(child: _detailError
                ? TextButton(onPressed: _loadDetail, child: const Text('Could not load device. Retry'))
                : const UiSpinner(size: 22));
          }
          final s = Signals.of(widget.state, d);
          final hero = s.heroColor;
          return Stack(
            children: [
              TopFade(top: mq.top, child: ListView(
                padding: EdgeInsets.only(top: mq.top + 44, bottom: 28 + 48 + mq.bottom),
                children: [
                  RadarHero.device(
                    color: hero,
                    icon: s.icon,
                    ripple: (s.hasAlert || s.unrec) && s.online,
                    topLeft: Text(
                      d.typeLabel.toUpperCase(),
                      style: UiText.typeKicker.copyWith(color: Ui.mute),
                    ),
                    topRight: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
                      decoration: BoxDecoration(
                        color: Ui.fade(s.trustColor, .18),
                        borderRadius: BorderRadius.circular(UiRadius.pill),
                      ),
                      child: Text(d.recognitionLabel, style: UiText.pill.copyWith(color: s.trustColor)),
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: UiSpace.pageText),
                    child: Column(
                      children: [
                        // breakName: wrap long machine-style tokens at their
                        // separators instead of mid-word; the column grows.
                        Text(breakName(d.displayName),
                            textAlign: TextAlign.center, style: UiText.deviceName),
                        const SizedBox(height: 8),
                        Pressable(
                          onTap: _saving ? null : () => _rename(d),
                          semanticLabel: 'Rename device',
                          child: Padding(
                            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Text('RENAME ', style: UiText.link.copyWith(color: Ui.acc)),
                                // Pencil flipped to point toward the text.
                                Transform.flip(
                                  flipX: true,
                                  child: Text('✎', style: UiText.link.copyWith(color: Ui.acc)),
                                ),
                              ],
                            ),
                          ),
                        ),
                        const SizedBox(height: 8),
                        Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Container(width: 22, height: 1, color: hero),
                            const SizedBox(width: 10),
                            Flexible(
                              child: Text(
                                s.verdict,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: UiText.verdict.copyWith(color: hero),
                              ),
                            ),
                            const SizedBox(width: 10),
                            Container(width: 22, height: 1, color: hero),
                          ],
                        ),
                      ],
                    ),
                  ),
                  if (_detailError)
                    TextButton(onPressed: _loadDetail,
                        child: const Text('Could not refresh details. Retry')),
                  _identity(d, hero),
                  const SizedBox(height: 8),
                  SpecList(
                    railColor: hero,
                    rows: [
                      ('Vendor',
                          d.vendorInferred
                              ? '${d.vendorLabel} (inferred)'
                              : d.vendorLabel,
                          Ui.ink),
                      ('Type',
                          d.typeInferred
                              ? '${d.typeLabel} (inferred)'
                              : d.typeLabel,
                          Ui.ink),
                      if ((d.model?.trim() ?? '').isNotEmpty &&
                          d.model!.trim() != d.displayName)
                        ('Model',
                            d.modelInferred
                                ? '${d.model!.trim()} (inferred)'
                                : d.model!.trim(),
                            Ui.ink),
                      ('Last seen', TimeFormat.lastSeen(d.lastSeen), Ui.ink),
                      d.monitored == null
                          ? ('Monitoring', 'Unknown', Ui.mute)
                          : d.isNotMonitored
                              ? ('Monitoring', 'Not Monitored', Ui.med)
                              : ('Monitoring', 'Monitored', Ui.low),
                      Released.baseline
                          ? (
                              'Baseline',
                              d.baselineLabel,
                              d.baseline == BaselineStatus.established ? Ui.ink : Ui.med,
                            )
                          : ('Baseline', 'SOON · SPRINT 3', Ui.acc),
                    ],
                  ),
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
                    child: PillButton(
                      label: d.trusted ? 'Remove trust' : 'Mark as trusted',
                      // Reserve the wider label so the pill keeps one width when
                      // trust toggles (no jump).
                      reserveLabel: 'Mark as trusted',
                      filled: !d.trusted,
                      busy: _saving,
                      onTap: () => _setTrusted(d, !d.trusted),
                    ),
                  ),
                  SectionHeader(
                    'Alerts for this device',
                    padding: const EdgeInsets.fromLTRB(22, 26, 22, 10),
                    // Sort control sits to the right of the header, on the same
                    // row; only once there are enough alerts to reorder.
                    trailing: (_deviceAlertList?.length ?? 0) >= 2 ? _alertSortButton() : null,
                  ),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: UiSpace.pageCards),
                    child: _deviceAlerts(context, d),
                  ),
                ],
              )),
              DetailHeader(trailing: _statusPill(s)),
            ],
          );
        },
      ),
    );
  }

  Widget _statusPill(DeviceSignal s) {
    return Glass(
      color: Ui.fade(Ui.bg, .62),
      radius: UiRadius.pill,
      padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 6),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          PulseDot(s.dotColor),
          const SizedBox(width: 6),
          Text(s.device.onlineLabel.toUpperCase(), style: UiText.statusPill.copyWith(color: s.dotColor)),
        ],
      ),
    );
  }

  Widget _identity(Device d, Color hero) {
    Widget bracket({required bool topLeft}) => RotatedBox(
          quarterTurns: topLeft ? 0 : 2,
          child: CustomPaint(size: const Size(14, 14), painter: _BracketPainter(hero)),
        );
    // One uniform style for every address VALUE (IPv4, IPv6, MAC) and a smaller
    // uniform style for the labels. The value is tap-to-copy (raw text); long
    // addresses wrap at `:`/`.` groups at the SAME font size (no shrink/clip).
    final labelStyle = UiText.mono(9, 600, em: .14, color: Ui.mute);
    final valueStyle = UiText.ip; // same size + weight for IPv4, IPv6 and MAC
    Widget field(String k, String v) => Padding(
          padding: const EdgeInsets.fromLTRB(6, 6, 6, 8),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(k, style: labelStyle),
              const SizedBox(height: 5),
              Pressable(
                semanticLabel: 'Copy $k',
                onTap: () {
                  Clipboard.setData(ClipboardData(text: v));
                  showToast(context, 'Copied');
                },
                child: Text(breakAddress(v), style: valueStyle, softWrap: true),
              ),
            ],
          ),
        );
    return Container(
      margin: const EdgeInsets.fromLTRB(16, 22, 16, 0),
      decoration: surfCard(UiRadius.card),
      child: Stack(
        children: [
          Positioned(left: 10, top: 10, child: Opacity(opacity: .7, child: bracket(topLeft: true))),
          Positioned(right: 10, bottom: 10, child: Opacity(opacity: .7, child: bracket(topLeft: false))),
          Padding(
            padding: const EdgeInsets.fromLTRB(18, 18, 18, 16),
            child: SizedBox(
              width: double.infinity,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  field('IP ADDRESS', d.ipLabel),
                  for (final address in d.displayIpv6.where((v) => v != d.ip))
                    field('IPV6 ADDRESS', address),
                  field('MAC ADDRESS', d.macLabel),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _deviceAlerts(BuildContext context, Device d) {
    if (!Released.alerts) {
      return const EmptyDashed(
        padding: EdgeInsets.all(26),
        title: 'Coming soon',
        hint: 'Alerts for this device will appear here.',
      );
    }
    if (!_alertsLoaded) {
      return const Padding(padding: EdgeInsets.all(26), child: Center(child: UiSpinner(size: 20)));
    }
    final raw = _deviceAlertList;
    if (raw == null || raw.isEmpty) {
      return EmptyDashed(
        padding: const EdgeInsets.all(26),
        title: raw == null ? 'Alerts are not available yet' : 'No alerts for this device',
        hint: 'Alerts related to this device will appear here.',
      );
    }
    final alerts = sortedAlerts(raw, _alertSort);
    return Column(
      children: [
        for (var i = 0; i < alerts.length; i++) ...[
          if (i > 0) const SizedBox(height: 8),
          TimelineAlertCard(
            alert: alerts[i],
            compact: true,
            dotSize: 11,
            railWidth: 22,
            onTap: () async {
              await Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => AlertDetailsScreen(state: widget.state, alertId: alerts[i].id),
                ),
              );
              // State may have changed on the details screen; refresh this list.
              await _loadAlerts();
            },
          ),
        ],
      ],
    );
  }

  /// Detail record has more fields; list record is refreshed more often.
  Device? _merge(Device? detail, Device? fromList) {
    if (detail == null) return fromList;
    if (fromList == null) return detail;
    return Device(
      mac: detail.mac,
      ip: fromList.ip,
      ipv6: detail.ipv6,
      userName: fromList.userName,
      hostname: fromList.hostname,
      model: fromList.model,
      vendor: fromList.vendor,
      deviceType: fromList.deviceType,
      presence: fromList.presence,
      trusted: fromList.trusted,
      monitored: fromList.monitored ?? detail.monitored,
      baseline: detail.baseline,
      lastSeen: fromList.lastSeen,
      vendorSource: fromList.vendorSource ?? detail.vendorSource,
      classSource: detail.classSource,
      modelSource: detail.modelSource,
    );
  }
}

/// Corner bracket (top-left shape; rotated for bottom-right).
class _BracketPainter extends CustomPainter {
  _BracketPainter(this.color);

  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    const r = UiRadius.bracket;
    final p = Path()
      ..moveTo(.5, size.height)
      ..lineTo(.5, r)
      ..arcToPoint(const Offset(r, .5), radius: const Radius.circular(r - .5))
      ..lineTo(size.width, .5);
    canvas.drawPath(
      p,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1
        ..color = color,
    );
  }

  @override
  bool shouldRepaint(_BracketPainter old) => old.color != color;
}
