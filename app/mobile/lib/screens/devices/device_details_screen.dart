import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../state/app_state.dart';
import '../../theme/assas_ui.dart';
import '../../widgets/coming_soon.dart';
import '../../widgets/device_signals.dart';
import '../../widgets/radar_hero.dart';
import '../../widgets/rename_dialog.dart';
import '../../widgets/ui_kit.dart';
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

  @override
  void initState() {
    super.initState();
    _loadDetail();
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
                        Text(d.displayName, textAlign: TextAlign.center, style: UiText.deviceName),
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
                      ('Vendor', d.vendorLabel, Ui.ink),
                      ('Type', d.typeWithModel, Ui.ink),
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
                      filled: !d.trusted,
                      busy: _saving,
                      onTap: () => _setTrusted(d, !d.trusted),
                    ),
                  ),
                  const SectionHeader(
                    'Alerts for this device',
                    padding: EdgeInsets.fromLTRB(22, 26, 22, 10),
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
    Widget field(String k, String v, TextStyle style) => Padding(
          padding: const EdgeInsets.fromLTRB(6, 6, 6, 8),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(k, style: UiText.identityLabel.copyWith(color: Ui.mute)),
              const SizedBox(height: 5),
              Text(v, style: style),
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
                  field('IP ADDRESS', d.ipLabel, UiText.ip),
                  field('MAC ADDRESS', d.macLabel, UiText.mac),
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
        hint: 'Alerts for this device arrive with threat detection.',
        action: SoonTag(2),
      );
    }
    final alerts = widget.state.alertsForDevice(d.mac);
    if (alerts == null || alerts.isEmpty) {
      return EmptyDashed(
        padding: const EdgeInsets.all(26),
        title: alerts == null ? 'Alerts are not available yet' : 'All quiet',
        hint: 'Alerts related to this device will appear here.',
      );
    }
    return Column(
      children: [
        for (var i = 0; i < alerts.length; i++) ...[
          if (i > 0) const SizedBox(height: 8),
          TimelineAlertCard(
            alert: alerts[i],
            compact: true,
            dotSize: 11,
            railWidth: 22,
            onTap: () => Navigator.of(context).push(
              MaterialPageRoute(
                builder: (_) => AlertDetailsScreen(state: widget.state, alertId: alerts[i].id),
              ),
            ),
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
