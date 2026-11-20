import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../state/app_state.dart';
import '../../theme/assas_ui.dart';
import '../../widgets/coming_soon.dart';
import '../../widgets/device_signals.dart';
import '../../widgets/radar_hero.dart';
import '../../widgets/ui_icons.dart';
import '../../widgets/ui_kit.dart';
import '../../widgets/ui_overlays.dart';
import '../devices/device_details_screen.dart';

/// Alert details: severity, state, plain-language explanation (PBI-18),
/// affected device and first detection, repeated-detection details, and the
/// resolve action (PBI-19; Release 1: New -> Resolved only).
/// No raw SHAP values, model scores, or feature names are shown.
class AlertDetailsScreen extends StatefulWidget {
  const AlertDetailsScreen({super.key, required this.state, required this.alertId});

  final AppState state;
  final String alertId;

  @override
  State<AlertDetailsScreen> createState() => _AlertDetailsScreenState();
}

class _AlertDetailsScreenState extends State<AlertDetailsScreen> {
  bool _saving = false;
  // Fetched directly by id so the alert survives leaving the loaded/paginated
  // list (the global page can scroll past it while this screen is open).
  SecurityAlert? _fetched;

  @override
  void initState() {
    super.initState();
    if (widget.state.alertById(widget.alertId) == null) _fetch();
  }

  Future<void> _fetch() async {
    try {
      final a = await widget.state.repo.getAlertById(widget.alertId);
      if (mounted && a != null) setState(() => _fetched = a);
    } catch (e) {
      if (mounted) widget.state.handleFailure(e);
    }
  }

  Future<void> _resolve() async {
    setState(() => _saving = true);
    try {
      await widget.state.setAlertState(widget.alertId, AlertState.resolved);
      await _fetch(); // reflect the new state even if it is off the loaded page
      if (!mounted) return;
      showToast(context, 'Marked as resolved');
    } catch (e) {
      if (widget.state.handleFailure(e) || !mounted) return;
      showToast(context, 'Could not update the alert. Try again.');
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
          // Prefer the copy we fetched directly (set on open-if-missing and after
          // every state change) over the polled list copy, so a poll that is in
          // flight can't momentarily show the pre-change state.
          final a = _fetched ?? widget.state.alertById(widget.alertId);
          if (a == null) {
            return Stack(
              children: [
                ListView(
                  padding: EdgeInsets.fromLTRB(16, mq.top + 64, 16, 28),
                  children: const [
                    EmptyDashed(
                      title: 'Alert not found',
                      hint: 'This alert is no longer available.',
                    ),
                  ],
                ),
                const DetailHeader(trailing: SizedBox()),
              ],
            );
          }
          final c = sevColor(a.severity);
          final open = a.isUnresolved;
          return Stack(
            children: [
              TopFade(top: mq.top, child: ListView(
                padding: EdgeInsets.only(top: mq.top + 44, bottom: 28 + 48 + mq.bottom),
                children: [
                  RadarHero.alert(
                    color: c,
                    ripple: open,
                    topLeft: Text(sevUpper(a.severity), style: UiText.mono(9.5, 700, em: .14, color: c)),
                    topRight: Text(kindUpper(a), style: UiText.mono(9, 600, em: .14, color: Ui.mute)),
                  ),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: UiSpace.pageText),
                    child: Column(
                      children: [
                        Text(a.title, textAlign: TextAlign.center, style: UiText.alertTitle),
                        const SizedBox(height: 10),
                        // "{device} · {first detection time}" (Release 1).
                        _deviceLink(context, a),
                      ],
                    ),
                  ),
                  // Plain-language explanation per classtype (Sprint 2, Option 2),
                  // followed by the device role line when it is known.
                  if (Released.alertExplanations) ...[
                    SectionHeader(
                      'What happened',
                      padding: const EdgeInsets.fromLTRB(22, 24, 22, 8),
                      trailing: Text('ASSAS / EXPLAIN', style: UiText.mono(10, 500, color: Ui.mute)),
                    ),
                    _explain(a, c),
                  ],
                  const SectionHeader(
                    'Signal details',
                    padding: EdgeInsets.fromLTRB(22, 24, 22, 8),
                  ),
                  // Device shown once via the tappable pill under the title, so
                  // it is not repeated here. Repeated detections of the same rule
                  // on the same device (5-minute sliding window) are one alert:
                  // its count and first/last detection times are shown. The
                  // original rule name is always kept here. The rule ID and ports
                  // are never shown (team decision; they remain in the database
                  // and API).
                  SpecList(
                    railColor: c,
                    copyable: const {'Source IP', 'Destination IP'},
                    onCopy: (_) => showToast(context, 'Copied'),
                    rows: [
                      ('Alert type', a.kindLabel, Ui.ink),
                      if (a.kind == AlertKind.threat && a.ruleName != null)
                        ('Rule', a.ruleName!, Ui.ink),
                      ('Severity', a.severityLabel, c),
                      ('Detections', '${a.occurrenceCount}', Ui.ink),
                      ('First detected', TimeFormat.alertTime(a.firstDetected), Ui.ink),
                      ('Last detected', TimeFormat.alertTime(a.lastTime ?? a.time), Ui.ink),
                      if (a.kind == AlertKind.threat && a.sourceIp != null)
                        ('Source IP', a.sourceIp!, Ui.ink),
                      if (a.kind == AlertKind.threat && a.destinationIp != null)
                        ('Destination IP', a.destinationIp!, Ui.ink),
                    ],
                  ),
                  // Resolve arrives with alert management (PBI-19).
                  if (!Released.alertManagement)
                    const Padding(
                      padding: EdgeInsets.fromLTRB(16, 14, 16, 0),
                      child: Center(child: SoonTag(5)),
                    )
                  else
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
                    child: PillButton(
                      label: 'Resolve',
                      opacity: open ? 1 : .35,
                      onTap: _saving || !open ? null : _resolve,
                    ),
                  ),
                  if (!open && Released.alertManagement)
                    DashedBox(
                      radius: 18,
                      color: Ui.mix(Ui.low, .42, Ui.line),
                      margin: const EdgeInsets.fromLTRB(16, 10, 16, 0),
                      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                      child: SizedBox(
                        width: double.infinity,
                        child: Text(
                          '✓ RESOLVED — kept in history for context',
                          textAlign: TextAlign.center,
                          style: UiText.mono(11, 600, color: Ui.low),
                        ),
                      ),
                    ),
                ],
              )),
              DetailHeader(
                trailing: !Released.alertManagement
                    ? const SizedBox.shrink()
                    : Container(
                  padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
                  decoration: BoxDecoration(
                    color: stateBg(a),
                    borderRadius: BorderRadius.circular(UiRadius.pill),
                  ),
                  child: Text(a.stateLabel, style: UiText.pill.copyWith(color: stateColor(a))),
                ),
              ),
            ],
          );
        },
      ),
    );
  }

  /// "{device} · {first detection time}" pill; opens the device when it is
  /// known. Unlinked alerts read "Unknown device · {time}".
  Widget _deviceLink(BuildContext context, SecurityAlert a) {
    final mac = a.deviceMac;
    final device = mac == null ? null : widget.state.deviceByMac(mac);
    final known = device != null;
    // Prefer the inventory's display name (already machine-id-aware); otherwise
    // sanitize the alert's own name so opaque identifiers show "Unknown device".
    final name = mac == null ? 'Unknown device' : device?.displayName ?? a.displayDeviceName;
    final line = '$name · ${TimeFormat.alertDetected(a.firstDetected)}';
    return Pressable(
      onTap: known
          ? () => Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => DeviceDetailsScreen(state: widget.state, mac: mac!),
                ),
              )
          : null,
      child: Container(
        padding: const EdgeInsets.fromLTRB(12, 5, 8, 5),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(UiRadius.pill),
          border: Border.all(color: Ui.line),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Flexible(
              child: Text(
                line,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: UiText.secondary,
              ),
            ),
            if (known) ...[
              const SizedBox(width: 6),
              UiIcon(UiIcons.chevron, size: 13, stroke: 2.2, color: Ui.mute),
            ],
          ],
        ),
      ),
    );
  }

  Widget _explain(SecurityAlert a, Color c) {
    final why = a.displayNote ??
        (a.kind == AlertKind.threat
            ? 'This matched a known security pattern. ASSAS is showing the event and context so you can decide whether it belongs on your network.'
            : 'This behavior differs from the device baseline. ASSAS flags the change for review without assuming it is malicious.');
    Widget tile(String icon, Color color, Color bg) => Container(
          width: 30,
          height: 30,
          alignment: Alignment.center,
          decoration: BoxDecoration(color: bg, borderRadius: BorderRadius.circular(UiRadius.explainTile)),
          child: UiIcon(icon, size: 15, stroke: 2, color: color),
        );
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: UiSpace.pageCards),
      padding: const EdgeInsets.fromLTRB(18, 18, 18, 20),
      decoration: surfCard(UiRadius.explainCard),
      child: Column(
            children: [
              Stack(
                clipBehavior: Clip.none,
                children: [
                  // Connector down to the second tile.
                  Positioned(
                    left: 14.5,
                    top: 36,
                    bottom: -14,
                    child: Container(
                      width: 1,
                      decoration: BoxDecoration(
                        gradient: LinearGradient(
                          begin: Alignment.topCenter,
                          end: Alignment.bottomCenter,
                          colors: [Ui.fade(c, .55), Ui.fade(Ui.acc, .55)],
                        ),
                      ),
                    ),
                  ),
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      tile(UiIcons.warning, c, Ui.mix(c, .16, Ui.surf2)),
                      const SizedBox(width: 14),
                      Expanded(
                        child: Padding(
                          padding: const EdgeInsets.only(top: 4),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                a.explanation ?? 'A plain-language explanation is not available for this alert yet.',
                                style: UiText.alertDescription,
                              ),
                              if (a.roleLine != null) ...[
                                const SizedBox(height: 8),
                                Text(
                                  a.roleLine!,
                                  style: UiText.alertDescription.copyWith(fontWeight: FontWeight.w600),
                                ),
                              ],
                            ],
                          ),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
              const SizedBox(height: 20),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  tile(UiIcons.eye, Ui.acc, Ui.mix(Ui.acc, .18, Ui.surf2)),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Padding(
                          padding: const EdgeInsets.only(top: 2),
                          child: Text(
                            'WHY ASSAS NOTICED',
                            style: UiText.mono(10, 700, em: .12, color: Ui.acc),
                          ),
                        ),
                        const SizedBox(height: 7),
                        Text(why, style: UiText.why.copyWith(color: Ui.mute)),
                      ],
                    ),
                  ),
                ],
              ),
            ],
          ),
    );
  }
}
