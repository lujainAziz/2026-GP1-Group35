import 'dart:math' as math;
import 'dart:ui' as ui;

import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../state/app_state.dart';
import '../../widgets/activity_strip.dart';
import '../../theme/assas_ui.dart';
import '../../widgets/coming_soon.dart';
import '../../widgets/device_signals.dart';
import '../../widgets/synaptic_field.dart';
import '../../widgets/ui_kit.dart';
import '../alerts/alert_details_screen.dart';
import '../devices/device_details_screen.dart';

/// Dashboard (PBI-21): network alert level, online / total devices, unresolved alerts,
/// unrecognized devices, recent alerts.
class DashboardScreen extends StatelessWidget {
  const DashboardScreen({
    super.key,
    required this.state,
    required this.onOpenDevices,
    required this.onOpenAlerts,
    this.onOpenUnrecognized,
  });

  final AppState state;
  final VoidCallback onOpenDevices;
  final VoidCallback onOpenAlerts;

  /// Devices tab with the Unrecognized filter (falls back to [onOpenDevices]).
  final VoidCallback? onOpenUnrecognized;

  /// Online card bars, attention first. 10 keeps each bar at least as wide as
  /// its 5px gap on the narrowest layout (320 px phone, Largest text).
  static const _maxBars = 10;

  void _openAlert(BuildContext context, SecurityAlert a) => Navigator.of(context).push(
        MaterialPageRoute(builder: (_) => AlertDetailsScreen(state: state, alertId: a.id)),
      );

  void _openDevice(BuildContext context, Device d) => Navigator.of(context).push(
        MaterialPageRoute(builder: (_) => DeviceDetailsScreen(state: state, mac: d.mac)),
      );

  @override
  Widget build(BuildContext context) {
    final mq = MediaQuery.paddingOf(context);
    return ListenableBuilder(
      listenable: state,
      builder: (context, _) {
        final signals = Signals.sorted(state);
        final attention = signals.where((s) => s.needsAttention).length;
        final offline = state.connection == ConnectionStatus.unreachable;
        return Stack(
          children: [
            TopFade(top: mq.top, child: RefreshIndicator(
              onRefresh: state.refresh,
              color: Ui.acc,
              backgroundColor: Ui.surf,
              child: ListView(
                padding: EdgeInsets.only(
                  top: mq.top,
                  bottom: UiSpace.navBottomPad + math.max(0.0, mq.bottom - 14),
                ),
                children: [
                  Container(
                    height: 58,
                    alignment: Alignment.centerLeft,
                    padding: const EdgeInsets.symmetric(horizontal: UiSpace.pageText),
                    child: Text('ASSAS', style: UiText.wordmark),
                  ),
                  if (offline)
                    Container(
                      margin: const EdgeInsets.fromLTRB(16, 8, 16, 0),
                      padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 9),
                      decoration: BoxDecoration(
                        color: Ui.mix(Ui.crit, .07, Ui.surf),
                        borderRadius: BorderRadius.circular(UiRadius.banner),
                        border: Border.all(color: Ui.mix(Ui.crit, .24, Ui.line)),
                      ),
                      child: Text(
                        'ASSAS is offline. Showing the last synced information only.',
                        style: UiText.banner.copyWith(color: Ui.crit),
                      ),
                    ),
                  const SizedBox(height: 12),
                  Center(
                    child: SynapticField(
                      top: signals,
                      onOpen: (s) => _openDevice(context, s.device),
                    ),
                  ),
                  Transform.translate(
                    offset: const Offset(0, -8),
                    child: Center(
                      child: Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 16),
                        child: FittedBox(fit: BoxFit.scaleDown, child: _ribbon(attention)),
                      ),
                    ),
                  ),
                  const SizedBox(height: 14),
                  _risk(),
                  ActivityTrace(activity: state.activity, connected: state.connection == ConnectionStatus.live),
                  ObservedProtocols(activity: state.activity, connected: state.connection == ConnectionStatus.live),
                  _stats(signals),
                  SectionHeader(
                    'Recent',
                    padding: const EdgeInsets.fromLTRB(22, 34, 22, 10),
                    trailing: Pressable(
                      onTap: onOpenAlerts,
                      child: Text('SEE ALL →', style: UiText.link.copyWith(color: Ui.acc)),
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: UiSpace.pageCards),
                    child: _recent(context),
                  ),
                ],
              ),
            )),
            // Floating connection pill (right side of the wordmark row, like the design).
            Positioned(
              top: mq.top + 8,
              right: UiSpace.pageText,
              child: _connectionPill(),
            ),
          ],
        );
      },
    );
  }

  Widget _connectionPill() {
    final c = ConnectionLook.color(state.connection);
    return Pressable(
      onTap: state.refresh,
      semanticLabel: 'Connection: ${ConnectionLook.text(state.connection)}. Tap to refresh',
      child: Glass(
        color: Ui.fade(Ui.bg, .62),
        radius: UiRadius.headerPill,
        height: 42,
        padding: const EdgeInsets.symmetric(horizontal: 12),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                UiClock(
                  builder: (context, t, _) => Opacity(
                    opacity: 1 - .75 * wave(t, 2),
                    child: GlowDot(c, glow: 0),
                  ),
                ),
                const SizedBox(width: 7),
                Text(ConnectionLook.text(state.connection), style: UiText.connection.copyWith(color: c)),
              ],
            ),
            const SizedBox(height: 2),
            Text(
              ConnectionLook.synced(state.connection, state.lastSync),
              style: UiText.synced.copyWith(color: Ui.mute),
            ),
          ],
        ),
      ),
    );
  }

  Widget _ribbon(int attention) {
    Widget n(String v, {Color? color}) =>
        Text(v, style: UiText.ribbonNumber.copyWith(color: color ?? Ui.ink));
    Widget l(String v) => Text(v, style: UiText.ribbonLabel.copyWith(color: Ui.mute));
    Widget sep() => Opacity(opacity: .28, child: l('•'));
    return Glass(
      color: Ui.fade(Ui.surf2, .88),
      radius: UiRadius.pill,
      blur: 12,
      padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 7),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          n('${state.totalCount}'),
          const SizedBox(width: 7),
          l('DEVICES'),
          const SizedBox(width: 7),
          sep(),
          const SizedBox(width: 7),
          n('${state.onlineCount}'),
          const SizedBox(width: 7),
          l('ONLINE'),
          if (attention > 0) ...[
            const SizedBox(width: 7),
            sep(),
            const SizedBox(width: 7),
            n('$attention', color: Ui.med),
            const SizedBox(width: 7),
            l('NEED ATTENTION'),
          ],
        ],
      ),
    );
  }

  Widget _risk() {
    final risk = Released.risk ? state.risk : null;
    final unresolved = Released.alertsHome ? state.unresolvedAlertCount : null;
    final note = unresolved == null
        ? 'Alerts are not available yet'
        : unresolved > 0
            ? '$unresolved alert${unresolved > 1 ? 's' : ''} unresolved on your network'
            : 'No unresolved alerts';
    return Padding(
      padding: const EdgeInsets.fromLTRB(22, 18, 22, 0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('NETWORK ALERT LEVEL', style: UiText.kicker.copyWith(color: Ui.mute)),
          Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Expanded(
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(2, 2, 0, 5),
                  child: FittedBox(
                    fit: BoxFit.scaleDown,
                    alignment: Alignment.centerLeft,
                    child: Text(
                      risk?.level ?? (Released.risk ? '—' : 'Soon'),
                      style: UiText.riskWord.copyWith(
                        color: risk == null ? Ui.mute : Ui.severity(risk.level),
                      ),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 130),
                child: Padding(
                  padding: const EdgeInsets.only(bottom: 6),
                  child: Text(
                    !Released.risk
                        ? 'Network Alert Level arrives in Sprint 4'
                        : risk == null
                            ? 'Alert level is not available yet'
                            : note,
                    textAlign: TextAlign.right,
                    style: UiText.secondary.copyWith(height: 1.35, color: Ui.mute),
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _stats(List<DeviceSignal> signals) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 26, 16, 0),
      child: IntrinsicHeight(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Expanded(
              flex: 115,
              child: Pressable(
                onTap: onOpenDevices,
                child: _CardX(
                  radius: UiRadius.onlineCard,
                  child: Container(
                    constraints: const BoxConstraints(minHeight: 160),
                    padding: const EdgeInsets.all(18),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text('ONLINE', style: UiText.mono(11, 500, em: .08, color: Ui.mute)),
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            // Shrinks for 3-digit counts (the appliance keeps old devices).
                            FittedBox(
                              fit: BoxFit.scaleDown,
                              alignment: Alignment.centerLeft,
                              child: Row(
                                crossAxisAlignment: CrossAxisAlignment.baseline,
                                textBaseline: TextBaseline.alphabetic,
                                children: [
                                  Text('${state.onlineCount}', style: UiText.onlineNumber),
                                  const SizedBox(width: 4),
                                  Text(
                                    '/${state.totalCount}',
                                    style: UiText.sans(22, 600, color: Ui.mute),
                                  ),
                                ],
                              ),
                            ),
                            if (signals.isNotEmpty) ...[
                              const SizedBox(height: 12),
                              Row(
                                children: [
                                  for (var i = 0; i < math.min(signals.length, _maxBars); i++) ...[
                                    if (i > 0) const SizedBox(width: 5),
                                    Expanded(
                                      child: Container(
                                        height: 6,
                                        decoration: BoxDecoration(
                                          color: signals[i].bar,
                                          borderRadius: BorderRadius.circular(3),
                                        ),
                                      ),
                                    ),
                                  ],
                                ],
                              ),
                            ],
                          ],
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              flex: 100,
              child: Column(
                // Stretch so both cards share one width; Expanded makes the two
                // cards + the gap span the full column height, which (in the
                // IntrinsicHeight row) equals the Online card — Unresolved
                // alerts aligns to Online's top and Unrecognized to its bottom.
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Expanded(
                    child: Pressable(
                      onTap: onOpenAlerts, // PBI-17
                      child: _CardX(
                        radius: UiRadius.card,
                        color: Ui.mix(Ui.high, .16, Ui.surf),
                        child: Released.alertsHome
                            ? _unresolvedInner()
                            : _soonInner('Unresolved\nalerts', 2),
                      ),
                    ),
                  ),
                  const SizedBox(height: 10),
                  Expanded(
                    child: Pressable(
                      onTap: onOpenUnrecognized ?? onOpenDevices,
                      child: _CardX(
                        radius: UiRadius.card,
                        stripes: Ui.mix(Ui.med, .14, Ui.surf),
                        // Soft hyphen (U+00AD): invisible normally; if the word must break at
                        // the largest size it hyphenates cleanly instead of a raw mid-word cut.
                        child: _statInner('Unrecog\u00adnized', '${state.unrecognizedCount}', Ui.med),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// Shared layout for the two stacked stat cards (Unresolved alerts + Unrecognized):
  /// identical padding, label on the left and value on the right, across the
  /// full card width. The card width is fixed (the column stretches both cards
  /// to the same width); Wrap keeps the label and value on one line at normal
  /// text sizes and, when the enlarged font no longer fits them together, flows
  /// the value onto the next line so the card grows in HEIGHT (width unchanged).
  Widget _statCard(String label, Widget value, {String? note}) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      // Centre the label/value row vertically now the card fills the column
      // height; stretch keeps the Wrap full-width so the value sits at the
      // right edge.
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Wrap(
            alignment: WrapAlignment.spaceBetween,
            crossAxisAlignment: WrapCrossAlignment.center,
            runSpacing: 2,
            children: [
              Text(label, style: UiText.sans(13, 600, height: 1.2)),
              value,
            ],
          ),
          if (note != null) ...[
            const SizedBox(height: 4),
            Text(note, key: const ValueKey('unresolvedNote'),
                style: UiText.mono(10, 600, em: .06, color: Ui.mute)),
          ],
        ],
      ),
    );
  }

  /// "Unresolved alerts" card: the DB count of New alerts (GET /alerts/open_count).
  /// 0 is muted with "No unresolved alerts" (never "All clear": the card must
  /// not suggest the network is safe). After a failed refresh the last known
  /// count stays, dimmed, with "Last known"; with no count yet it shows "—".
  Widget _unresolvedInner() {
    final n = state.unresolvedAlertCount;
    final lastKnown = n != null && state.alertsError;
    final note = n == null
        ? null
        : lastKnown
            ? 'Last known'
            : n == 0
                ? 'No unresolved alerts'
                : null;
    final color = n == null || n == 0
        ? Ui.mute
        : lastKnown
            ? Ui.fade(Ui.high, .45)
            : Ui.high;
    return _statCard(
      'Unresolved\nalerts',
      Text(n == null ? '—' : '$n', key: const ValueKey('unresolvedCount'),
          style: UiText.sans(18, 800, em: -.02, color: color)),
      note: note,
    );
  }

  /// Stat card content for a feature from a later sprint (same layout as a live
  /// stat card, with the deferred marker in place of the number).
  Widget _soonInner(String label, int sprint) =>
      _statCard(label, Text('SOON', style: UiText.mono(13, 700, em: .1, color: Ui.mute)));

  /// A labelled count. The number is a normal (not oversized) weight so it sits
  /// on the same line as the label at normal text sizes; it keeps its colour
  /// (e.g. the amber used for Unrecognized).
  Widget _statInner(String label, String value, Color color) =>
      _statCard(label, Text(value, style: UiText.sans(18, 800, em: -.02, color: color)));

  Widget _recent(BuildContext context) {
    if (!Released.alertsHomeRecent) {
      // Alerts are live in the Alerts tab; only the Home summary here is still
      // deferred: the Home network-status summary (PBI-26), planned for Sprint 5.
      return const EmptyDashed(
        title: 'See the Alerts tab',
        hint: 'A summary of recent alerts on the home screen is coming later. '
            'Go to the Alerts tab for the full list.',
        action: SoonTag(5),
      );
    }
    final alerts = state.alerts;
    if (alerts == null) {
      return const EmptyDashed(
        title: 'Alerts are not available yet',
        hint: 'Security alerts will appear here once detection is running.',
      );
    }
    if (alerts.isEmpty) {
      return const EmptyDashed(
        title: 'No alerts yet',
        hint: 'ASSAS has not detected any security events.',
      );
    }
    final list = Signals.openFirst(alerts).take(2).toList();
    return Column(
      children: [
        for (var i = 0; i < list.length; i++) ...[
          if (i > 0) const SizedBox(height: 8),
          _RecentCard(alert: list[i], onTap: () => _openAlert(context, list[i])),
        ],
      ],
    );
  }
}

/// Recent alert card (severity bar on the left).
class _RecentCard extends StatelessWidget {
  const _RecentCard({required this.alert, required this.onTap});

  final SecurityAlert alert;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Pressable(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.fromLTRB(14, 14, 16, 14),
        decoration: surfCard(UiRadius.alertCard),
        child: IntrinsicHeight(
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Container(
                width: 4,
                decoration: BoxDecoration(
                  color: sevColor(alert.severity),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    AlertMetaRow(alert),
                    const SizedBox(height: 3),
                    Text(alert.title, style: UiText.recentTitle),
                    const SizedBox(height: 3),
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            alert.deviceName,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: UiText.secondary.copyWith(color: Ui.mute),
                          ),
                        ),
                        StatePill(alert),
                      ],
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// `.assas-cardx`: card with a faint gradient edge (accent -> green).
class _CardX extends StatelessWidget {
  const _CardX({required this.child, required this.radius, this.color, this.stripes});

  final Widget child;
  final double radius;
  final Color? color;

  /// Diagonal stripes (135deg, 8px) of this color over the surface.
  final Color? stripes;

  @override
  Widget build(BuildContext context) {
    return CustomPaint(
      painter: stripes == null ? null : _StripesPainter(stripes!, Ui.surf, radius),
      foregroundPainter: _EdgePainter(radius),
      child: Container(
        decoration: BoxDecoration(
          color: stripes == null ? (color ?? Ui.surf) : null,
          borderRadius: BorderRadius.circular(radius),
          border: Border.all(color: Ui.line),
        ),
        child: child,
      ),
    );
  }
}

class _EdgePainter extends CustomPainter {
  _EdgePainter(this.radius);

  final double radius;

  @override
  void paint(Canvas canvas, Size size) {
    final rect = Offset.zero & size;
    final rr = RRect.fromRectAndRadius(rect.deflate(.5), Radius.circular(radius));
    canvas.drawRRect(
      rr,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1
        ..shader = LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Ui.fade(Ui.acc, .22), Ui.fade(Ui.acc, 0), Ui.fade(Ui.low, 0), Ui.fade(Ui.low, .12)],
          stops: const [0, .35, .70, 1],
        ).createShader(rect),
    );
  }

  @override
  bool shouldRepaint(_EdgePainter old) => true;
}

class _StripesPainter extends CustomPainter {
  _StripesPainter(this.a, this.b, this.radius);

  final Color a;
  final Color b;
  final double radius;

  @override
  void paint(Canvas canvas, Size size) {
    const d = 16 / math.sqrt2; // one 16px period along 135deg
    final shader = ui.Gradient.linear(
      Offset.zero,
      const Offset(d, d),
      [a, a, b, b],
      const [0, .5, .5, 1],
      TileMode.repeated,
    );
    canvas.drawRRect(
      RRect.fromRectAndRadius(Offset.zero & size, Radius.circular(radius)),
      Paint()..shader = shader,
    );
  }

  @override
  bool shouldRepaint(_StripesPainter old) => old.a != a || old.b != b;
}
