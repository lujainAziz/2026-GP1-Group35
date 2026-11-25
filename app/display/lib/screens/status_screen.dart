import 'dart:async';
import 'dart:math' as math;

import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../config/data_source.dart';
import 'pairing_qr.dart';
import '../display_ui.dart';
import 'package:assas_design/widgets/synaptic_field.dart';
import 'package:assas_design/widgets/device_signals.dart';
import 'package:assas_design/widgets/ui_kit.dart' show surfCard, glassCard;
import 'package:assas_design/theme/assas_ui.dart';
import 'package:assas_design/widgets/assas_eye.dart';
import 'package:assas_design/release_status.dart';

/// Glanceable status for the 7-inch screen (1024 x 600):
/// network alert level, devices online, unresolved alerts, system status,
/// and the rotating pairing QR code.
class StatusScreen extends StatefulWidget {
  const StatusScreen({super.key, this.repo});
  final AssasRepository? repo;

  @override
  State<StatusScreen> createState() => _StatusScreenState();
}

class _StatusScreenState extends State<StatusScreen> {
  AssasRepository get _repo => widget.repo ?? repository;
  ConnectionStatus _status = ConnectionStatus.checking;
  RiskInfo? _risk;
  List<Device> _devices = const [];
  int? _online;
  int? _total;
  // Unresolved (New) alerts, the DB aggregate from GET /alerts/open_count.
  // null = never loaded / not available (shows "—").
  int? _unresolved;
  // The last poll failed: _unresolved is the last known count (shown dimmed).
  bool _unresolvedLastKnown = false;
  DateTime? _lastSync;
  Timer? _timer;
  bool _refreshing = false;

  // New-phone notice (Maraheb's spec, part 3).
  int? _lastPhoneId; // highest session id seen; null until the first check
  String? _newPhoneName; // shown for 10 s
  Timer? _noticeTimer;

  @override
  void initState() {
    super.initState();
    _refresh();
    _timer = Timer.periodic(const Duration(seconds: 5), (_) => _refresh());
  }

  @override
  void dispose() {
    _timer?.cancel();
    _noticeTimer?.cancel();
    super.dispose();
  }

  /// Checks the paired phones. The first check only remembers the highest id
  /// (so old phones are never shown as new after a restart). Later, a higher
  /// id means a new phone: show its name for 10 seconds. Errors and a missing
  /// endpoint (not merged yet) are ignored quietly.
  Future<void> _checkPhones() async {
    try {
      final phones = await _repo.getPairedPhones();
      if (phones == null || !mounted) return;
      final maxId = phones.fold<int>(0, (m, p) => p.id > m ? p.id : m);
      final last = _lastPhoneId;
      if (last != null) {
        final fresh = phones.where((p) => p.id > last).toList();
        if (fresh.isNotEmpty) {
          _noticeTimer?.cancel();
          setState(() => _newPhoneName = fresh.last.deviceName);
          _noticeTimer = Timer(const Duration(seconds: 10), () {
            if (mounted) setState(() => _newPhoneName = null);
          });
        }
      }
      _lastPhoneId = last == null ? maxId : (maxId > last ? maxId : last);
    } catch (_) {
      // ignore quietly
    }
  }

  Future<void> _refresh() async {
    if (_refreshing || !mounted) return;
    _refreshing = true;
    try {
    await _checkPhones();
    if (!mounted) return;
    var status = await _repo.checkHealth();
    RiskInfo? risk = _risk;
    int? online = _online, total = _total, unresolved = _unresolved;
    bool unresolvedLastKnown = _unresolvedLastKnown;

    try {
      final devices = await _repo.getDevices();
      _devices = devices;
      _lastSync = DateTime.now();
      online = devices.where((d) => d.isOnline).length;
      total = devices.length;
    } catch (_) {
      if (status == ConnectionStatus.live) status = ConnectionStatus.stale;
    }
    if (FeatureRelease.alertDisplay) {
    // The true total from the database (never the length of a downloaded page).
    // null = the appliance has no such endpoint (404). On failure keep the last
    // known count, flagged so the card dims it; with none yet it shows "—".
    try {
      unresolved = await _repo.getOpenAlertCount();
      unresolvedLastKnown = false;
    } catch (_) {
      unresolvedLastKnown = unresolved != null;
    }
    }
    if (FeatureRelease.risk) {
    try {
      risk = await _repo.getRiskLevel();
    } catch (_) {}
    }

    if (!mounted) return;
    setState(() {
      _status = status;
      _risk = risk;
      _online = online;
      _total = total;
      _unresolved = unresolved;
      _unresolvedLastKnown = unresolvedLastKnown;
    });
    } finally {
      _refreshing = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    // Stale still reads CONNECTED (as live); only the sync line says OUTDATED.
    final statusLabel = ConnectionWording.text(_status);
    final statusColor = ConnectionWording.color(_status);
    return Scaffold(body: Padding(
      padding: const EdgeInsets.all(24),
      child: Column(children: [
        Row(children: [
          const SizedBox(width: 50, height: 32,
            child: FittedBox(child: AssasEye(size: 64))),
          const SizedBox(width: 14),
          Text('ASSAS', style: DisplayUi.mono(20, color: DisplayUi.ink).copyWith(letterSpacing: 7)),
          const SizedBox(width: 18),
          Container(width: 1, height: 26, color: DisplayUi.line),
          const SizedBox(width: 18),
          Text('YOUR NETWORK. IN SIGHT.', style: DisplayUi.mono(10)),
          const Spacer(),
          Container(padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            decoration: DisplayUi.card(color: DisplayUi.raised, radius: 18),
            child: Row(mainAxisSize: MainAxisSize.min, children: [
              Container(width: 7, height: 7, decoration: BoxDecoration(color: statusColor, shape: BoxShape.circle)),
              const SizedBox(width: 9),
              Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(statusLabel, style: DisplayUi.mono(11, color: statusColor)),
                Text(ConnectionWording.synced(_status, _lastSync),
                    style: UiText.synced.copyWith(color: ConnectionWording.syncedColor(_status) ?? Ui.mute)),
              ]),
            ])),
        ]),
        const SizedBox(height: 22),
        Expanded(child: Stack(children: [
          Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Expanded(flex: 22, child: _overview()),
            const SizedBox(width: 18),
            Expanded(flex: 11, child: PairingQrPanel(repo: _repo)),
          ]),
          if (_newPhoneName != null) Positioned(top: 10, left: 16, right: 16,
            child: Center(child: Container(
              constraints: const BoxConstraints(maxWidth: 850),
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
              decoration: DisplayUi.card(color: DisplayUi.raised, radius: 22),
              child: Row(mainAxisSize: MainAxisSize.min, children: [
                const Icon(Icons.phone_iphone, color: DisplayUi.green, size: 22),
                const SizedBox(width: 12),
                Flexible(child: Text('New phone paired: $_newPhoneName', maxLines: 2,
                    overflow: TextOverflow.ellipsis, style: DisplayUi.sans(18))),
              ]),
            ))),
        ])),
        const SizedBox(height: 16),
        Row(children: [
          Text('LOCAL NETWORK GUARDIAN', style: DisplayUi.mono(9, color: DisplayUi.accent)),
          const Spacer(),
          Text('Scan the code with the ASSAS mobile app to pair.', style: DisplayUi.mono(9)),
        ]),
      ]),
    ));
  }

  Widget _overview() {
    final signals = [for (final device in _devices) DeviceSignal(device, null)]..sort(DeviceSignal.compare);
    final riskColor = !FeatureRelease.risk || _risk == null ? Ui.mute : Ui.severity(_risk!.level);
    return Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Expanded(flex: 14, child: Column(children: [
        Align(alignment: Alignment.centerLeft, child: Text('ON YOUR NETWORK', style: UiText.kicker.copyWith(color: Ui.mute))),
        const SizedBox(height: 8),
        Expanded(child: Center(child: FittedBox(fit: BoxFit.contain,
          child: IgnorePointer(child: SynapticField(top: const [], onOpen: (_) {}))))),
        const SizedBox(height: 10),
        Container(padding: const EdgeInsets.symmetric(horizontal: 15, vertical: 10),
          decoration: glassCard(999),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            Text('${_total ?? '—'}', style: UiText.ribbonNumber),
            Text(' DEVICES', style: UiText.ribbonLabel.copyWith(color: Ui.mute)),
            Text('  •  ', style: UiText.ribbonLabel.copyWith(color: Ui.mute)),
            Text('${_online ?? '—'}', style: UiText.ribbonNumber.copyWith(color: Ui.low)),
            Text(' ONLINE', style: UiText.ribbonLabel.copyWith(color: Ui.mute)),
          ])),
        const SizedBox(height: 18),
      ])),
      const SizedBox(width: 18),
      Expanded(flex: 10, child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Padding(padding: const EdgeInsets.fromLTRB(18, 0, 0, 20),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('NETWORK ALERT LEVEL', style: UiText.kicker.copyWith(color: Ui.mute)),
            const SizedBox(height: 10),
            Row(crossAxisAlignment: CrossAxisAlignment.end, children: [
              Expanded(child: FittedBox(fit: BoxFit.scaleDown, alignment: Alignment.centerLeft,
                child: Text(FeatureRelease.risk ? (_risk?.level ?? '—') : 'Soon', style: UiText.riskWord.copyWith(color: riskColor)))),
              const SizedBox(width: 12),
              ConstrainedBox(constraints: const BoxConstraints(maxWidth: 130),
                child: Text(!FeatureRelease.risk ? 'Network Alert Level arrives in Sprint 4' : _risk == null ? 'Alert level is not available yet' : 'Highest severity among open alerts',
                  textAlign: TextAlign.right, style: UiText.secondary.copyWith(height: 1.35, color: Ui.mute))),
            ]),
          ])),
        Expanded(child: Container(padding: const EdgeInsets.all(18), decoration: surfCard(UiRadius.onlineCard),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
            Text('ONLINE', style: UiText.mono(11, 500, em: .08, color: Ui.mute)),
            Row(crossAxisAlignment: CrossAxisAlignment.baseline, textBaseline: TextBaseline.alphabetic, children: [
              Text('${_online ?? '—'}', style: UiText.onlineNumber),
              const SizedBox(width: 5),
              Text('/${_total ?? '—'}', style: UiText.sans(22, 600, color: Ui.mute)),
            ]),
            LayoutBuilder(builder: (context, box) {
              // Counts include every device; the marks are a bounded sample.
              final count = math.min(signals.length, (box.maxWidth / 8).floor());
              return Row(children: [for (var i = 0; i < count; i++) ...[
                if (i > 0) const SizedBox(width: 4),
                Expanded(child: Container(height: 6, decoration: BoxDecoration(color: signals[i].bar,
                    borderRadius: BorderRadius.circular(3)))),
              ]]);
            }),
          ]))),
        const SizedBox(height: 12),
        Container(padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 18),
          decoration: surfCard(UiRadius.card, color: Ui.mix(Ui.high, .16, Ui.surf)),
          child: _unresolvedCard()),
      ])),
    ]);
  }

  /// "Unresolved alerts": the count of New alerts. 0 is muted with "No
  /// unresolved alerts" (never "All clear": the card must not suggest the
  /// network is safe). After a failed poll the last known count stays, dimmed,
  /// with "Last known"; with no count yet it shows "—".
  Widget _unresolvedCard() {
    if (!FeatureRelease.alertDisplay) {
      return Row(children: [
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Unresolved\nalerts', style: UiText.sans(15, 600)),
          const SizedBox(height: 8),
          const SoonTag(2),
        ])),
        Text('SOON', style: UiText.mono(13, 700, em: .1, color: Ui.mute)),
      ]);
    }
    final n = _unresolved;
    final note = n == null
        ? null
        : _unresolvedLastKnown
            ? 'Last known'
            : n == 0
                ? 'No unresolved alerts'
                : null;
    final color = n == null || n == 0
        ? Ui.mute
        : _unresolvedLastKnown
            ? Ui.fade(Ui.high, .45)
            : Ui.high;
    return Row(children: [
      Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text('Unresolved\nalerts', style: UiText.sans(15, 600)),
        if (note != null) ...[
          const SizedBox(height: 6),
          Text(note, key: const ValueKey('unresolvedNote'),
              style: UiText.mono(10, 600, em: .06, color: Ui.mute)),
        ],
      ])),
      Text(n == null ? '—' : '$n', key: const ValueKey('unresolvedCount'),
          style: UiText.statNumber.copyWith(color: color)),
    ]);
  }
}
