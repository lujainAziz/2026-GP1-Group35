import 'dart:async';
import 'dart:math' as math;

import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../services/session_store.dart';
import '../../state/app_settings.dart';
import '../../state/app_state.dart';
import '../../theme/assas_ui.dart';
import '../../widgets/assas_eye.dart';
import '../../widgets/device_signals.dart';
import '../../widgets/ui_kit.dart';
import '../../widgets/ui_overlays.dart';
import '../pairing/pairing_screen.dart';

/// Settings (team decision): identification probes on/off, appearance,
/// appliance status, and Unpair (lets the user pair with another Assas device).
class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key, required this.state});

  final AppState state;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  ApplianceSettings? _settings;
  bool _settingsUnavailable = false;
  bool _saving = false;
  bool _loading = false;
  bool _unpairing = false;
  Timer? _settingsTimer;

  AssasRepository get _repo => widget.state.repo;

  @override
  void initState() {
    super.initState();
    _loadSettings();
    _settingsTimer = Timer.periodic(const Duration(seconds: 5), (_) {
      if (!_saving && !_unpairing && !widget.state.sessionEnded) _loadSettings();
    });
  }

  @override
  void dispose() {
    _settingsTimer?.cancel();
    super.dispose();
  }

  Future<void> _loadSettings() async {
    if (_loading || _saving) return;
    _loading = true;
    try {
      final s = await _repo.getSettings();
      if (mounted) {
        setState(() {
          _settings = s;
          _settingsUnavailable = false;
        });
      }
    } catch (e) {
      if (widget.state.handleFailure(e)) return;
      if (mounted) setState(() => _settingsUnavailable = true);
    } finally {
      _loading = false;
    }
  }

  Future<void> _toggleProbes(bool value) async {
    final old = _settings!;
    setState(() {
      _settings = old.copyWith(activeProbes: value);
      _saving = true;
    });
    try {
      await _repo.updateSettings(_settings!);
    } catch (e) {
      if (widget.state.handleFailure(e) || !mounted) return;
      setState(() => _settings = old);
      showToast(context, 'Could not save the setting. Try again.');
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _unpair() async {
    if (_unpairing) return;
    _unpairing = true;
    try {
    final ok = await showConfirm(
      context,
      title: 'Unpair this phone?',
      message: 'This phone will stop receiving information from this Assas device. '
          'You can pair again using the code on the Assas screen.',
      confirmLabel: 'Unpair',
      danger: true,
    );
    if (!ok) return;

    try {
      await _repo.unpair();
    } on AssasApiException catch (e) {
      // A rejected token is already invalid; other failures must keep it.
      if (e.statusCode != 401) {
        if (!await _confirmForgetOffline()) return;
      }
    } catch (_) {
      if (!await _confirmForgetOffline()) return;
    }
    await SessionStore.clear();
    _repo.setAuthToken(null);
    widget.state.stopPolling();
    if (!mounted) return;
    Navigator.of(context).pushAndRemoveUntil(
      MaterialPageRoute(builder: (_) => const PairingScreen()),
      (_) => false,
    );
    } finally {
      _unpairing = false;
    }
  }

  /// ASSAS could not be reached: offer to forget it on this phone only.
  Future<bool> _confirmForgetOffline() async {
    if (!mounted) return false;
    final ok = await showConfirm(
      context,
      title: "Can't reach ASSAS",
      message: "Can't reach ASSAS. Forget it on this phone anyway?",
      confirmLabel: 'Forget',
      danger: true,
    );
    if (!ok && mounted) showToast(context, 'Could not unpair. Connect to ASSAS and try again.');
    return ok;
  }

  @override
  Widget build(BuildContext context) {
    final bottomPad = UiSpace.navBottomPad + math.max(0.0, MediaQuery.paddingOf(context).bottom - 14);
    final app = AppSettings.instance;
    return ListenableBuilder(
      listenable: Listenable.merge([widget.state, app]),
      builder: (context, _) {
        return SafeArea(
          bottom: false,
          child: TopFade(child: ListView(
            padding: EdgeInsets.only(bottom: bottomPad),
            children: [
              const KickerRow('ASSAS CORE'),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: UiSpace.pageText),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    Expanded(
                      child: Padding(
                        padding: const EdgeInsets.only(top: 5),
                        // scaleDown keeps the two-line title intact and shrinks it
                        // to fit instead of wrapping mid-word on narrow / large-font
                        // layouts.
                        child: FittedBox(
                          fit: BoxFit.scaleDown,
                          alignment: Alignment.centerLeft,
                          child: Text('Control\ncenter.', style: UiText.settingsTitle),
                        ),
                      ),
                    ),
                    const SizedBox(width: 16),
                    const SizedBox(
                      width: 118,
                      height: 82,
                      child: OverflowBox(
                        maxWidth: 132,
                        maxHeight: 82,
                        child: AssasEye(size: 132),
                      ),
                    ),
                  ],
                ),
              ),
              _protectionCard(),
              _groupLabel('APPEARANCE'),
              _themeCard(app),
              _groupLabel('TEXT SIZE'),
              _textSizeCard(app),
              _groupLabel('CONNECTED HARDWARE'),
              _hardwareCard(),
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
                child: PillButton(
                  label: 'Unpair this phone',
                  onTap: _unpair,
                  filled: false,
                  textColor: Ui.crit,
                  borderColor: Ui.mix(Ui.crit, .34, Ui.line),
                  background: Ui.fade(Ui.crit, .06),
                ),
              ),
            ],
          )),
        );
      },
    );
  }

  Widget _groupLabel(String text) => Padding(
        padding: const EdgeInsets.fromLTRB(22, 25, 22, 9),
        child: Text(text, style: UiText.groupLabel.copyWith(color: Ui.mute)),
      );

  /// Active identification (optional probes) on / off.
  Widget _protectionCard() {
    final s = _settings;
    final on = s?.activeProbes ?? false;
    final color = _settingsUnavailable || s == null ? Ui.mute : (on ? Ui.low : Ui.med);
    final desc = _settingsUnavailable
        ? 'Could not load settings. Tap to retry.'
        : s == null
            ? 'Loading…'
            : on
                ? 'ASSAS sends light local checks to identify devices more accurately.'
                : 'Optional identification probes are off. Monitoring and basic discovery continue.';
    return Container(
      margin: const EdgeInsets.fromLTRB(16, 22, 16, 0),
      padding: const EdgeInsets.all(18),
      decoration: glassCard(UiRadius.protectionCard),
      child: Row(
        children: [
          Container(
            width: 50,
            height: 50,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              color: Ui.mix(color, .14, Ui.surf2),
              borderRadius: BorderRadius.circular(UiRadius.iconTile),
            ),
            child: PulseDot(color, size: 11),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Active identification', style: UiText.rowTitle),
                const SizedBox(height: 2),
                Text(desc, style: UiText.rowSubtitle.copyWith(color: Ui.mute)),
              ],
            ),
          ),
          const SizedBox(width: 14),
          // Until the real state is known, do NOT show a toggle (it would read as
          // a confirmed "off"): show an explicit error+retry or a loading spinner.
          if (_settingsUnavailable)
            Pressable(
              onTap: _loading ? null : _loadSettings,
              semanticLabel: 'Retry loading settings',
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 9),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(UiRadius.pill),
                  border: Border.all(color: Ui.mix(Ui.med, .4, Ui.line)),
                ),
                child: Text('RETRY', style: UiText.mono(10.5, 700, em: .1, color: Ui.med)),
              ),
            )
          else if (s == null)
            const Padding(padding: EdgeInsets.symmetric(horizontal: 10), child: UiSpinner(size: 18))
          else
            _Toggle(
              value: on,
              onChanged: _saving || _loading ? null : _toggleProbes,
            ),
        ],
      ),
    );
  }

  /// Dark mode: Midnight / Pearl.
  Widget _themeCard(AppSettings app) {
    Widget option(String label, bool dark) {
      final on = app.darkMode == dark;
      final fg = on ? Ui.accInk : Ui.ink;
      return Expanded(
        child: Pressable(
          onTap: () => app.setDarkMode(dark),
          semanticLabel: '$label theme${on ? ', selected' : ''}',
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 250),
            height: 52,
            decoration: BoxDecoration(
              color: on ? Ui.acc : Ui.fade(Ui.acc, 0),
              borderRadius: BorderRadius.circular(UiRadius.themeOption),
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Container(
                  width: 10,
                  height: 10,
                  decoration: BoxDecoration(
                    color: dark ? UiPalette.dark.bg : UiPalette.light.bg,
                    shape: BoxShape.circle,
                    border: Border.all(color: on ? fg : Ui.line),
                  ),
                ),
                const SizedBox(width: 8),
                Text(label, style: UiText.button.copyWith(color: fg)),
              ],
            ),
          ),
        ),
      );
    }

    return Container(
      margin: const EdgeInsets.symmetric(horizontal: UiSpace.pageCards),
      padding: const EdgeInsets.all(8),
      decoration: surfCard(UiRadius.settingsCard),
      child: Row(
        children: [
          option('Midnight', true),
          const SizedBox(width: 7),
          option('Pearl', false),
        ],
      ),
    );
  }

  /// Text size (fixed steps, so the layout never breaks).
  Widget _textSizeCard(AppSettings app) {
    final label = UiText.mono(10, 500, color: Ui.mute);
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: UiSpace.pageCards),
      padding: const EdgeInsets.symmetric(horizontal: 15, vertical: 14),
      decoration: surfCard(UiRadius.settingsCard),
      child: Column(
        children: [
          // Keep the design width when possible; shrink to fit at larger zoom.
          LayoutBuilder(builder: (context, box) {
            final w = ((box.maxWidth - 3 * 6) / 4).clamp(0.0, 66.0).toDouble();
            return Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              for (var i = 0; i < AppSettings.textScales.length; i++)
                Pressable(
                  onTap: () => app.setTextScaleIndex(i),
                  semanticLabel:
                      'Text size ${AppSettings.textScaleLabels[i]}${i == app.textScaleIndex ? ', selected' : ''}',
                  child: AnimatedContainer(
                    duration: const Duration(milliseconds: 220),
                    width: w,
                    height: 58,
                    alignment: Alignment.center,
                    decoration: BoxDecoration(
                      color: i == app.textScaleIndex ? Ui.acc : Ui.surf2,
                      borderRadius: BorderRadius.circular(UiRadius.textSizeOption),
                    ),
                    child: Text(
                      'Aa',
                      textScaler: TextScaler.noScaling,
                      style: UiText.sans(12 + i * 4.0, 800,
                          color: i == app.textScaleIndex ? Ui.accInk : Ui.ink),
                    ),
                  ),
                ),
            ],
            );
          }),
          const SizedBox(height: 10),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text('COMPACT', style: label),
              Text(app.textScaleLabel.toUpperCase(), style: label.copyWith(color: Ui.ink)),
              Text('LARGE', style: label),
            ],
          ),
        ],
      ),
    );
  }

  Widget _hardwareCard() {
    final c = widget.state.connection;
    final color = ConnectionLook.color(c);
    Widget cell(String k, String v, {Color? color}) => Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(k, style: UiText.mono(8.5, 500, color: Ui.mute)),
            const SizedBox(height: 3),
            Text(
              v,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: UiText.mono(10.5, 600, color: color ?? Ui.ink),
            ),
          ],
        );
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: UiSpace.pageCards),
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 17),
      decoration: glassCard(UiRadius.settingsCard),
      child: Column(
        children: [
          // At least 58 high; grows when the title wraps at large text sizes.
          ConstrainedBox(
            constraints: const BoxConstraints(minHeight: 58),
            child: Row(
              children: [
                Expanded(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('ASSAS Hardware', style: UiText.cardTitle),
                      const SizedBox(height: 3),
                      Text(
                        '● ${ConnectionLook.text(c)} / PAIRED',
                        style: UiText.mono(10.5, 500, color: color),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 14),
                const SizedBox(width: 92, height: 58, child: Center(child: AssasEye(size: 58))),
              ],
            ),
          ),
          const SizedBox(height: 13),
          Container(
            padding: const EdgeInsets.only(top: 11),
            decoration: BoxDecoration(border: Border(top: BorderSide(color: Ui.line))),
            child: Column(
              children: [
                Row(
                  children: [
                    Expanded(child: cell('LOCAL ADDRESS', _repo.applianceAddress)),
                    const SizedBox(width: 14),
                    // ---------- DEMO ONLY marker (disappears with the real backend) ----------
                    Expanded(
                      child: cell(
                        'DATA',
                        _repo.isDemo ? 'DEMO DATA' : 'LIVE',
                        color: _repo.isDemo ? Ui.med : null,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 10),
                Row(
                  children: [
                    Expanded(child: cell('LAST SYNC', ConnectionLook.synced(c, widget.state.lastSync))),
                    const SizedBox(width: 14),
                    Expanded(
                      child: cell(
                        'SESSION',
                        widget.state.lastSync == null ? 'NOT VERIFIED' : (c == ConnectionStatus.unreachable ? 'UNREACHABLE' : 'AUTHENTICATED'),
                        color: c == ConnectionStatus.unreachable ? Ui.crit : Ui.low,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// Toggle switch from the design (52 x 30, knob 22).
class _Toggle extends StatelessWidget {
  const _Toggle({required this.value, required this.onChanged});

  final bool value;
  final ValueChanged<bool>? onChanged;

  @override
  Widget build(BuildContext context) {
    return Pressable(
      onTap: onChanged == null ? null : () => onChanged!(!value),
      semanticLabel: 'Active identification, ${value ? 'on' : 'off'}',
      child: Opacity(
        opacity: onChanged == null ? .5 : 1,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 250),
          width: 52,
          height: 30,
          decoration: BoxDecoration(
            color: value ? Ui.acc : Ui.surf2,
            borderRadius: BorderRadius.circular(UiRadius.toggle),
            border: Border.all(color: Ui.line),
          ),
          child: AnimatedAlign(
            duration: const Duration(milliseconds: 280),
            curve: kUiEase,
            alignment: value ? Alignment.centerRight : Alignment.centerLeft,
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 3),
              child: Container(
                width: 22,
                height: 22,
                decoration: BoxDecoration(
                  color: value ? Ui.accInk : Ui.mute,
                  shape: BoxShape.circle,
                  boxShadow: UiShadow.toggleKnob,
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
