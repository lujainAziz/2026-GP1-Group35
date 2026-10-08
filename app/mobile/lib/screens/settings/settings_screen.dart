import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import '../../services/session_store.dart';
import '../../state/app_settings.dart';
import '../../state/app_state.dart';
import '../../widgets/common.dart';
import '../../widgets/purple_header.dart';
import '../pairing/pairing_screen.dart';

/// Settings (team decision): appliance status, identification probes on/off,
/// and Unpair (lets the user pair with another Assas device).
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

  AssasRepository get _repo => widget.state.repo;

  @override
  void initState() {
    super.initState();
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    try {
      final s = await _repo.getSettings();
      if (mounted) setState(() => _settings = s);
    } catch (_) {
      if (mounted) setState(() => _settingsUnavailable = true);
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
    } catch (_) {
      if (!mounted) return;
      setState(() => _settings = old);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Could not save the setting. Try again.')),
      );
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _unpair() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Unpair this phone?'),
        content: const Text(
          'This phone will stop receiving information from this Assas device. '
          'You can pair again using the code on the Assas screen.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: Text('Unpair', style: TextStyle(color: AssasColors.danger)),
          ),
        ],
      ),
    );
    if (ok != true) return;

    try {
      await _repo.unpair();
    } catch (_) {
      // Even if the appliance is unreachable, remove the session from this phone.
    }
    await SessionStore.clear();
    _repo.setAuthToken(null);
    widget.state.stopPolling();
    if (!mounted) return;
    Navigator.of(context).pushAndRemoveUntil(
      MaterialPageRoute(builder: (_) => const PairingScreen()),
      (_) => false,
    );
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: widget.state,
      builder: (context, _) {
        return ListView(
          padding: EdgeInsets.zero,
          children: [
            PurpleHeader(
              title: 'Settings',
              trailing: ConnectionPill(status: widget.state.connection),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, kBottomNavClearance),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const SectionTitle('Assas device'),
                  const SizedBox(height: 6),
                  AppCard(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                    child: Column(
                      children: [
                        InfoRow('Connection', widget.state.connection.label),
                        const Divider(height: 1),
                        InfoRow('Address', _repo.applianceAddress),
                        // ---------- DEMO ONLY marker (disappears with the real backend) ----------
                        if (_repo.isDemo) ...[
                          const Divider(height: 1),
                          InfoRow('Data', 'Demo data', valueColor: AssasColors.warningFg),
                        ],
                      ],
                    ),
                  ),
                  const SizedBox(height: 20),
                  const SectionTitle('Appearance'),
                  const SizedBox(height: 6),
                  _appearanceCard(),
                  const SizedBox(height: 20),
                  const SectionTitle('Device identification'),
                  const SizedBox(height: 6),
                  _probesCard(),
                  const SizedBox(height: 20),
                  OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      foregroundColor: AssasColors.danger,
                      side: BorderSide(color: AssasColors.danger, width: 1.5),
                    ),
                    onPressed: _unpair,
                    icon: const Icon(Icons.link_off_rounded),
                    label: const Text('Unpair this phone'),
                  ),
                ],
              ),
            ),
          ],
        );
      },
    );
  }

  /// Dark mode + text size (saved on the phone, applied to the whole app).
  Widget _appearanceCard() {
    final app = AppSettings.instance;
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) => AppCard(
        padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 4),
        child: Column(
          children: [
            SwitchListTile(
              value: app.darkMode,
              onChanged: app.setDarkMode,
              secondary: Icon(
                app.darkMode ? Icons.dark_mode_rounded : Icons.light_mode_rounded,
                color: AssasColors.primary,
              ),
              title: Text('Dark mode', style: AssasText.bodyStrong),
            ),
            const Divider(height: 1),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
              child: Row(
                children: [
                  Icon(Icons.format_size_rounded, color: AssasColors.primary),
                  const SizedBox(width: 16),
                  Expanded(child: Text('Text size', style: AssasText.bodyStrong)),
                  Text(app.textScaleLabel, style: AssasText.mutedLabel),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              child: Row(
                children: [
                  Text(
                    'A',
                    style: TextStyle(fontSize: 13, fontWeight: FontWeight.w700, color: AssasColors.muted),
                  ),
                  Expanded(
                    // Fixed steps only (Small -> Larger), so the layout never breaks.
                    child: Slider(
                      value: app.textScaleIndex.toDouble(),
                      min: 0,
                      max: (AppSettings.textScales.length - 1).toDouble(),
                      divisions: AppSettings.textScales.length - 1,
                      label: app.textScaleLabel,
                      onChanged: (v) => app.setTextScaleIndex(v.round()),
                    ),
                  ),
                  Text(
                    'A',
                    style: TextStyle(fontSize: 20, fontWeight: FontWeight.w700, color: AssasColors.muted),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _probesCard() {
    if (_settingsUnavailable) {
      return const EmptyState(
        icon: Icons.tune_rounded,
        title: 'Not available yet',
        subtitle: 'This setting will be available in a later version.',
      );
    }
    final s = _settings;
    if (s == null) {
      return const AppCard(
        child: Center(
          child: Padding(
            padding: EdgeInsets.all(8),
            child: CircularProgressIndicator(),
          ),
        ),
      );
    }
    return AppCard(
      padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 4),
      child: SwitchListTile(
        value: s.activeProbes,
        onChanged: _saving ? null : _toggleProbes,
        title: const Text(
          'Active identification',
          style: TextStyle(fontWeight: FontWeight.w700),
        ),
        subtitle: Text(
          'Lets Assas send light local checks to identify devices more accurately. '
          'Turn off for fully passive monitoring.',
          style: AssasText.small,
        ),
      ),
    );
  }
}
