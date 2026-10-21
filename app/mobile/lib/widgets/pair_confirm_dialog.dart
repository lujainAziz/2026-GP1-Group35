import 'package:flutter/foundation.dart' show kIsWeb, defaultTargetPlatform, TargetPlatform;
import 'dart:ui' as ui;

import 'package:device_info_plus/device_info_plus.dart';
import 'package:flutter/material.dart';

import '../theme/assas_ui.dart';
import 'ui_kit.dart';

/// Fallback when the phone's name cannot be read.
String defaultPhoneName() {
  if (kIsWeb) return 'Web browser';
  return defaultTargetPlatform == TargetPlatform.iOS ? 'iPhone' : 'Android phone';
}

/// The phone's own name (e.g. "Maraheb's iPhone", "Galaxy S23"), max 40.
Future<String> readPhoneName() async {
  var name = '';
  try {
    final info = DeviceInfoPlugin();
    if (!kIsWeb && defaultTargetPlatform == TargetPlatform.android) {
      final a = await info.androidInfo;
      name = a.name.trim();
      if (name.isEmpty) {
        final brand = a.brand.isEmpty ? '' : '${a.brand[0].toUpperCase()}${a.brand.substring(1)} ';
        name = '$brand${a.model}'.trim();
      }
    } else if (!kIsWeb && defaultTargetPlatform == TargetPlatform.iOS) {
      final i = await info.iosInfo;
      name = i.name.trim();
      // iOS 16+ only returns "iPhone" without a special permission: use the model.
      if (name.isEmpty || name == 'iPhone') name = i.modelName.trim();
    }
  } catch (_) {
    // keep the fallback
  }
  if (name.isEmpty) name = defaultPhoneName();
  return name.length > 40 ? name.substring(0, 40) : name;
}

/// Confirm before pairing (Maraheb's spec, part 1).
/// Returns the phone name to send, or null when the user cancels
/// (then no request is sent).
Future<String?> showPairConfirm(BuildContext context) {
  return showGeneralDialog<String>(
    context: context,
    barrierDismissible: true,
    barrierLabel: 'Cancel',
    barrierColor: const Color(0x8C000000),
    transitionDuration: const Duration(milliseconds: 250),
    pageBuilder: (context, _, __) => const _PairConfirm(),
    transitionBuilder: (context, anim, _, child) {
      final v = kUiEase.transform(anim.value);
      return Opacity(
        opacity: anim.value,
        child: Transform.scale(scale: .96 + .04 * v, child: child),
      );
    },
  );
}

class _PairConfirm extends StatefulWidget {
  const _PairConfirm();

  @override
  State<_PairConfirm> createState() => _PairConfirmState();
}

class _PairConfirmState extends State<_PairConfirm> {
  final _name = TextEditingController(text: defaultPhoneName());
  bool _edited = false;

  @override
  void initState() {
    super.initState();
    // Fill in the phone's real name, unless the user already started typing.
    readPhoneName().then((n) {
      if (mounted && !_edited) _name.text = n;
    });
  }

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  void _pair() => Navigator.of(context).pop(_name.text.trim());

  @override
  Widget build(BuildContext context) {
    return Center(
      child: SingleChildScrollView(
        padding: EdgeInsets.fromLTRB(22, 22, 22, 22 + MediaQuery.viewInsetsOf(context).bottom),
        child: Material(
          type: MaterialType.transparency,
          child: ClipRRect(
            borderRadius: BorderRadius.circular(UiRadius.settingsCard),
            child: BackdropFilter(
              filter: ui.ImageFilter.blur(sigmaX: 9, sigmaY: 9),
              child: Container(
                padding: const EdgeInsets.fromLTRB(22, 24, 22, 18),
                decoration: BoxDecoration(
                  color: Ui.fade(Ui.surf2, .94),
                  borderRadius: BorderRadius.circular(UiRadius.settingsCard),
                  border: Border.all(color: Ui.line),
                ),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Pair this phone with ASSAS?', style: UiText.section),
                    const SizedBox(height: 8),
                    Text(
                      "This phone will be able to see your network's devices and alerts.",
                      style: UiText.why.copyWith(color: Ui.mute),
                    ),
                    const SizedBox(height: 16),
                    Text('PHONE NAME', style: UiText.specLabel.copyWith(color: Ui.mute)),
                    const SizedBox(height: 6),
                    TextField(
                      controller: _name,
                      maxLength: 40,
                      textInputAction: TextInputAction.done,
                      onSubmitted: (_) => _pair(),
                      onChanged: (_) => _edited = true,
                      style: UiText.input,
                      cursorColor: Ui.acc,
                      decoration: InputDecoration(
                        hintText: 'Unnamed phone',
                        hintStyle: UiText.input.copyWith(color: Ui.mute),
                        counterStyle: UiText.mono(9, 500, color: Ui.mute),
                      ),
                    ),
                    const SizedBox(height: 14),
                    Row(
                      children: [
                        Expanded(
                          child: PillButton(
                            label: 'Cancel',
                            filled: false,
                            borderColor: Ui.line,
                            onTap: () => Navigator.of(context).pop(),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(child: PillButton(label: 'Pair', onTap: _pair)),
                      ],
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}