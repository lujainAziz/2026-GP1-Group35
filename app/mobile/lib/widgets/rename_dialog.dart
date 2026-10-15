import 'dart:ui' as ui;

import 'package:flutter/material.dart';

import '../theme/assas_ui.dart';
import 'ui_kit.dart';

/// Rename a device. Returns:
/// - null: cancelled
/// - '': go back to the name Assas detected
/// - text: the new name
Future<String?> showRenameDialog(
  BuildContext context, {
  required String current,
  required String detected,
  required bool hasUserName,
}) {
  return showGeneralDialog<String>(
    context: context,
    barrierDismissible: true,
    barrierLabel: 'Cancel',
    barrierColor: const Color(0x8C000000),
    transitionDuration: const Duration(milliseconds: 250),
    pageBuilder: (context, _, __) => _RenameDialog(
      current: current,
      detected: detected,
      hasUserName: hasUserName,
    ),
    transitionBuilder: (context, anim, _, child) {
      final v = kUiEase.transform(anim.value);
      return Opacity(
        opacity: anim.value,
        child: Transform.scale(scale: .96 + .04 * v, child: child),
      );
    },
  );
}

class _RenameDialog extends StatefulWidget {
  const _RenameDialog({required this.current, required this.detected, required this.hasUserName});

  final String current;
  final String detected;
  final bool hasUserName;

  @override
  State<_RenameDialog> createState() => _RenameDialogState();
}

class _RenameDialogState extends State<_RenameDialog> {
  late final _text = TextEditingController(text: widget.current);

  @override
  void initState() {
    super.initState();
    _text.addListener(() => setState(() {}));
  }

  @override
  void dispose() {
    _text.dispose();
    super.dispose();
  }

  void _save() {
    final name = _text.text.trim();
    // Empty = back to the detected name.
    Navigator.of(context).pop(name == widget.detected ? '' : name);
  }

  @override
  Widget build(BuildContext context) {
    final changed = _text.text.trim() != widget.current;
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
                    Text('Rename device', style: UiText.section),
                    const SizedBox(height: 6),
                    Text(
                      'Only you see this name. Detected name: ${widget.detected}',
                      style: UiText.rowSubtitle.copyWith(color: Ui.mute),
                    ),
                    const SizedBox(height: 16),
                    TextField(
                      controller: _text,
                      autofocus: true,
                      maxLength: 40,
                      textInputAction: TextInputAction.done,
                      onSubmitted: (_) => _save(),
                      style: UiText.input,
                      cursorColor: Ui.acc,
                      decoration: InputDecoration(
                        hintText: widget.detected,
                        hintStyle: UiText.input.copyWith(color: Ui.mute),
                        counterStyle: UiText.mono(9, 500, color: Ui.mute),
                      ),
                    ),
                    if (widget.hasUserName) ...[
                      const SizedBox(height: 4),
                      Pressable(
                        onTap: () => Navigator.of(context).pop(''),
                        child: Padding(
                          padding: const EdgeInsets.symmetric(vertical: 6),
                          child: Text(
                            'USE DETECTED NAME',
                            style: UiText.link.copyWith(color: Ui.acc),
                          ),
                        ),
                      ),
                    ],
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
                        Expanded(
                          child: PillButton(
                            label: 'Save',
                            opacity: changed ? 1 : .4,
                            onTap: changed ? _save : null,
                          ),
                        ),
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
