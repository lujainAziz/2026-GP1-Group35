import 'dart:async';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';

import '../theme/assas_ui.dart';
import 'ui_kit.dart';

// Toast and confirm dialog from the design (replace the stock Android
// SnackBar and AlertDialog).

OverlayEntry? _toast;
Timer? _toastTimer;

/// Design toast: a small pill (ink on bg) 104 above the bottom, fades up in
/// .3s and disappears after 1.8s. A new toast replaces the old one.
void showToast(BuildContext context, String message) {
  final overlay = Overlay.maybeOf(context, rootOverlay: true);
  if (overlay == null) return;
  _toastTimer?.cancel();
  _toast?.remove();
  final entry = OverlayEntry(
    builder: (context) => Positioned(
      left: 24,
      right: 24,
      bottom: 104 + MediaQuery.paddingOf(context).bottom * .5,
      child: IgnorePointer(
        child: Center(
          child: TweenAnimationBuilder<double>(
            tween: Tween(begin: 0, end: 1),
            duration: const Duration(milliseconds: 300),
            curve: Curves.easeOut,
            builder: (context, v, child) => Opacity(
              opacity: v,
              child: Transform.translate(offset: Offset(0, 10 * (1 - v)), child: child),
            ),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 11),
              decoration: BoxDecoration(
                color: Ui.ink,
                borderRadius: BorderRadius.circular(UiRadius.pill),
              ),
              child: Text(
                message,
                textAlign: TextAlign.center,
                style: UiText.toast.copyWith(color: Ui.bg, decoration: TextDecoration.none),
              ),
            ),
          ),
        ),
      ),
    ),
  );
  _toast = entry;
  overlay.insert(entry);
  _toastTimer = Timer(const Duration(milliseconds: 1800), () {
    if (_toast == entry) {
      entry.remove();
      _toast = null;
    }
  });
}

/// Confirm dialog in the design's style (glass card, two round buttons).
/// Returns true when the user confirms.
Future<bool> showConfirm(
  BuildContext context, {
  required String title,
  required String message,
  required String confirmLabel,
  String cancelLabel = 'Cancel',
  bool danger = false,
}) async {
  final ok = await showGeneralDialog<bool>(
    context: context,
    barrierDismissible: true,
    barrierLabel: cancelLabel,
    barrierColor: const Color(0x8C000000),
    transitionDuration: const Duration(milliseconds: 250),
    pageBuilder: (context, _, __) => Center(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 22),
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
                    Text(title, style: UiText.section),
                    const SizedBox(height: 10),
                    Text(message, style: UiText.why.copyWith(color: Ui.mute)),
                    const SizedBox(height: 22),
                    Row(
                      children: [
                        Expanded(
                          child: PillButton(
                            label: cancelLabel,
                            filled: false,
                            borderColor: Ui.line,
                            onTap: () => Navigator.of(context).pop(false),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: PillButton(
                            label: confirmLabel,
                            filled: !danger,
                            textColor: danger ? Ui.crit : null,
                            borderColor: danger ? Ui.mix(Ui.crit, .34, Ui.line) : null,
                            background: danger ? Ui.fade(Ui.crit, .10) : null,
                            onTap: () => Navigator.of(context).pop(true),
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
    ),
    transitionBuilder: (context, anim, _, child) {
      final v = kUiEase.transform(anim.value);
      return Opacity(
        opacity: anim.value,
        child: Transform.scale(scale: .96 + .04 * v, child: child),
      );
    },
  );
  return ok == true;
}
