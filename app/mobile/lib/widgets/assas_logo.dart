import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

/// Assas eye logo in a white rounded box.
/// Uses assets/images/logo_eye.png (copied from the old app). If the file is
/// missing, a shield icon is shown instead of crashing.
class AssasLogo extends StatelessWidget {
  const AssasLogo({super.key, this.size = 36});

  final double size;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      padding: EdgeInsets.all(size * 0.12),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(size * 0.25),
      ),
      child: Image.asset(
        'assets/images/logo_eye.png',
        fit: BoxFit.contain,
        errorBuilder: (_, __, ___) => Icon(
          Icons.shield_outlined,
          color: AssasColors.primary,
          size: size * 0.6,
        ),
      ),
    );
  }
}
