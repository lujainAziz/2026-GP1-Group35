import 'package:assas_core/assas_core.dart';
import 'package:flutter/material.dart';

import 'screens/status_screen.dart';

/// 7-inch on-device screen. Read-only: no buttons, no navigation.
void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const AssasDisplayApp());
}

class AssasDisplayApp extends StatelessWidget {
  const AssasDisplayApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Assas Display',
      debugShowCheckedModeBanner: false,
      theme: AssasTheme.light,
      builder: (context, child) => AssasBackground(child: child ?? const SizedBox()),
      home: const StatusScreen(),
    );
  }
}
