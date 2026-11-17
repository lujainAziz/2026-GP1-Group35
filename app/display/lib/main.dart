import 'package:flutter/material.dart';

import 'display_ui.dart';

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
      theme: DisplayUi.theme,
      builder: (context, child) => _DisplayCanvas(child: child ?? const SizedBox()),
      home: const StatusScreen(),
    );
  }
}

class _DisplayCanvas extends StatelessWidget {
  const _DisplayCanvas({required this.child});
  final Widget child;
  @override
  Widget build(BuildContext context) => ColoredBox(
        color: DisplayUi.bg,
        child: LayoutBuilder(builder: (context, constraints) => Center(
          child: FittedBox(fit: BoxFit.contain, child: SizedBox(
            width: 1024, height: 600,
            child: MediaQuery(data: MediaQuery.of(context).copyWith(size: const Size(1024, 600)),
              child: TickerMode(enabled: false, child: DisplayBackground(child: child))),
          )),
        )),
      );
}
