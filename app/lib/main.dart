import 'package:flutter/material.dart';
import 'theme/app_theme.dart';
import 'screens/main_shell_screen.dart';
import 'screen_dashboard.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const AssasUnifiedApp());
}

class AssasUnifiedApp extends StatelessWidget {
  const AssasUnifiedApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Assas | عسس',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.lightTheme, // إجباري لايت مود في كل الأحوال
      themeMode: ThemeMode.light,      // تشغيل اللايت مود كوضع أساسي
      home: LayoutBuilder(
        builder: (context, constraints) {
          if (constraints.maxWidth > 700) {
            return const ApplianceScreenDashboard();
          }
          // توجيه الجوال لشاشة القائمة والصفحات المتعددة
          return const MainShellScreen();
        },
      ),
    );
  }
}