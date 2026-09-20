import 'package:flutter/material.dart';
import 'theme/app_theme.dart';
import 'widgets/risk_gauge_widget.dart';

class ApplianceScreenDashboard extends StatelessWidget {
  const ApplianceScreenDashboard({super.key});

  @override
  Widget build(BuildContext context) {
    // Kiosk Telemetry Constants
    const int riskScore = 28;
    const int activeEndpoints = 4;

    return Scaffold(
      backgroundColor: AppColors.lightBackground, // خلفية لافندر فاتحة وناعمة تبرز درجات اللوجو الداكنة
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(20.0),
          child: Column(
            children: [
              // Top Appliance Kiosk App Bar
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Image.asset(
                    'assets/images/banner_assas.png',
                    fit: BoxFit.contain,
                    height: 40,
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
                    decoration: BoxDecoration(
                      color: AppColors.lightCardSurface,
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(color: AppColors.lightCardBorder),
                    ),
                    child: Row(
                      children: [
                        Container(
                          width: 8,
                          height: 8,
                          decoration: const BoxDecoration(
                            color: AppColors.statusSafe,
                            shape: BoxShape.circle,
                          ),
                        ),
                        const SizedBox(width: 8),
                        const Text(
                          "Appliance Online • eth1 SPAN Mode",
                          style: TextStyle(
                            color: AppColors.darkPurpleBase,
                            fontSize: 12,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 16),

              // Main Dashboard Two-Column Layout (1024x600 Optimized)
              Expanded(
                child: Row(
                  children: [
                    // Column 1: Central Interactive Risk Posture & Logo Eye
                    Expanded(
                      flex: 5,
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                        decoration: BoxDecoration(
                          color: AppColors.lightCardSurface,
                          borderRadius: BorderRadius.circular(24),
                          border: Border.all(color: AppColors.lightCardBorder),
                          boxShadow: [
                            BoxShadow(
                              color: AppColors.darkPurpleBase.withOpacity(0.04),
                              blurRadius: 18,
                              offset: const Offset(0, 6),
                            ),
                          ],
                        ),
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: const [
                            Text(
                              'NETWORK RISK POSTURE',
                              style: TextStyle(
                                color: AppColors.mediumPurple,
                                fontSize: 11,
                                fontWeight: FontWeight.w800,
                                letterSpacing: 1.2,
                              ),
                            ),
                            SizedBox(height: 10),
                            RiskGaugeWidget(riskScore: riskScore),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(width: 18),

                    // Column 2: System Telemetry & Detection Status
                    Expanded(
                      flex: 6,
                      child: Column(
                        children: [
                          // Suricata IDS Telemetry Card
                          Expanded(
                            child: Container(
                              padding: const EdgeInsets.all(18),
                              decoration: BoxDecoration(
                                color: AppColors.lightCardSurface,
                                borderRadius: BorderRadius.circular(20),
                                border: Border.all(color: AppColors.lightCardBorder),
                                boxShadow: [
                                  BoxShadow(
                                    color: AppColors.darkPurpleBase.withOpacity(0.03),
                                    blurRadius: 14,
                                    offset: const Offset(0, 4),
                                  ),
                                ],
                              ),
                              child: Row(
                                children: [
                                  Container(
                                    width: 50,
                                    height: 50,
                                    decoration: BoxDecoration(
                                      color: Colors.grey.withOpacity(0.12),
                                      borderRadius: BorderRadius.circular(14),
                                    ),
                                    child: const Icon(
                                      Icons.shield_outlined,
                                      color: Colors.grey,
                                      size: 28,
                                    ),
                                  ),
                                  const SizedBox(width: 16),
                                  Expanded(
                                    child: Column(
                                      crossAxisAlignment: CrossAxisAlignment.start,
                                      mainAxisAlignment: MainAxisAlignment.center,
                                      children: const [
                                        Text(
                                          'Threat Detection',
                                          style: TextStyle(
                                            color: AppColors.darkPurpleBase,
                                            fontSize: 16,
                                            fontWeight: FontWeight.w700,
                                          ),
                                        ),
                                        SizedBox(height: 4),
                                        Text(
                                          'Planned for Sprint 1 — not yet enabled',
                                          style: TextStyle(
                                            color: Colors.black54,
                                            fontSize: 12,
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                          const SizedBox(height: 14),

                          // Active Local Assets Telemetry Card
                          Expanded(
                            child: Container(
                              padding: const EdgeInsets.all(18),
                              decoration: BoxDecoration(
                                color: AppColors.lightCardSurface,
                                borderRadius: BorderRadius.circular(20),
                                border: Border.all(color: AppColors.lightCardBorder),
                                boxShadow: [
                                  BoxShadow(
                                    color: AppColors.darkPurpleBase.withOpacity(0.03),
                                    blurRadius: 14,
                                    offset: const Offset(0, 4),
                                  ),
                                ],
                              ),
                              child: Row(
                                children: [
                                  Container(
                                    width: 50,
                                    height: 50,
                                    decoration: BoxDecoration(
                                      color: AppColors.vibrantPurple.withOpacity(0.1),
                                      borderRadius: BorderRadius.circular(14),
                                    ),
                                    child: const Icon(
                                      Icons.sensors_rounded,
                                      color: AppColors.vibrantPurple,
                                      size: 28,
                                    ),
                                  ),
                                  const SizedBox(width: 16),
                                  Expanded(
                                    child: Column(
                                      crossAxisAlignment: CrossAxisAlignment.start,
                                      mainAxisAlignment: MainAxisAlignment.center,
                                      children: [
                                        const Text(
                                          'Active Local Assets',
                                          style: TextStyle(
                                            color: AppColors.darkPurpleBase,
                                            fontSize: 16,
                                            fontWeight: FontWeight.w700,
                                          ),
                                        ),
                                        const SizedBox(height: 4),
                                        Text(
                                          '$activeEndpoints Endpoints Discovered via SPAN',
                                          style: const TextStyle(
                                            color: Colors.black54,
                                            fontSize: 12,
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}