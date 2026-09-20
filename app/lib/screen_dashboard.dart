import 'package:flutter/material.dart';

import 'theme/app_theme.dart';

class ApplianceScreenDashboard extends StatelessWidget {
  const ApplianceScreenDashboard({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.lightBackground,
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Image.asset(
                    'assets/images/banner_assas.png',
                    fit: BoxFit.contain,
                    height: 40,
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 14,
                      vertical: 6,
                    ),
                    decoration: BoxDecoration(
                      color: AppColors.lightCardSurface,
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(color: AppColors.lightCardBorder),
                    ),
                    child: const Row(
                      children: [
                        Icon(
                          Icons.visibility_outlined,
                          size: 16,
                          color: AppColors.vibrantPurple,
                        ),
                        SizedBox(width: 8),
                        Text(
                          'ASSAS Local Status Display',
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
              Expanded(
                child: Row(
                  children: [
                    Expanded(
                      flex: 5,
                      child: _statusCard(
                        icon: Icons.devices_other_outlined,
                        title: 'SPRINT 0 DEVICE INVENTORY',
                        body:
                            'The appliance maintains a local inventory of discovered devices for the mobile application.',
                      ),
                    ),
                    const SizedBox(width: 18),
                    Expanded(
                      flex: 6,
                      child: Column(
                        children: [
                          Expanded(
                            child: _statusCard(
                              icon: Icons.settings_input_antenna_outlined,
                              title: 'Passive SPAN Capture',
                              body:
                                  'Mirrored traffic is received on the dedicated eth1 capture interface.',
                            ),
                          ),
                          const SizedBox(height: 14),
                          Expanded(
                            child: _statusCard(
                              icon: Icons.api_outlined,
                              title: 'Local Device API',
                              body:
                                  'The current Sprint 0 interface exposes device inventory and appliance health over the local API.',
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

  Widget _statusCard({
    required IconData icon,
    required String title,
    required String body,
  }) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: AppColors.lightCardSurface,
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: AppColors.lightCardBorder),
        boxShadow: [
          BoxShadow(
            color: AppColors.darkPurpleBase.withOpacity(0.04),
            blurRadius: 16,
            offset: const Offset(0, 5),
          ),
        ],
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            width: 58,
            height: 58,
            decoration: BoxDecoration(
              color: AppColors.vibrantPurple.withOpacity(0.1),
              borderRadius: BorderRadius.circular(16),
            ),
            child: Icon(
              icon,
              color: AppColors.vibrantPurple,
              size: 30,
            ),
          ),
          const SizedBox(height: 14),
          Text(
            title,
            textAlign: TextAlign.center,
            style: const TextStyle(
              color: AppColors.darkPurpleBase,
              fontSize: 15,
              fontWeight: FontWeight.w800,
              letterSpacing: 0.6,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            body,
            textAlign: TextAlign.center,
            style: const TextStyle(
              color: Colors.black54,
              fontSize: 12,
              height: 1.4,
            ),
          ),
        ],
      ),
    );
  }
}
