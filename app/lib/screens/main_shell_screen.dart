import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import '../theme/app_theme.dart';
import '../widgets/risk_gauge_widget.dart';

class MainShellScreen extends StatefulWidget {
  const MainShellScreen({Key? key}) : super(key: key);

  @override
  State<MainShellScreen> createState() => _MainShellScreenState();
}

class _MainShellScreenState extends State<MainShellScreen> {
  int _currentIndex = 0;
  final String apiBaseUrl = "http://10.0.2.2:8000";

  int totalKnown = 15;
  int activeDevices = 9;
  int riskScore = 18; // Default live posture score
  String pipelineName = "Assas SPAN Ingestion Pipeline";
  bool isConnected = false;
  String selectedFilter = 'All';
  String searchQuery = '';
  final TextEditingController _searchController = TextEditingController();

  // Baseline verified edge device inventory
  List<Map<String, dynamic>> devices = [
    {
      "hostname": "Lujains-iPhone",
      "vendor": "Apple Inc.",
      "ip": "192.168.100.233",
      "mac": "3c:78:95:6a:5d:04",
      "category": "Smartphone",
      "status": "online"
    },
    {
      "hostname": "Yard-Cam",
      "vendor": "Hikvision",
      "ip": "192.168.100.133",
      "mac": "a4:14:37:1b:22:90",
      "category": "IoT Camera",
      "status": "online"
    },
    {
      "hostname": "Assas-AP (WR802N)",
      "vendor": "TP-Link",
      "ip": "192.168.100.1",
      "mac": "50:d4:f7:88:aa:11",
      "category": "Access Point",
      "status": "online"
    }
  ];

  @override
  void initState() {
    super.initState();
    _fetchTelemetry();
  }

  Future<void> _fetchTelemetry() async {
    try {
      final res = await http
          .get(Uri.parse('$apiBaseUrl/api/system/health'))
          .timeout(const Duration(seconds: 3));
      if (res.statusCode == 200) {
        final data = json.decode(res.body);
        if (mounted) {
          setState(() {
            totalKnown = data['total_known'] ?? 15;
            activeDevices = data['active_devices'] ?? 9;
            pipelineName = data['pipeline'] ?? pipelineName;
            isConnected = true;
          });
        }
      }
    } catch (_) {}
  }

  void _showDeviceDetails(BuildContext context, Map<String, dynamic> device) {
    HapticFeedback.lightImpact();

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.white,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (ctx) {
        final String hostname = device['hostname'] ?? device['name'] ?? "Unknown Host";
        final String ip = device['ip'] ?? "192.168.100.X";
        final String mac = device['mac'] ?? "3c:78:95:6a:5d:04";
        final String vendor = device['vendor'] ?? "Generic Device";
        final String category = device['category'] ?? "Network Endpoint";
        final String status = (device['status'] ?? "online").toString().toUpperCase();

        return Padding(
          padding: const EdgeInsets.fromLTRB(24, 16, 24, 32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Center(
                child: Container(
                  width: 44,
                  height: 4,
                  decoration: BoxDecoration(
                    color: Colors.grey.shade300,
                    borderRadius: BorderRadius.circular(10),
                  ),
                ),
              ),
              const SizedBox(height: 18),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Expanded(
                    child: Text(
                      hostname,
                      style: const TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                        color: AppColors.darkPurpleBase,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                    decoration: BoxDecoration(
                      color: AppColors.statusSafe.withOpacity(0.12),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Text(
                      status,
                      style: const TextStyle(
                        color: AppColors.statusSafe,
                        fontSize: 12,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                ],
              ),
              Divider(height: 28, color: AppColors.mediumPurple.withOpacity(0.1)),
              _buildDetailRow("Device Category", category),
              _buildDetailRow("IP Address", ip),
              _buildDetailRow("MAC Address", mac),
              _buildDetailRow("Hardware Vendor (OUI)", vendor),
              _buildDetailRow("Inspection Mode", "Passive SPAN (eth1)"),
              const SizedBox(height: 14),
            ],
          ),
        );
      },
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: TextStyle(color: Colors.grey.shade600, fontSize: 13)),
          Text(
            value,
            style: const TextStyle(
              fontWeight: FontWeight.w600,
              color: AppColors.darkPurpleBase,
              fontSize: 13,
            ),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF6F3F8), // Soft Lavender base
      body: SafeArea(
        child: IndexedStack(
          index: _currentIndex,
          children: [
            _buildDashboardPage(),
            _buildDevicesPage(),
            _buildThreatsPage(),
            _buildSettingsPage(),
          ],
        ),
      ),
      bottomNavigationBar: Container(
        decoration: BoxDecoration(
          color: Colors.white.withOpacity(0.9),
          border: Border(
            top: BorderSide(
              color: AppColors.mediumPurple.withOpacity(0.08),
              width: 1,
            ),
          ),
          boxShadow: [
            BoxShadow(
              color: AppColors.darkPurpleBase.withOpacity(0.04),
              blurRadius: 10,
              offset: const Offset(0, -3),
            ),
          ],
        ),
        child: BottomNavigationBar(
          currentIndex: _currentIndex,
          onTap: (index) {
            HapticFeedback.lightImpact();
            setState(() => _currentIndex = index);
          },
          type: BottomNavigationBarType.fixed,
          backgroundColor: Colors.transparent,
          elevation: 0,
          selectedItemColor: AppColors.vibrantPurple,
          unselectedItemColor: Colors.grey.shade500,
          selectedFontSize: 12,
          unselectedFontSize: 11,
          items: const [
            BottomNavigationBarItem(
              icon: Icon(Icons.dashboard_outlined),
              activeIcon: Icon(Icons.dashboard),
              label: "Dashboard",
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.devices_outlined),
              activeIcon: Icon(Icons.devices),
              label: "Devices",
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.shield_outlined),
              activeIcon: Icon(Icons.shield),
              label: "Threats",
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.settings_outlined),
              activeIcon: Icon(Icons.settings),
              label: "Settings",
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // TAB 1: DASHBOARD
  // ==========================================
  Widget _buildDashboardPage() {
    return SingleChildScrollView(
      physics: const BouncingScrollPhysics(),
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Center(
            child: Padding(
              padding: const EdgeInsets.symmetric(vertical: 8.0),
              child: Image.asset(
                'assets/images/banner_assas.png',
                fit: BoxFit.contain,
                height: 56,
              ),
            ),
          ),
          const SizedBox(height: 12),

          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                children: [
                  Container(
                    width: 8,
                    height: 8,
                    decoration: BoxDecoration(
                      color: isConnected ? AppColors.statusSafe : AppColors.statusWarning,
                      shape: BoxShape.circle,
                    ),
                  ),
                  const SizedBox(width: 8),
                  Text(
                    isConnected ? "Active • eth1 SPAN" : "Fallback • Local Mode",
                    style: const TextStyle(
                      fontSize: 12.5,
                      fontWeight: FontWeight.w600,
                      color: AppColors.darkPurpleBase,
                    ),
                  ),
                ],
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.85),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: AppColors.mediumPurple.withOpacity(0.12)),
                ),
                child: Text(
                  "$totalKnown Known Assets",
                  style: const TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                    color: AppColors.mediumPurple,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),

          _buildGlassCard(
            child: Column(
              children: [
                RiskGaugeWidget(riskScore: riskScore),
                const SizedBox(height: 16),
                const Divider(height: 20, thickness: 0.8),

                // Simulation Toggles for the Presentation
                Row(
                  children: [
                    const Icon(Icons.science_outlined, size: 16, color: Colors.grey),
                    const SizedBox(width: 6),
                    Text(
                      "Simulation Trigger:",
                      style: TextStyle(
                        fontSize: 11.5,
                        fontWeight: FontWeight.w600,
                        color: Colors.grey.shade700,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 10),
                Row(
                  children: [
                    Expanded(
                      child: _buildSimulationButton(
                        label: "Safe",
                        score: 18,
                        color: AppColors.statusSafe,
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: _buildSimulationButton(
                        label: "Warning",
                        score: 54,
                        color: AppColors.statusWarning,
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: _buildSimulationButton(
                        label: "Critical",
                        score: 88,
                        color: AppColors.statusDanger,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          _buildGlassCard(
            color: AppColors.vibrantPurple.withOpacity(0.06),
            borderColor: AppColors.vibrantPurple.withOpacity(0.2),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      "LOCAL ASSET INVENTORY",
                      style: TextStyle(
                        color: AppColors.mediumPurple,
                        fontSize: 11,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 1.1,
                      ),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      "$activeDevices Active Devices",
                      style: const TextStyle(
                        color: AppColors.darkPurpleBase,
                        fontSize: 22,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      pipelineName,
                      style: TextStyle(color: Colors.grey.shade700, fontSize: 12),
                    ),
                  ],
                ),
                ElevatedButton(
                  onPressed: () => setState(() => _currentIndex = 1),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.vibrantPurple,
                    foregroundColor: Colors.white,
                    elevation: 0,
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                  ),
                  child: const Text("View All"),
                )
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // TAB 2: DEVICES (Directly Clickable Cards)
  // ==========================================
  Widget _buildDevicesPage() {
    final filtered = devices.where((d) {
      final matchFilter = (selectedFilter == 'All') ||
          (selectedFilter == 'Online' && d['status'] == 'online') ||
          (selectedFilter == 'Offline' && d['status'] == 'offline');
      final q = searchQuery.toLowerCase();
      final name = (d['hostname'] ?? '').toLowerCase();
      final ip = (d['ip'] ?? '').toLowerCase();
      return matchFilter && (q.isEmpty || name.contains(q) || ip.contains(q));
    }).toList();

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            "Connected Endpoints",
            style: TextStyle(
              fontSize: 22,
              fontWeight: FontWeight.bold,
              color: AppColors.darkPurpleBase,
            ),
          ),
          const SizedBox(height: 14),

          _buildGlassCard(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 4),
            child: TextField(
              controller: _searchController,
              onChanged: (v) => setState(() => searchQuery = v),
              decoration: const InputDecoration(
                hintText: "Search hostname, IP, vendor...",
                prefixIcon: Icon(Icons.search, color: AppColors.vibrantPurple),
                border: InputBorder.none,
              ),
            ),
          ),
          const SizedBox(height: 12),

          Expanded(
            child: ListView.separated(
              itemCount: filtered.length,
              separatorBuilder: (_, __) => const SizedBox(height: 10),
              itemBuilder: (ctx, i) {
                final item = filtered[i];
                final bool isOnline = (item['status'] ?? 'online') == 'online';

                // Guaranteed direct clickable wrapper with full hit-test absorption
                return GestureDetector(
                  behavior: HitTestBehavior.opaque,
                  onTap: () => _showDeviceDetails(context, item),
                  child: _buildGlassCard(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                    child: Row(
                      children: [
                        Container(
                          width: 42,
                          height: 42,
                          decoration: BoxDecoration(
                            color: isOnline
                                ? AppColors.statusSafe.withOpacity(0.15)
                                : Colors.grey.withOpacity(0.15),
                            borderRadius: BorderRadius.circular(10),
                          ),
                          child: Icon(
                            Icons.wifi,
                            color: isOnline ? AppColors.statusSafe : Colors.grey,
                            size: 22,
                          ),
                        ),
                        const SizedBox(width: 14),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                item['hostname'] ?? "Unknown Host",
                                style: const TextStyle(
                                  fontWeight: FontWeight.bold,
                                  fontSize: 15,
                                  color: AppColors.darkPurpleBase,
                                ),
                              ),
                              const SizedBox(height: 3),
                              Text(
                                "${item['vendor']} • ${item['ip']}",
                                style: TextStyle(
                                  color: Colors.grey.shade600,
                                  fontSize: 12.5,
                                ),
                              ),
                            ],
                          ),
                        ),
                        const Icon(
                          Icons.chevron_right,
                          color: AppColors.mediumPurple,
                          size: 22,
                        ),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // TAB 3: THREATS
  // ==========================================
  Widget _buildThreatsPage() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24.0),
        child: _buildGlassCard(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.shield_outlined, size: 58, color: AppColors.vibrantPurple),
              const SizedBox(height: 14),
              const Text(
                "Threat Detection Not Yet Enabled",
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                  color: AppColors.darkPurpleBase,
                ),
              ),
              const SizedBox(height: 6),
              Text(
                "Threat detection is not enabled yet. Signature-based detection (Suricata) is planned for Sprint 1; the appliance currently performs passive device discovery and classification only.",
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.grey.shade600, fontSize: 13),
              ),
            ],
          ),
        ),
      ),
    );
  }

  // ==========================================
  // TAB 4: SETTINGS
  // ==========================================
  Widget _buildSettingsPage() {
    return Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            "Settings & Appliance",
            style: TextStyle(
              fontSize: 22,
              fontWeight: FontWeight.bold,
              color: AppColors.darkPurpleBase,
            ),
          ),
          const SizedBox(height: 20),
          _buildGlassCard(
            child: const ListTile(
              contentPadding: EdgeInsets.zero,
              leading: Icon(Icons.router_outlined, color: AppColors.vibrantPurple),
              title: Text(
                "Assas Appliance Core",
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              subtitle: Text("Raspberry Pi 5 Gateway"),
              trailing: Text(
                "10.0.2.2:8000",
                style: TextStyle(
                  fontWeight: FontWeight.bold,
                  color: AppColors.mediumPurple,
                ),
              ),
            ),
          ),
          const SizedBox(height: 14),
          _buildGlassCard(
            child: const ListTile(
              contentPadding: EdgeInsets.zero,
              leading: Icon(Icons.palette_outlined, color: AppColors.vibrantPurple),
              title: Text("Active Appearance"),
              subtitle: Text("Soft Lavender Clean Mode"),
              trailing: Icon(Icons.check_circle, color: AppColors.statusSafe),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSimulationButton({
    required String label,
    required int score,
    required Color color,
  }) {
    final bool isSelected = riskScore == score;
    return OutlinedButton(
      onPressed: () {
        HapticFeedback.mediumImpact();
        setState(() => riskScore = score);
      },
      style: OutlinedButton.styleFrom(
        padding: const EdgeInsets.symmetric(vertical: 8),
        backgroundColor: isSelected ? color.withOpacity(0.18) : Colors.white.withOpacity(0.6),
        side: BorderSide(
          color: isSelected ? color : Colors.grey.shade300,
          width: isSelected ? 1.8 : 1.0,
        ),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
      ),
      child: Text(
        "$label ($score)",
        style: TextStyle(
          color: isSelected ? color : Colors.grey.shade700,
          fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
          fontSize: 11.5,
        ),
      ),
    );
  }

  Widget _buildGlassCard({
    required Widget child,
    EdgeInsetsGeometry padding = const EdgeInsets.all(18),
    Color? color,
    Color? borderColor,
  }) {
    return Container(
      width: double.infinity,
      padding: padding,
      decoration: BoxDecoration(
        color: color ?? Colors.white.withOpacity(0.75),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: borderColor ?? Colors.white.withOpacity(0.9),
          width: 1.2,
        ),
        boxShadow: [
          BoxShadow(
            color: AppColors.darkPurpleBase.withOpacity(0.04),
            blurRadius: 16,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: child,
    );
  }
}