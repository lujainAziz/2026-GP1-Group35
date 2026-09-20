import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'theme/app_theme.dart';
import 'widgets/risk_gauge_widget.dart';

class MobileDashboard extends StatefulWidget {
  const MobileDashboard({super.key});

  @override
  State<MobileDashboard> createState() => _MobileDashboardState();
}

class _MobileDashboardState extends State<MobileDashboard> {
  final String apiBaseUrl = "http://10.0.2.2:8000";

  int totalKnown = 15;
  int activeDevices = 9;
  int riskScore = 18; // Live network risk score
  String pipelineName = "Assas SPAN Ingestion Pipeline";
  bool isConnected = false;
  bool isLoading = false;
  String selectedFilter = 'All';
  String searchQuery = '';
  final TextEditingController _searchController = TextEditingController();

  // Lujain's verified sprint 1 fallback baseline
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
    fetchDataFromApi();
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<void> fetchDataFromApi() async {
    setState(() => isLoading = true);
    try {
      final healthUri = Uri.parse('$apiBaseUrl/api/system/health');
      final healthResponse = await http.get(healthUri).timeout(const Duration(seconds: 4));

      if (healthResponse.statusCode == 200) {
        final data = json.decode(healthResponse.body);
        setState(() {
          totalKnown = data['total_known'] ?? 15;
          activeDevices = data['active_devices'] ?? 9;
          pipelineName = data['pipeline'] ?? "Assas SPAN Ingestion Pipeline";
          riskScore = data['risk_score'] ?? 18;
          isConnected = true;
        });
      }

      final devicesUri = Uri.parse('$apiBaseUrl/api/devices');
      final devicesResponse = await http.get(devicesUri).timeout(const Duration(seconds: 4));

      if (devicesResponse.statusCode == 200) {
        final List<dynamic> list = json.decode(devicesResponse.body);
        setState(() {
          devices = list.map((e) => Map<String, dynamic>.from(e)).toList();
        });
      }
    } catch (e) {
      setState(() {
        isConnected = false;
      });
      debugPrint("Offline mode or API unreachable: $e");
    } finally {
      setState(() => isLoading = false);
    }
  }

  void _showDeviceDetails(BuildContext context, Map<String, dynamic> device) {
    HapticFeedback.lightImpact();
    final isDark = Theme.of(context).brightness == Brightness.dark;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: isDark ? AppColors.darkCardSurface : Colors.white,
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
                    color: isDark ? Colors.white24 : Colors.grey.shade300,
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
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                        color: isDark ? Colors.white : AppColors.darkPurpleBase,
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
              Divider(
                height: 28,
                color: isDark ? AppColors.darkCardBorder : AppColors.lightCardBorder,
              ),
              _buildDetailRow("Device Category", category, isDark),
              _buildDetailRow("IP Address", ip, isDark),
              _buildDetailRow("MAC Address", mac, isDark),
              _buildDetailRow("Hardware Vendor (OUI)", vendor, isDark),
              _buildDetailRow("Inspection Mode", "Passive SPAN (eth0)", isDark),
              const SizedBox(height: 12),
            ],
          ),
        );
      },
    );
  }

  Widget _buildDetailRow(String label, String value, bool isDark) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: TextStyle(
              color: isDark ? Colors.grey.shade400 : Colors.grey.shade600,
              fontSize: 13,
            ),
          ),
          Text(
            value,
            style: TextStyle(
              fontWeight: FontWeight.w600,
              color: isDark ? Colors.white : AppColors.darkPurpleBase,
              fontSize: 13,
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    final filteredDevices = devices.where((device) {
      final matchesFilter = (selectedFilter == 'All') ||
          (selectedFilter == 'Online' && device['status'] == 'online') ||
          (selectedFilter == 'Offline' && device['status'] == 'offline');

      final query = searchQuery.trim().toLowerCase();
      final name = (device['hostname'] ?? device['name'] ?? '').toString().toLowerCase();
      final ip = (device['ip'] ?? '').toString().toLowerCase();
      final mac = (device['mac'] ?? '').toString().toLowerCase();
      final vendor = (device['vendor'] ?? '').toString().toLowerCase();

      final matchesSearch = query.isEmpty ||
          name.contains(query) ||
          ip.contains(query) ||
          mac.contains(query) ||
          vendor.contains(query);

      return matchesFilter && matchesSearch;
    }).toList();

    return Scaffold(
      body: SafeArea(
        child: RefreshIndicator(
          onRefresh: fetchDataFromApi,
          color: AppColors.vibrantPurple,
          child: SingleChildScrollView(
            physics: const AlwaysScrollableScrollPhysics(),
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // 1. Official Assas Branding Header
                Center(
                  child: Padding(
                    padding: const EdgeInsets.symmetric(vertical: 8.0),
                    child: Image.asset(
                      'assets/images/banner_assas.png',
                      fit: BoxFit.contain,
                      height: 52,
                    ),
                  ),
                ),
                const SizedBox(height: 8),

                // 2. SPAN Telemetry & Node Status
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Row(
                      children: [
                        Container(
                          width: 9,
                          height: 9,
                          decoration: BoxDecoration(
                            color: isConnected ? AppColors.statusSafe : AppColors.statusWarning,
                            shape: BoxShape.circle,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Text(
                          isConnected ? "Active • eth0 SPAN" : "Offline • Fallback",
                          style: TextStyle(
                            fontSize: 12.5,
                            fontWeight: FontWeight.w500,
                            color: isDark ? Colors.grey[300] : Colors.grey[700],
                          ),
                        ),
                      ],
                    ),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                      decoration: BoxDecoration(
                        color: isDark ? AppColors.darkCardSurface : Colors.white,
                        borderRadius: BorderRadius.circular(20),
                        border: Border.all(
                          color: isDark ? AppColors.darkCardBorder : AppColors.lightCardBorder,
                        ),
                      ),
                      child: Text(
                        "$totalKnown Total",
                        style: TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                          color: isDark ? Colors.white70 : AppColors.darkPurpleBase,
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 18),

                // 3. Central Dynamic Risk Gauge
                _buildCardContainer(
                  context,
                  child: Column(
                    children: [
                      Align(
                        alignment: Alignment.topRight,
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                          decoration: BoxDecoration(
                            color: AppColors.statusSafe.withOpacity(0.12),
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: const Text(
                            "live telemetry",
                            style: TextStyle(color: AppColors.statusSafe, fontSize: 10, fontWeight: FontWeight.w600),
                          ),
                        ),
                      ),
                      RiskGaugeWidget(riskScore: riskScore),
                    ],
                  ),
                ),
                const SizedBox(height: 16),

                // 4. Local Asset Inventory Summary Card
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(20),
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(
                      colors: [AppColors.darkPurpleAccent, AppColors.vibrantPurple],
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                    ),
                    borderRadius: BorderRadius.circular(20),
                    boxShadow: [
                      BoxShadow(
                        color: AppColors.vibrantPurple.withOpacity(0.25),
                        blurRadius: 14,
                        offset: const Offset(0, 6),
                      ),
                    ],
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            "LOCAL ASSET INVENTORY",
                            style: TextStyle(
                              color: Colors.white70,
                              fontSize: 11,
                              fontWeight: FontWeight.w700,
                              letterSpacing: 1.1,
                            ),
                          ),
                          const SizedBox(height: 6),
                          Text(
                            "$activeDevices Active Devices",
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 22,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            pipelineName,
                            style: const TextStyle(
                              color: Colors.white70,
                              fontSize: 11.5,
                            ),
                          ),
                        ],
                      ),
                      Container(
                        width: 44,
                        height: 44,
                        decoration: BoxDecoration(
                          color: Colors.white.withOpacity(0.16),
                          shape: BoxShape.circle,
                        ),
                        child: const Icon(Icons.wifi_tethering, color: Colors.white, size: 24),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 18),

                // 5. Search Bar
                Container(
                  decoration: BoxDecoration(
                    color: isDark ? AppColors.darkCardSurface : Colors.white,
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(
                      color: isDark ? AppColors.darkCardBorder : AppColors.lightCardBorder,
                    ),
                  ),
                  child: TextField(
                    controller: _searchController,
                    onChanged: (val) => setState(() => searchQuery = val),
                    style: TextStyle(color: isDark ? Colors.white : AppColors.darkPurpleBase),
                    decoration: InputDecoration(
                      hintText: "Search IP, MAC, Hostname or Vendor...",
                      hintStyle: TextStyle(
                        color: isDark ? Colors.grey.shade500 : Colors.grey.shade400,
                        fontSize: 13,
                      ),
                      prefixIcon: const Icon(Icons.search, color: AppColors.vibrantPurple, size: 20),
                      suffixIcon: searchQuery.isNotEmpty
                          ? IconButton(
                              icon: const Icon(Icons.clear, size: 18, color: Colors.grey),
                              onPressed: () {
                                _searchController.clear();
                                setState(() => searchQuery = '');
                              },
                            )
                          : null,
                      border: InputBorder.none,
                      contentPadding: const EdgeInsets.symmetric(vertical: 14),
                    ),
                  ),
                ),
                const SizedBox(height: 14),

                // 6. Filter Chips
                Row(
                  children: [
                    _buildFilterChip("All", isDark),
                    const SizedBox(width: 8),
                    _buildFilterChip("Online", isDark),
                    const SizedBox(width: 8),
                    _buildFilterChip("Offline", isDark),
                  ],
                ),
                const SizedBox(height: 16),

                // 7. Filtered Devices List
                if (filteredDevices.isEmpty)
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(32),
                    alignment: Alignment.center,
                    child: Column(
                      children: [
                        Icon(Icons.search_off, size: 36, color: Colors.grey.shade400),
                        const SizedBox(height: 8),
                        Text(
                          "No matching devices found",
                          style: TextStyle(color: Colors.grey.shade500, fontSize: 13),
                        ),
                      ],
                    ),
                  )
                else
                  ListView.separated(
                    shrinkWrap: true,
                    physics: const NeverScrollableScrollPhysics(),
                    itemCount: filteredDevices.length,
                    separatorBuilder: (context, index) => const SizedBox(height: 10),
                    itemBuilder: (context, index) {
                      final item = filteredDevices[index];
                      final bool isOnline = (item['status'] ?? 'online') == 'online';

                      return GestureDetector(
                        behavior: HitTestBehavior.opaque,
                        onTap: () => _showDeviceDetails(context, item),
                        child: Container(
                          padding: const EdgeInsets.all(14),
                          decoration: BoxDecoration(
                            color: isDark ? AppColors.darkCardSurface : Colors.white,
                            borderRadius: BorderRadius.circular(14),
                            border: Border.all(
                              color: isDark ? AppColors.darkCardBorder : AppColors.lightCardBorder,
                            ),
                          ),
                          child: Row(
                            children: [
                              Container(
                                width: 40,
                                height: 40,
                                decoration: BoxDecoration(
                                  color: isOnline
                                      ? AppColors.statusSafe.withOpacity(0.12)
                                      : Colors.grey.withOpacity(0.12),
                                  borderRadius: BorderRadius.circular(10),
                                ),
                                child: Icon(
                                  Icons.wifi,
                                  color: isOnline ? AppColors.statusSafe : Colors.grey,
                                  size: 20,
                                ),
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      item['hostname'] ?? item['name'] ?? "Unknown Host",
                                      style: TextStyle(
                                        fontSize: 14,
                                        fontWeight: FontWeight.w700,
                                        color: isDark ? Colors.white : AppColors.darkPurpleBase,
                                      ),
                                    ),
                                    const SizedBox(height: 3),
                                    Text(
                                      "${item['vendor'] ?? 'Unknown'} • ${item['ip'] ?? '0.0.0.0'}",
                                      style: TextStyle(
                                        fontSize: 12,
                                        color: isDark ? Colors.grey.shade400 : Colors.grey.shade600,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                              Icon(
                                Icons.chevron_right,
                                color: isDark ? Colors.grey.shade600 : Colors.grey.shade400,
                                size: 20,
                              ),
                            ],
                          ),
                        ),
                      );
                    },
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildFilterChip(String label, bool isDark) {
    final bool isSelected = selectedFilter == label;
    return GestureDetector(
      onTap: () {
        HapticFeedback.lightImpact();
        setState(() => selectedFilter = label);
      },
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 7),
        decoration: BoxDecoration(
          color: isSelected
              ? AppColors.vibrantPurple
              : (isDark ? AppColors.darkCardSurface : Colors.white),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: isSelected
                ? AppColors.vibrantPurple
                : (isDark ? AppColors.darkCardBorder : AppColors.lightCardBorder),
          ),
        ),
        child: Text(
          label,
          style: TextStyle(
            color: isSelected
                ? Colors.white
                : (isDark ? Colors.grey.shade300 : Colors.grey.shade700),
            fontSize: 12,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
    );
  }

  Widget _buildCardContainer(BuildContext context, {required Widget child}) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: isDark ? AppColors.darkCardSurface : AppColors.lightCardSurface,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: isDark ? AppColors.darkCardBorder : AppColors.lightCardBorder,
          width: 1,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(isDark ? 0.25 : 0.04),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: child,
    );
  }
}