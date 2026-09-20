import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../services/assas_api_service.dart';
import '../theme/app_theme.dart';

class MainShellScreen extends StatefulWidget {
  const MainShellScreen({super.key});

  @override
  State<MainShellScreen> createState() => _MainShellScreenState();
}

class _MainShellScreenState extends State<MainShellScreen> {
  final AssasApiService _api = AssasApiService();
  final TextEditingController _searchController = TextEditingController();

  Timer? _pollTimer;
  int _currentIndex = 0;

  int totalKnown = 0;
  int activeDevices = 0;
  bool isConnected = false;
  bool isDaemonStale = false;
  bool isLoading = true;
  String? loadError;

  String selectedFilter = 'All';
  String searchQuery = '';
  List<Map<String, dynamic>> devices = [];

  @override
  void initState() {
    super.initState();
    _refreshFromApi();
    _pollTimer = Timer.periodic(
      const Duration(seconds: 5),
      (_) => _refreshFromApi(showLoading: false),
    );
  }

  Future<void> _refreshFromApi({bool showLoading = true}) async {
    if (showLoading && mounted) {
      setState(() {
        isLoading = true;
        loadError = null;
      });
    }

    try {
      final health = await _api.getHealth();
      final summary = await _api.getSummary();
      final latestDevices = await _api.getDevices();

      if (!mounted) return;

      setState(() {
        isConnected = true;
        isDaemonStale = health['daemon_stale'] == true;
        totalKnown = _asInt(summary['total_known']);
        activeDevices = _onlineCountFromSummary(summary);
        devices = latestDevices;
        isLoading = false;
        loadError = null;
      });
    } catch (error) {
      if (!mounted) return;

      setState(() {
        isConnected = false;
        isLoading = false;
        loadError = error.toString();
      });
    }
  }

  int _asInt(dynamic value) {
    if (value is int) return value;
    if (value is num) return value.toInt();
    return int.tryParse(value?.toString() ?? '') ?? 0;
  }

  int _onlineCountFromSummary(Map<String, dynamic> summary) {
    final byStatus = summary['by_status'];
    if (byStatus is List) {
      for (final item in byStatus) {
        if (item is Map && item['status']?.toString() == 'online') {
          return _asInt(item['count']);
        }
      }
    }
    return _asInt(summary['current_subnet']);
  }

  String _displayText(dynamic value, {String fallback = 'Unknown'}) {
    final text = value?.toString().trim() ?? '';
    return text.isEmpty ? fallback : text;
  }

  String get _connectionLabel {
    if (!isConnected) return 'ASSAS appliance unavailable';
    if (isDaemonStale) return 'Connected • inventory data is stale';
    return 'Connected • live inventory';
  }

  Color get _connectionColor {
    if (!isConnected) return AppColors.statusDanger;
    if (isDaemonStale) return AppColors.statusWarning;
    return AppColors.statusSafe;
  }

  Future<void> _showDeviceDetails(
    BuildContext context,
    Map<String, dynamic> device,
  ) async {
    HapticFeedback.lightImpact();

    Map<String, dynamic> detail = device;
    final mac = _displayText(device['mac'], fallback: '');

    if (mac.isNotEmpty) {
      try {
        detail = await _api.getDevice(mac);
      } catch (_) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text(
                'Could not refresh device details. Showing the latest list data.',
              ),
            ),
          );
        }
      }
    }

    if (!mounted) return;

    final hostname = _displayText(
      detail['hostname'],
      fallback: _displayText(detail['model'], fallback: 'Unknown Device'),
    );
    final ip = _displayText(detail['ip'], fallback: 'Not available');
    final detailMac = _displayText(detail['mac'], fallback: 'Not available');
    final vendor = _displayText(detail['vendor'], fallback: 'Unknown');
    final deviceType = _displayText(
      detail['device_type'],
      fallback: 'Generic / Unknown',
    );
    final model = _displayText(detail['model'], fallback: 'Not identified');
    final status = _displayText(detail['status'], fallback: 'unknown').toUpperCase();
    final lastSeen = _displayText(detail['last_seen'], fallback: 'Not available');
    final classSource = _displayText(
      detail['class_source'],
      fallback: 'Not available',
    );

    final isOnline = status == 'ONLINE';

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.white,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (ctx) {
        return SafeArea(
          child: SingleChildScrollView(
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
                      padding: const EdgeInsets.symmetric(
                        horizontal: 10,
                        vertical: 4,
                      ),
                      decoration: BoxDecoration(
                        color: (isOnline
                                ? AppColors.statusSafe
                                : Colors.grey)
                            .withOpacity(0.12),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        status,
                        style: TextStyle(
                          color: isOnline ? AppColors.statusSafe : Colors.grey,
                          fontSize: 12,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  ],
                ),
                Divider(
                  height: 28,
                  color: AppColors.mediumPurple.withOpacity(0.1),
                ),
                _buildDetailRow('Device Category', deviceType),
                _buildDetailRow('Model', model),
                _buildDetailRow('IP Address', ip),
                _buildDetailRow('MAC Address', detailMac),
                _buildDetailRow('Hardware Vendor', vendor),
                _buildDetailRow('Last Seen', lastSeen),
                _buildDetailRow('Classification Source', classSource),
                const SizedBox(height: 8),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            flex: 4,
            child: Text(
              label,
              style: TextStyle(
                color: Colors.grey.shade600,
                fontSize: 13,
              ),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            flex: 6,
            child: Text(
              value,
              textAlign: TextAlign.right,
              style: const TextStyle(
                fontWeight: FontWeight.w600,
                color: AppColors.darkPurpleBase,
                fontSize: 13,
              ),
            ),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    _api.dispose();
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF6F3F8),
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
              label: 'Dashboard',
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.devices_outlined),
              activeIcon: Icon(Icons.devices),
              label: 'Devices',
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.shield_outlined),
              activeIcon: Icon(Icons.shield),
              label: 'Threats',
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.settings_outlined),
              activeIcon: Icon(Icons.settings),
              label: 'Settings',
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDashboardPage() {
    return RefreshIndicator(
      onRefresh: _refreshFromApi,
      color: AppColors.vibrantPurple,
      child: SingleChildScrollView(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Center(
              child: Padding(
                padding: const EdgeInsets.symmetric(vertical: 8),
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
                Expanded(
                  child: Row(
                    children: [
                      Container(
                        width: 8,
                        height: 8,
                        decoration: BoxDecoration(
                          color: _connectionColor,
                          shape: BoxShape.circle,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          _connectionLabel,
                          style: const TextStyle(
                            fontSize: 12.5,
                            fontWeight: FontWeight.w600,
                            color: AppColors.darkPurpleBase,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 12),
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 10,
                    vertical: 4,
                  ),
                  decoration: BoxDecoration(
                    color: Colors.white.withOpacity(0.85),
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(
                      color: AppColors.mediumPurple.withOpacity(0.12),
                    ),
                  ),
                  child: Text(
                    '$totalKnown Known Assets',
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
                  Container(
                    width: 76,
                    height: 76,
                    decoration: BoxDecoration(
                      color: _connectionColor.withOpacity(0.1),
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      isConnected
                          ? Icons.hub_outlined
                          : Icons.cloud_off_outlined,
                      color: _connectionColor,
                      size: 36,
                    ),
                  ),
                  const SizedBox(height: 14),
                  const Text(
                    'SPRINT 0 LIVE INVENTORY',
                    style: TextStyle(
                      color: AppColors.mediumPurple,
                      fontSize: 11,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 1.1,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    isConnected
                        ? (isDaemonStale
                            ? 'The API is reachable, but the discovery data is currently stale.'
                            : 'Device inventory is being read from the ASSAS appliance.')
                        : 'The app cannot currently reach the ASSAS appliance.',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: Colors.grey.shade700,
                      fontSize: 13,
                      height: 1.4,
                    ),
                  ),
                  if (loadError != null && !isConnected) ...[
                    const SizedBox(height: 10),
                    TextButton.icon(
                      onPressed: _refreshFromApi,
                      icon: const Icon(Icons.refresh, size: 18),
                      label: const Text('Retry'),
                    ),
                  ],
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
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'LOCAL ASSET INVENTORY',
                          style: TextStyle(
                            color: AppColors.mediumPurple,
                            fontSize: 11,
                            fontWeight: FontWeight.w800,
                            letterSpacing: 1.1,
                          ),
                        ),
                        const SizedBox(height: 6),
                        Text(
                          '$activeDevices Active Devices',
                          style: const TextStyle(
                            color: AppColors.darkPurpleBase,
                            fontSize: 22,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Text(
                          'Live data from the ASSAS device inventory API',
                          style: TextStyle(
                            color: Colors.grey.shade700,
                            fontSize: 12,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 12),
                  ElevatedButton(
                    onPressed: () => setState(() => _currentIndex = 1),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppColors.vibrantPurple,
                      foregroundColor: Colors.white,
                      elevation: 0,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                    ),
                    child: const Text('View All'),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDevicesPage() {
    final query = searchQuery.trim().toLowerCase();

    final filtered = devices.where((device) {
      final status = _displayText(device['status'], fallback: '').toLowerCase();
      final matchesFilter = selectedFilter == 'All' ||
          (selectedFilter == 'Online' && status == 'online') ||
          (selectedFilter == 'Offline' && status == 'offline');

      final searchable = [
        device['hostname'],
        device['ip'],
        device['mac'],
        device['vendor'],
        device['device_type'],
        device['model'],
      ].map((value) => _displayText(value, fallback: '').toLowerCase());

      final matchesSearch =
          query.isEmpty || searchable.any((value) => value.contains(query));

      return matchesFilter && matchesSearch;
    }).toList();

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text(
                'Connected Endpoints',
                style: TextStyle(
                  fontSize: 22,
                  fontWeight: FontWeight.bold,
                  color: AppColors.darkPurpleBase,
                ),
              ),
              IconButton(
                tooltip: 'Refresh',
                onPressed: () => _refreshFromApi(),
                icon: const Icon(
                  Icons.refresh,
                  color: AppColors.vibrantPurple,
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          _buildGlassCard(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 4),
            child: TextField(
              controller: _searchController,
              onChanged: (value) => setState(() => searchQuery = value),
              decoration: const InputDecoration(
                hintText: 'Search hostname, IP, MAC, vendor...',
                prefixIcon: Icon(
                  Icons.search,
                  color: AppColors.vibrantPurple,
                ),
                border: InputBorder.none,
              ),
            ),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              _buildFilterChip('All'),
              const SizedBox(width: 8),
              _buildFilterChip('Online'),
              const SizedBox(width: 8),
              _buildFilterChip('Offline'),
            ],
          ),
          const SizedBox(height: 12),
          Expanded(
            child: _buildDeviceList(filtered),
          ),
        ],
      ),
    );
  }

  Widget _buildDeviceList(List<Map<String, dynamic>> filtered) {
    if (isLoading && devices.isEmpty) {
      return const Center(
        child: CircularProgressIndicator(color: AppColors.vibrantPurple),
      );
    }

    if (!isConnected && devices.isEmpty) {
      return Center(
        child: _buildEmptyState(
          icon: Icons.cloud_off_outlined,
          title: 'ASSAS appliance unavailable',
          subtitle: 'Check the local connection, then try again.',
        ),
      );
    }

    if (filtered.isEmpty) {
      return Center(
        child: _buildEmptyState(
          icon: Icons.search_off,
          title: 'No matching devices',
          subtitle: 'Try another search or filter.',
        ),
      );
    }

    return ListView.separated(
      itemCount: filtered.length,
      separatorBuilder: (_, __) => const SizedBox(height: 10),
      itemBuilder: (context, index) {
        final item = filtered[index];
        final status = _displayText(item['status'], fallback: 'unknown');
        final isOnline = status.toLowerCase() == 'online';
        final hostname = _displayText(
          item['hostname'],
          fallback: _displayText(item['model'], fallback: 'Unknown Device'),
        );
        final vendor = _displayText(item['vendor'], fallback: 'Unknown vendor');
        final ip = _displayText(item['ip'], fallback: 'No IP');
        final deviceType = _displayText(
          item['device_type'],
          fallback: 'Generic / Unknown',
        );

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
                    color: (isOnline ? AppColors.statusSafe : Colors.grey)
                        .withOpacity(0.15),
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
                        hostname,
                        style: const TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 15,
                          color: AppColors.darkPurpleBase,
                        ),
                      ),
                      const SizedBox(height: 3),
                      Text(
                        '$deviceType • $vendor',
                        style: TextStyle(
                          color: Colors.grey.shade600,
                          fontSize: 12.5,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        ip,
                        style: TextStyle(
                          color: Colors.grey.shade500,
                          fontSize: 11.5,
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
    );
  }

  Widget _buildEmptyState({
    required IconData icon,
    required String title,
    required String subtitle,
  }) {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 42, color: Colors.grey.shade400),
          const SizedBox(height: 10),
          Text(
            title,
            textAlign: TextAlign.center,
            style: const TextStyle(
              color: AppColors.darkPurpleBase,
              fontWeight: FontWeight.w700,
              fontSize: 15,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            subtitle,
            textAlign: TextAlign.center,
            style: TextStyle(
              color: Colors.grey.shade600,
              fontSize: 12.5,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildThreatsPage() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: _buildGlassCard(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(
                Icons.shield_outlined,
                size: 58,
                color: AppColors.vibrantPurple,
              ),
              const SizedBox(height: 14),
              const Text(
                'Threat Monitoring',
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                  color: AppColors.darkPurpleBase,
                ),
              ),
              const SizedBox(height: 6),
              Text(
                'This Sprint 0 build is currently connected to the device inventory API. Threat-detection data is not exposed to this screen yet.',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Colors.grey.shade600,
                  fontSize: 13,
                  height: 1.4,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildSettingsPage() {
    return Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Settings & Appliance',
            style: TextStyle(
              fontSize: 22,
              fontWeight: FontWeight.bold,
              color: AppColors.darkPurpleBase,
            ),
          ),
          const SizedBox(height: 20),
          _buildGlassCard(
            child: ListTile(
              contentPadding: EdgeInsets.zero,
              leading: const Icon(
                Icons.router_outlined,
                color: AppColors.vibrantPurple,
              ),
              title: const Text(
                'Assas Appliance Core',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              subtitle: Text(_connectionLabel),
              trailing: SizedBox(
                width: 145,
                child: Text(
                  _api.baseUrl,
                  textAlign: TextAlign.right,
                  overflow: TextOverflow.ellipsis,
                  maxLines: 2,
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    color: AppColors.mediumPurple,
                    fontSize: 11,
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(height: 14),
          _buildGlassCard(
            child: const ListTile(
              contentPadding: EdgeInsets.zero,
              leading: Icon(
                Icons.palette_outlined,
                color: AppColors.vibrantPurple,
              ),
              title: Text('Active Appearance'),
              subtitle: Text('Soft Lavender Clean Mode'),
              trailing: Icon(
                Icons.check_circle,
                color: AppColors.statusSafe,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFilterChip(String label) {
    final isSelected = selectedFilter == label;

    return GestureDetector(
      onTap: () {
        HapticFeedback.lightImpact();
        setState(() => selectedFilter = label);
      },
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 7),
        decoration: BoxDecoration(
          color: isSelected ? AppColors.vibrantPurple : Colors.white,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: isSelected
                ? AppColors.vibrantPurple
                : AppColors.lightCardBorder,
          ),
        ),
        child: Text(
          label,
          style: TextStyle(
            color: isSelected ? Colors.white : Colors.grey.shade700,
            fontSize: 12,
            fontWeight: FontWeight.w600,
          ),
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
