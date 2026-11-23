import 'dart:math';

import '../models/appliance_settings.dart';
import '../models/live_activity.dart';
import '../models/device.dart';
import '../models/network_status.dart';
import '../models/pairing_code.dart';
import '../models/paired_phone.dart';
import '../models/security_alert.dart';
import 'assas_repository.dart';

// =====================================================================
//  DEMO DATA ONLY
//  Same values as the agreed interface design (Canva).
//  Nothing here talks to the network.
// =====================================================================
class DemoRepository implements AssasRepository {
  @override
  Future<LiveActivity?> getActivity() async => null;
  DemoRepository() {
    final now = DateTime.now();
    final today = DateTime(now.year, now.month, now.day);
    final yesterday = today.subtract(const Duration(days: 1));

    _devices = [
      Device(
        mac: '7c:9e:bd:00:04:0f', ip: '192.168.1.23', hostname: 'Living room TV',
        vendor: 'Samsung', deviceType: 'Smart TV',
        presence: Presence.online, trusted: true, lastSeen: now,
      ),
      Device(
        mac: '7c:6b:cb:00:01:5d', ip: '192.168.1.41', hostname: 'Front door camera',
        vendor: 'Hikvision', deviceType: 'Camera',
        presence: Presence.online, trusted: true, lastSeen: now,
      ),
      Device(
        mac: '5f:4a:cb:5a:66:0f', ip: '192.168.1.57', hostname: null,
        vendor: 'Espressif', deviceType: null,
        presence: Presence.online, trusted: false, lastSeen: now,
      ),
      Device(
        mac: '5b:8c:da:4d:34:5a', ip: '192.168.1.12', hostname: 'Work laptop',
        vendor: 'Dell', deviceType: 'Laptop',
        presence: Presence.online, trusted: true, lastSeen: now,
      ),
      Device(
        mac: '50:c7:bf:00:03:33', ip: '192.168.1.66', hostname: 'Smart plug',
        vendor: 'TP-Link', deviceType: 'Smart plug',
        presence: Presence.online, trusted: true, lastSeen: now,
      ),
      Device(
        mac: 'a4:83:e7:00:05:b8', ip: '192.168.1.30', hostname: "Nona's iPhone",
        vendor: 'Apple', deviceType: 'Mobile',
        presence: Presence.offline, trusted: true,
        lastSeen: now.subtract(const Duration(hours: 3)),
      ),
      Device(
        mac: '3c:2a:f4:00:02:e1', ip: '192.168.1.50', hostname: 'Office printer',
        vendor: 'HP', deviceType: 'Printer',
        presence: Presence.offline, trusted: true,
        lastSeen: now.subtract(const Duration(days: 1)),
      ),
    ];

    _alerts = [
      SecurityAlert(
        id: 'demo-1', kind: AlertKind.anomaly, title: 'Unusual activity',
        deviceMac: '7c:6b:cb:00:01:5d', deviceName: 'Front door camera',
        time: today.add(const Duration(hours: 22, minutes: 42)),
        severity: Severity.high, state: AlertState.newAlert, read: false,
        explanation:
            'Your front door camera sent much more data than it normally does in a single connection, and the connection lasted longer than usual.',
      ),
      SecurityAlert(
        id: 'demo-2', kind: AlertKind.threat, title: 'Port scan detected',
        deviceMac: '5b:8c:da:4d:34:5a', deviceName: 'Work laptop',
        time: today.add(const Duration(hours: 21, minutes: 15)),
        severity: Severity.medium, state: AlertState.newAlert, read: true,
        explanation:
            'Another device tried to connect to many different ports on your work laptop in a short time. This is often how attackers look for services they can reach.',
        sourceIp: '192.168.1.57', destinationIp: '192.168.1.12',
      ),
      SecurityAlert(
        id: 'demo-3', kind: AlertKind.threat, title: 'Malware server contacted',
        deviceMac: '50:c7:bf:00:03:33', deviceName: 'Smart plug',
        time: yesterday.add(const Duration(hours: 18, minutes: 5)),
        severity: Severity.high, state: AlertState.resolved, read: true,
        explanation:
            'Your smart plug connected to an internet address that is known to be used by malware.',
        sourceIp: '192.168.1.66', destinationIp: '203.0.113.4',
      ),
      SecurityAlert(
        id: 'demo-4', kind: AlertKind.anomaly, title: 'Unusual activity',
        deviceMac: '7c:9e:bd:00:04:0f', deviceName: 'Living room TV',
        time: yesterday.add(const Duration(hours: 16, minutes: 30)),
        severity: Severity.low, state: AlertState.resolved, read: true,
        explanation:
            'Your living room TV connected at a time when it is usually not active.',
      ),
    ];
  }

  late List<Device> _devices;
  late List<SecurityAlert> _alerts;
  ApplianceSettings _settings = const ApplianceSettings(activeProbes: true);
  PairingCode? _code;
  final _random = Random();

  Future<void> _delay() => Future.delayed(const Duration(milliseconds: 250));

  @override
  bool get isDemo => true;

  @override
  String get applianceAddress => 'Demo data';

  @override
  void setAuthToken(String? token) {}

  @override
  Future<ConnectionStatus> checkHealth() async => ConnectionStatus.live;

  @override
  Future<RiskInfo?> getRiskLevel() async {
    await _delay();
    return const RiskInfo('High');
  }

  @override
  Future<List<Device>> getDevices() async {
    await _delay();
    return List.unmodifiable(_devices);
  }

  @override
  Future<Device> getDevice(String mac) async {
    await _delay();
    return _devices.firstWhere(
      (d) => d.mac == mac,
      orElse: () => throw AssasApiException('Device not found', statusCode: 404),
    );
  }

  @override
  Future<void> setTrusted(String mac, bool trusted) async {
    await _delay();
    _devices = [
      for (final d in _devices) d.mac == mac ? d.copyWith(trusted: trusted) : d,
    ];
  }

  @override
  Future<void> renameDevice(String mac, String? name) async {
    await _delay();
    final clean = name?.trim() ?? '';
    _devices = [
      for (final d in _devices) d.mac == mac ? d.copyWith(userName: clean) : d,
    ];
  }

  @override
  Future<List<SecurityAlert>?> getAlerts({int? limit}) async {
    await _delay();
    final list = List<SecurityAlert>.from(_alerts)
      ..sort((a, b) => b.time.compareTo(a.time));
    return limit != null && list.length > limit ? list.sublist(0, limit) : list;
  }

  @override
  Future<void> setAlertState(String id, AlertState state) async {
    await _delay();
    _alerts = [
      for (final a in _alerts)
        a.id == id
            // Resolved alerts count as read.
            ? a.copyWith(state: state, read: state == AlertState.resolved ? true : null)
            : a,
    ];
  }

  @override
  Future<SecurityAlert?> markAlertRead(String id) async {
    await _delay();
    SecurityAlert? out;
    _alerts = [
      for (final a in _alerts)
        if (a.id == id) out = a.copyWith(read: true) else a,
    ];
    return out;
  }

  // Derived from getAlerts() so a subclass serving its own alert list (tests)
  // gets a matching Unread tab and badge.
  @override
  Future<List<SecurityAlert>?> getUnreadAlerts({int? limit}) async {
    final list = (await getAlerts())?.where((a) => a.isUnread && a.isUnresolved).toList();
    return list != null && limit != null && list.length > limit ? list.sublist(0, limit) : list;
  }

  @override
  Future<int?> getUnreadAlertCount() async =>
      (await getAlerts())?.where((a) => a.isUnread && a.isUnresolved).length;

  @override
  Future<int?> getOpenAlertCount() async {
    await _delay();
    return _alerts.where((a) => a.isUnresolved).length; // New
  }

  @override
  Future<List<SecurityAlert>?> getDeviceAlerts(String mac, {int? limit}) async {
    await _delay();
    final list = _alerts.where((a) => a.deviceMac == mac).toList()
      ..sort((a, b) => b.time.compareTo(a.time));
    return limit != null && list.length > limit ? list.sublist(0, limit) : list;
  }

  @override
  Future<SecurityAlert?> getAlertById(String id) async {
    await _delay();
    for (final a in _alerts) {
      if (a.id == id) return a;
    }
    return null;
  }

  /// Demo: any 6-character code (letters/numbers) is accepted.
  @override
  Future<String> pair(String code, {String? deviceName}) async {
    await Future.delayed(const Duration(milliseconds: 600));
    final c = code.trim().toUpperCase();
    if (!RegExp(r'^[A-Z0-9]{6}$').hasMatch(c)) {
      throw const PairingException(PairingException.wrongCode);
    }
    final name = deviceName?.trim() ?? '';
    _phones.add(PairedPhone(
      id: _phones.length + 1,
      deviceName: name.isEmpty ? 'Unnamed phone' : name,
      createdAt: DateTime.now(),
    ));
    return 'demo-token';
  }

  /// Demo: same rule as [pair]; a good code buys a ticket.
  @override
  Future<String?> verifyPairingCode(String code) async {
    await Future.delayed(const Duration(milliseconds: 600));
    final c = code.trim().toUpperCase();
    if (!RegExp(r'^[A-Z0-9]{6}$').hasMatch(c)) {
      throw const PairingException(PairingException.wrongCode);
    }
    return 'demo-ticket';
  }

  @override
  Future<String> pairWithTicket(String ticket, {String? deviceName}) async {
    await Future.delayed(const Duration(milliseconds: 600));
    final name = deviceName?.trim() ?? '';
    _phones.add(PairedPhone(
      id: _phones.length + 1,
      deviceName: name.isEmpty ? 'Unnamed phone' : name,
      createdAt: DateTime.now(),
    ));
    return 'demo-token';
  }

  /// Demo phones: one paired before, and a "new" one that appears about
  /// 20 seconds after the display starts, so the new-phone banner can be seen.
  final List<PairedPhone> _phones = [
    PairedPhone(id: 1, deviceName: "Owner's phone", createdAt: DateTime(2026, 10, 1)),
  ];
  final DateTime _demoStart = DateTime.now();

  @override
  Future<List<PairedPhone>?> getPairedPhones() async {
    await _delay();
    if (_phones.length == 1 && DateTime.now().difference(_demoStart).inSeconds > 20) {
      _phones.add(PairedPhone(id: 2, deviceName: "Maraheb's iPhone", createdAt: DateTime.now()));
    }
    return List.unmodifiable(_phones);
  }

  @override
  Future<void> unpair() async => _delay();

  /// Demo: new random code every 60 seconds.
  @override
  Future<PairingCode> getCurrentPairingCode() async {
    final now = DateTime.now();
    if (_code == null || !_code!.expiresAt.isAfter(now)) {
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
      final code = List.generate(6, (_) => chars[_random.nextInt(chars.length)]).join();
      _code = PairingCode(code: code, expiresAt: now.add(const Duration(seconds: 60)));
    }
    return _code!;
  }

  @override
  Future<ApplianceSettings> getSettings() async {
    await _delay();
    return _settings;
  }

  @override
  Future<void> updateSettings(ApplianceSettings settings) async {
    await _delay();
    _settings = settings;
  }
}
