/// A phone paired with this Assas device (GET /sessions, display only).
class PairedPhone {
  const PairedPhone({required this.id, required this.deviceName, this.createdAt});

  /// Increasing id: a higher id means a newer pairing.
  final int id;
  final String deviceName;
  final DateTime? createdAt;

  factory PairedPhone.fromApi(Map<String, dynamic> j) {
    final name = j['device_name']?.toString().trim();
    return PairedPhone(
      id: int.tryParse(j['id']?.toString() ?? '') ?? 0,
      deviceName: (name == null || name.isEmpty) ? 'Unnamed phone' : name,
      createdAt: DateTime.tryParse(j['created_at']?.toString() ?? ''),
    );
  }
}
