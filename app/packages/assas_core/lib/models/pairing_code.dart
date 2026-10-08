/// Rotating pairing code shown on the appliance's 7-inch screen.
class PairingCode {
  final String code;
  final DateTime expiresAt;

  const PairingCode({required this.code, required this.expiresAt});

  /// Text stored inside the QR code. The display creates it, the phone reads it.
  static const String qrPrefix = 'ASSAS:';
  String get qrPayload => '$qrPrefix$code';

  /// Turns whatever the phone camera read into a plain code.
  static String parseQr(String raw) {
    final t = raw.trim();
    if (t.toUpperCase().startsWith(qrPrefix)) {
      return t.substring(qrPrefix.length).trim().toUpperCase();
    }
    return t.toUpperCase();
  }

  /// "ABC123" -> "ABC 123" (easier to read on the screen).
  String get pretty =>
      code.length == 6 ? '${code.substring(0, 3)} ${code.substring(3)}' : code;

  int secondsLeft(DateTime now) {
    final s = expiresAt.difference(now).inSeconds;
    return s < 0 ? 0 : s;
  }

  // PROPOSED: GET /pairing/code  ->  {"code": "ABC123", "expires_at": "2026-10-08T21:15:00"}
  factory PairingCode.fromApi(Map<String, dynamic> j) => PairingCode(
        code: (j['code'] ?? '').toString(),
        expiresAt: DateTime.tryParse(j['expires_at']?.toString() ?? '') ??
            DateTime.now().add(const Duration(seconds: 60)),
      );
}
