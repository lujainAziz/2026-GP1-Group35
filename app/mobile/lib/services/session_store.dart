import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// One encrypted record keeps the token and appliance identity together.
class SessionStore {
  SessionStore._();
  static const _storage = FlutterSecureStorage();
  static const _key = 'assas_session_v2';
  // Only chain while an operation is in flight, so a finished future from
  // another zone (e.g. a widget test's fake clock) is never waited on.
  static Future<void>? _pending;

  static Future<T> _serial<T>(Future<T> Function() action) {
    final previous = _pending;
    final next = previous == null ? action() : previous.then((_) => action());
    late final Future<void> done;
    done = next.then<void>((_) {}, onError: (Object _, StackTrace __) {}).whenComplete(() {
      if (identical(_pending, done)) _pending = null;
    });
    _pending = done;
    return next;
  }

  static Future<void> _removeLegacy(SharedPreferences prefs) async {
    await prefs.remove('assas_session_token');
    await prefs.remove('assas_appliance_id');
  }

  static Future<Map<String, dynamic>?> _read() async {
    final prefs = await SharedPreferences.getInstance();
    var raw = await _storage.read(key: _key);
    final legacy = prefs.getString('assas_session_token');
    if (raw == null && legacy != null) {
      raw = jsonEncode({'token': legacy, 'appliance_id': prefs.getString('assas_appliance_id')});
      await _storage.write(key: _key, value: raw);
      if (await _storage.read(key: _key) != raw) {
        throw StateError('Could not migrate the pairing session');
      }
    }
    if (raw != null) await _removeLegacy(prefs);
    return raw == null ? null : Map<String, dynamic>.from(jsonDecode(raw) as Map);
  }

  // An unreadable store (e.g. a reset Android keystore) must not crash startup:
  // treat the phone as unpaired. A failed migration keeps the legacy values.
  static Future<Map<String, dynamic>?> _readOrNull() async {
    try {
      return await _read();
    } catch (_) {
      return null;
    }
  }

  static Future<String?> getToken() => _serial(() async => (await _readOrNull())?['token'] as String?);
  static Future<String?> getApplianceId() => _serial(() async => (await _readOrNull())?['appliance_id'] as String?);

  static Future<void> saveToken(String token, {String? applianceId}) => _serial(() async {
    await _storage.write(key: _key, value: jsonEncode({'token': token, 'appliance_id': applianceId}));
    await _removeLegacy(await SharedPreferences.getInstance());
  });

  static Future<void> clear() => _serial(() async {
    await _removeLegacy(await SharedPreferences.getInstance());
    await _storage.delete(key: _key);
  });
}
