import 'dart:convert';

import 'package:http/http.dart' as http;

import 'assas_repository.dart';

/// Thin HTTP wrapper: base URL, token header, timeout, JSON decoding.
class ApiClient {
  ApiClient({required String baseUrl, http.Client? client, this.resolveBaseUrl})
      : baseUrl = _normalize(baseUrl),
        _client = client ?? http.Client();

  String baseUrl;
  final Future<String> Function()? resolveBaseUrl;
  Future<void>? _resolving;
  bool _resolved = false;

  Future<http.Response> _send(Future<http.Response> Function() send) async {
    try {
      if (!_resolved && resolveBaseUrl != null) {
        _resolving ??= (() async {
          baseUrl = _normalize(await resolveBaseUrl!());
          _resolved = true;
        })();
        try { await _resolving; } finally { _resolving = null; }
      }
      return await send().timeout(_timeout);
    } catch (_) {
      _resolved = false; // Rediscover on the next request, never replay a mutation.
      rethrow;
    }
  }
  final http.Client _client;
  String? token;

  static const Duration _timeout = Duration(seconds: 5);

  static String _normalize(String v) {
    final t = v.trim();
    return t.endsWith('/') ? t.substring(0, t.length - 1) : t;
  }

  Map<String, String> get _headers => {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        if (token != null) 'Authorization': 'Bearer $token',
      };

  Uri _uri(String path) => Uri.parse('$baseUrl$path');

  Future<http.Response> get(String path) =>
      _send(() => _client.get(_uri(path), headers: _headers));

  Future<http.Response> post(String path, [Object? body]) =>
      _send(() => _client.post(_uri(path), headers: _headers,
          body: body == null ? null : jsonEncode(body)));

  Future<http.Response> put(String path, Object body) =>
      _send(() => _client.put(_uri(path), headers: _headers, body: jsonEncode(body)));

  Future<http.Response> patch(String path, Object body) =>
      _send(() => _client.patch(_uri(path), headers: _headers, body: jsonEncode(body)));

  /// Throws [AssasApiException] for any non-2xx response.
  static void ensureOk(http.Response r, String what) {
    if (r.statusCode < 200 || r.statusCode >= 300) {
      throw AssasApiException('Request failed: $what', statusCode: r.statusCode);
    }
  }

  static Map<String, dynamic> decodeObject(http.Response r) {
    final d = jsonDecode(r.body);
    if (d is! Map) throw const AssasApiException('Unexpected response format');
    return Map<String, dynamic>.from(d);
  }

  static List<Map<String, dynamic>> decodeList(http.Response r) {
    final d = jsonDecode(r.body);
    if (d is! List) throw const AssasApiException('Unexpected response format');
    return [for (final e in d) Map<String, dynamic>.from(e as Map)];
  }

  void dispose() => _client.close();
}
