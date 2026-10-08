import 'dart:convert';

import 'package:http/http.dart' as http;

import 'assas_repository.dart';

/// Thin HTTP wrapper: base URL, token header, timeout, JSON decoding.
class ApiClient {
  ApiClient({required String baseUrl, http.Client? client})
      : baseUrl = _normalize(baseUrl),
        _client = client ?? http.Client();

  final String baseUrl;
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
      _client.get(_uri(path), headers: _headers).timeout(_timeout);

  Future<http.Response> post(String path, [Object? body]) => _client
      .post(_uri(path), headers: _headers, body: body == null ? null : jsonEncode(body))
      .timeout(_timeout);

  Future<http.Response> put(String path, Object body) => _client
      .put(_uri(path), headers: _headers, body: jsonEncode(body))
      .timeout(_timeout);

  Future<http.Response> patch(String path, Object body) => _client
      .patch(_uri(path), headers: _headers, body: jsonEncode(body))
      .timeout(_timeout);

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
