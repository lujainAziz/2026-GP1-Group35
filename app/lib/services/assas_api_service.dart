import 'dart:convert';

import 'package:http/http.dart' as http;

class AssasApiService {
  AssasApiService({
    String? baseUrl,
    http.Client? client,
  })  : baseUrl = _normalizeBaseUrl(
          baseUrl ??
              const String.fromEnvironment(
                'ASSAS_API_BASE_URL',
                defaultValue: 'http://assas-pi.local:8000',
              ),
        ),
        _client = client ?? http.Client();

  final String baseUrl;
  final http.Client _client;

  static String _normalizeBaseUrl(String value) {
    final trimmed = value.trim();
    if (trimmed.endsWith('/')) {
      return trimmed.substring(0, trimmed.length - 1);
    }
    return trimmed;
  }

  Future<Map<String, dynamic>> getHealth() async {
    final response = await _get('/healthz');
    return _decodeObject(response.body);
  }

  Future<Map<String, dynamic>> getSummary() async {
    final response = await _get('/summary');
    return _decodeObject(response.body);
  }

  Future<List<Map<String, dynamic>>> getDevices() async {
    final response = await _get('/devices?limit=500');
    final decoded = jsonDecode(response.body);

    if (decoded is! List) {
      throw const AssasApiException('Unexpected /devices response format.');
    }

    return decoded.map<Map<String, dynamic>>((item) {
      if (item is! Map) {
        throw const AssasApiException('Unexpected device item format.');
      }
      return Map<String, dynamic>.from(item);
    }).toList();
  }

  Future<Map<String, dynamic>> getDevice(String mac) async {
    final encodedMac = Uri.encodeComponent(mac);
    final response = await _get('/devices/$encodedMac');
    return _decodeObject(response.body);
  }

  Future<http.Response> _get(String path) async {
    final response = await _client
        .get(Uri.parse('$baseUrl$path'))
        .timeout(const Duration(seconds: 5));

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw AssasApiException(
        'Request failed for $path.',
        statusCode: response.statusCode,
        responseBody: response.body,
      );
    }

    return response;
  }

  Map<String, dynamic> _decodeObject(String body) {
    final decoded = jsonDecode(body);
    if (decoded is! Map) {
      throw const AssasApiException('Unexpected API response format.');
    }
    return Map<String, dynamic>.from(decoded);
  }

  void dispose() {
    _client.close();
  }
}

class AssasApiException implements Exception {
  const AssasApiException(
    this.message, {
    this.statusCode,
    this.responseBody,
  });

  final String message;
  final int? statusCode;
  final String? responseBody;

  @override
  String toString() {
    if (statusCode == null) {
      return 'AssasApiException: $message';
    }
    return 'AssasApiException ($statusCode): $message';
  }
}
