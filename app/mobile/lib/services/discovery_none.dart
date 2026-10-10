// Fallback implementation for platforms without DNS-SD support (e.g. Flutter
// Web). Imported by appliance_locator.dart when dart:io is unavailable. No nsd
// or dart:io imports, so it always compiles; the caller uses the fallback URL.

/// No DNS-SD on this platform: always returns null so the caller falls back.
Future<String?> discoverAssasBaseUrl(Duration timeout) async => null;
