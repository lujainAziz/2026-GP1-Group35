// Pure, platform-free logic for resolving the ASSAS API base URL. Kept free of
// `nsd`, `dart:io`, and Flutter imports so it is deterministically unit-testable
// and safe to import anywhere (including web). The native DNS-SD plumbing lives
// in discovery_nsd.dart; this file only decides URLs from already-extracted
// values.

/// Static precedence that needs no platform calls:
///   * a non-empty [override] (ASSAS_API_BASE_URL) always wins;
///   * on web ([isWeb]) there is no DNS-SD, so use [fallback];
///   * otherwise return null -> the caller should attempt DNS-SD discovery and
///     fall back on failure.
String? staticBaseUrl({
  required String override,
  required bool isWeb,
  required String fallback,
}) {
  if (override.isNotEmpty) return override;
  if (isWeb) return fallback;
  return null;
}

/// Build `http://<ipv4>:<port>` from a resolved DNS-SD service.
///
/// Returns null unless a usable IPv4 address and a positive port are present,
/// so the caller can fall back. The ASSAS advertisement's TXT is `path=/`; a
/// root path must NOT produce a trailing/double slash, so "/" (and empty/null)
/// yield just the origin. Any non-root path is appended with exactly one
/// leading slash.
String? buildAssasBaseUrl({String? ipv4, int? port, String? path}) {
  if (ipv4 == null || ipv4.isEmpty) return null;
  if (port == null || port <= 0) return null;
  final base = 'http://$ipv4:$port';
  if (path == null || path.isEmpty || path == '/') return base;
  final normalized = path.startsWith('/') ? path : '/$path';
  return '$base$normalized';
}
