import 'package:assas_core/assas_core.dart';

// #####################################################################
//  DATA SOURCE SWITCH  (the ONLY place to change demo <-> real backend)
//
//  To switch to the real backend:
//    1) Comment the DEMO block.
//    2) Uncomment the REAL BACKEND block.
//  Both repositories are always compiled, so switching cannot break the build.
// #####################################################################

/// Explicit base-URL override, supplied at build time with:
///   flutter run --dart-define=ASSAS_API_BASE_URL=http://192.168.1.20:8000
/// EMPTY when not supplied -- do NOT confuse an unset override with the
/// fallback. A non-empty value always wins over DNS-SD discovery.
const String kApiBaseUrlOverride = String.fromEnvironment('ASSAS_API_BASE_URL');

/// Last-resort fallback used when discovery is unavailable, denied, times out,
/// or finds nothing. The mDNS host name (never a fixed IP), per API_CONTRACT.md.
const String kApiBaseUrlFallback = 'http://assas-pi.local:8000';

/// Set once from main() before runApp. Every screen reads this global.
late final AssasRepository repository;

// ======================= DEMO (active) ===============================
// const bool kShowPairingSkip = true; // "Skip" button on the pairing screen

// /// Builds the active repository. Demo data needs no backend, so it ignores the
// /// resolver and never triggers a network/DNS-SD browse.
// Future<AssasRepository> createRepository(
  // Future<String> Function() resolveBaseUrl,
// ) async {
 //  return DemoRepository();
// }
// =====================================================================

// ======================= REAL BACKEND ================================
const bool kShowPairingSkip = false;

// /// The real backend resolves its base URL first (ASSAS_API_BASE_URL override
// /// -> DNS-SD _assas._tcp -> assas-pi.local fallback), then builds the client.
Future<AssasRepository> createRepository(
  Future<String> Function() resolveBaseUrl,
 ) async {
  return ApiRepository(ApiClient(baseUrl: await resolveBaseUrl()));
 }
// =====================================================================
