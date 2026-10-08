import 'package:assas_core/assas_core.dart';

// #####################################################################
//  DATA SOURCE SWITCH  (the ONLY place to change demo <-> real backend)
//
//  To switch to the real backend:
//    1) Comment the DEMO block.
//    2) Uncomment the REAL BACKEND block.
//  Both repositories are always compiled, so switching cannot break the build.
// #####################################################################

/// Pi address. Default uses the mDNS name from API_CONTRACT.md (never a hardcoded IP).
/// Override when running:  flutter run --dart-define=ASSAS_API_BASE_URL=http://192.168.1.20:8000
const String kApiBaseUrl = String.fromEnvironment(
  'ASSAS_API_BASE_URL',
  defaultValue: 'http://assas-pi.local:8000',
);

// ======================= DEMO (active) ===============================
const bool kShowPairingSkip = true; // "Skip" button on the pairing screen
final AssasRepository repository = DemoRepository();
// =====================================================================

// ======================= REAL BACKEND ================================
// const bool kShowPairingSkip = false;
// final AssasRepository repository = ApiRepository(ApiClient(baseUrl: kApiBaseUrl));
// =====================================================================
