import 'package:assas_core/assas_core.dart';

// #####################################################################
//  DATA SOURCE SWITCH  (the ONLY place to change demo <-> real backend)
//
//  To switch to the real backend:
//    1) Comment the DEMO block.
//    2) Uncomment the REAL BACKEND block.
// #####################################################################

// ======================= DEMO (active) ===============================
// final AssasRepository repository = DemoRepository();
// =====================================================================

// ======================= REAL BACKEND ================================
// The display runs ON the Pi, so it talks to the API locally.
// GET /pairing/code must only answer requests from 127.0.0.1.
//
final AssasRepository repository =
    const bool.fromEnvironment('ASSAS_DEMO')
        ? DemoRepository()
        : ApiRepository(ApiClient(baseUrl: 'http://127.0.0.1:8000'));
// =====================================================================
