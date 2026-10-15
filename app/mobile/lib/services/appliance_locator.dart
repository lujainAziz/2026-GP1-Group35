import 'package:assas_core/assas_core.dart';
import 'session_store.dart';
import 'package:flutter/foundation.dart' show kIsWeb;

import '../config/data_source.dart' show kApiBaseUrlOverride, kApiBaseUrlFallback;
import 'appliance_locator_logic.dart';
// nsd supports android/ios/macos/windows only and pulls in dart:io, which does
// not compile on web. The conditional import gives web a no-op stub so the app
// still builds; native platforms get the real DNS-SD implementation.
import 'discovery_none.dart' if (dart.library.io) 'discovery_nsd.dart'
    as discovery;

/// Resolve the ASSAS API base URL in this order:
///   1. explicit ASSAS_API_BASE_URL override, if non-empty;
///   2. on supported native platforms, a bounded DNS-SD browse for
///      `_assas._tcp` resolved to IPv4;
///   3. the `assas-pi.local` fallback (also used for web and on any
///      discovery failure, timeout, permission denial, or empty result).
///
/// Never throws: any discovery error degrades to the fallback so app startup
/// cannot be blocked by mDNS problems.
Future<String> resolveApiBaseUrl({
  Duration timeout = const Duration(seconds: 4),
}) async {
  final expected = await SessionStore.getApplianceId();
  Future<bool> accepts(String url) async => expected == null ||
      await ApiRepository.identityAt(url) == expected;
  final staticUrl = staticBaseUrl(
    override: kApiBaseUrlOverride,
    isWeb: kIsWeb,
    fallback: kApiBaseUrlFallback,
  );
  if (staticUrl != null) {
    if (await accepts(staticUrl)) return staticUrl;
    throw const AssasApiException('Paired appliance not found');
  }

  try {
    final discovered = await discovery.discoverAssasBaseUrl(timeout, accepts: accepts);
    if (discovered != null && discovered.isNotEmpty) return discovered;
  } catch (_) {
    // Try the known hostname below, but never send a token to a different ID.
  }
  if (await accepts(kApiBaseUrlFallback)) return kApiBaseUrlFallback;
  throw const AssasApiException('Paired appliance not found');
}
