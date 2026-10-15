// Native DNS-SD implementation (android/ios/macos/windows) using the `nsd`
// plugin. Imported by appliance_locator.dart only when dart:io is available, so
// its nsd/dart:io imports never reach a web build.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:nsd/nsd.dart' as nsd;

import 'appliance_locator_logic.dart';

/// The exact service type the Pi advertises via Avahi (appliance/avahi/).
const String kAssasServiceType = '_assas._tcp';

/// Browse for the ASSAS API over DNS-SD and return the first usable IPv4 base
/// URL, or null if none is found within [timeout]. Discovery is always stopped,
/// including on timeout/error, so no background browse is left running.
Future<String?> discoverAssasBaseUrl(Duration timeout, {Future<bool> Function(String)? accepts}) async {
  nsd.Discovery? discovery;
  try {
    // ipLookupType.v4: resolve IPv4 addresses (the API listens on IPv4 only;
    // the advertised global IPv6 would refuse the connection).
    discovery = await nsd.startDiscovery(
      kAssasServiceType,
      ipLookupType: nsd.IpLookupType.v4,
    );

    final completer = Completer<String?>();
    final checking = <String>{};
    void evaluate() {
      if (completer.isCompleted) return;
      for (final service in discovery!.services) {
        final url = _serviceToBaseUrl(service);
        if (url != null && checking.add(url)) {
          Future<void>(() async {
            try {
              if ((accepts == null || await accepts(url)) && !completer.isCompleted) {
                completer.complete(url);
              }
            } catch (_) { /* Another discovered device may match. */ }
          });
        }
      }
    }

    discovery.addListener(evaluate);
    evaluate(); // services may already be resolved by the time we attach.
    return await completer.future.timeout(timeout, onTimeout: () => null);
  } finally {
    if (discovery != null) {
      // Best-effort cleanup; never let a stop error mask the result.
      try {
        await nsd.stopDiscovery(discovery);
      } catch (_) {}
    }
  }
}

String? _serviceToBaseUrl(nsd.Service service) {
  String? ipv4;
  for (final addr in service.addresses ?? const <InternetAddress>[]) {
    if (addr.type == InternetAddressType.IPv4) {
      ipv4 = addr.address;
      break;
    }
  }

  String? path;
  final rawPath = service.txt?['path'];
  if (rawPath != null) {
    try {
      path = utf8.decode(rawPath);
    } catch (_) {
      path = null; // ignore undecodable TXT rather than fail discovery
    }
  }

  return buildAssasBaseUrl(ipv4: ipv4, port: service.port, path: path);
}
