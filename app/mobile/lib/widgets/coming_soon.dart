import 'package:assas_core/assas_core.dart';
import 'package:assas_design/release_status.dart';
import '../state/app_state.dart';
export 'package:assas_design/release_status.dart' show SoonTag;

class Released {
  Released._();
  static bool get alerts => FeatureRelease.alerts;
  static bool get risk => FeatureRelease.risk;
  static bool get baseline => FeatureRelease.baseline;
  static bool get alertManagement => FeatureRelease.alertManagement;
  static bool get alertsHome => FeatureRelease.alertsHome;
  static bool get alertSeverityBadges => FeatureRelease.alertSeverityBadges;
  static bool get alertExplanations => FeatureRelease.alertExplanations;
  static List<SecurityAlert>? alertsOf(AppState s) => alerts ? s.alerts : null;
}
