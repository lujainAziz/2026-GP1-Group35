import 'security_alert.dart';

/// How an alert list is ordered.
enum AlertSort {
  /// Most recent event first — the default order.
  newest,

  /// Most severe first (Critical, High, Medium, Low); within the same severity,
  /// newest first — a severity sort never loses the time ordering for ties.
  severity,
}

extension AlertSortLabel on AlertSort {
  String get label => switch (this) {
        AlertSort.newest => 'Newest first',
        AlertSort.severity => 'Most severe first',
      };
}

extension AlertSeverityRank on Severity {
  /// Higher = more severe. low=0 … critical=3 (matches the enum order).
  int get rank => index;
}

/// A new list ordered by [sort]. [newest] orders by event time descending;
/// [severity] orders most-severe first and, for equal severities, newest first.
List<SecurityAlert> sortedAlerts(Iterable<SecurityAlert> alerts, AlertSort sort) {
  final list = List<SecurityAlert>.from(alerts);
  switch (sort) {
    case AlertSort.newest:
      list.sort((a, b) => b.time.compareTo(a.time));
    case AlertSort.severity:
      list.sort((a, b) {
        final s = b.severity.rank.compareTo(a.severity.rank);
        return s != 0 ? s : b.time.compareTo(a.time);
      });
  }
  return list;
}

/// Keeps only alerts whose severity is in [shown]. An empty set — or a set that
/// already contains every severity — shows everything (a filter that hides
/// nothing is the same as "all"), so the caller never has to special-case it.
Iterable<SecurityAlert> alertsWithSeverity(
  Iterable<SecurityAlert> alerts,
  Set<Severity> shown,
) =>
    (shown.isEmpty || shown.length == Severity.values.length)
        ? alerts
        : alerts.where((a) => shown.contains(a.severity));
