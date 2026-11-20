/// Small time helpers (no extra packages).
class TimeFormat {
  TimeFormat._();

  static const _months = [
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
  ];

  /// 22:42 -> "10:42 PM"
  static String clock(DateTime t) {
    final h = t.hour % 12 == 0 ? 12 : t.hour % 12;
    final m = t.minute.toString().padLeft(2, '0');
    return '$h:$m ${t.hour < 12 ? 'AM' : 'PM'}';
  }

  /// Alert list: today -> "10:42 PM", yesterday -> "Yesterday", older -> "3 Oct".
  static String alertTime(DateTime t, {DateTime? now}) {
    final n = now ?? DateTime.now();
    final today = DateTime(n.year, n.month, n.day);
    final day = DateTime(t.year, t.month, t.day);
    final diff = today.difference(day).inDays;
    if (diff == 0) return clock(t);
    if (diff == 1) return 'Yesterday';
    return '${t.day} ${_months[t.month - 1]}';
  }

  /// Alert details subtitle: "today at 10:42 PM" / "yesterday at 9:15 PM" / "on 3 Oct at 9:15 PM".
  static String alertTimePhrase(DateTime t, {DateTime? now}) {
    final n = now ?? DateTime.now();
    final today = DateTime(n.year, n.month, n.day);
    final day = DateTime(t.year, t.month, t.day);
    final diff = today.difference(day).inDays;
    if (diff == 0) return 'today at ${clock(t)}';
    if (diff == 1) return 'yesterday at ${clock(t)}';
    return 'on ${t.day} ${_months[t.month - 1]} at ${clock(t)}';
  }

  /// Alert detection line: "Today, 10:42 PM" / "Yesterday, 9:15 PM" / "3 Oct, 9:15 PM".
  static String alertDetected(DateTime t, {DateTime? now}) {
    final n = now ?? DateTime.now();
    final today = DateTime(n.year, n.month, n.day);
    final day = DateTime(t.year, t.month, t.day);
    final diff = today.difference(day).inDays;
    if (diff == 0) return 'Today, ${clock(t)}';
    if (diff == 1) return 'Yesterday, ${clock(t)}';
    return '${t.day} ${_months[t.month - 1]}, ${clock(t)}';
  }

  /// Repeated alert: "Detected 3 times · first 9:27 PM, last 9:40 PM". On one
  /// day the times stand alone (the device line above already shows the day);
  /// across days both show their day in the [alertDetected] style
  /// ("Yesterday, 11:50 PM", "Today, 12:05 AM", "18 Nov, 9:27 PM").
  static String detectionSummary(int count, DateTime first, DateTime last, {DateTime? now}) {
    final sameDay = first.year == last.year && first.month == last.month && first.day == last.day;
    String at(DateTime t) => sameDay ? clock(t) : alertDetected(t, now: now);
    return 'Detected $count times · first ${at(first)}, last ${at(last)}';
  }

  /// Device last seen: "Just now", "5 min ago", "3 h ago", "3 Oct".
  static String lastSeen(DateTime? t, {DateTime? now}) {
    if (t == null) return 'Unknown';
    final n = now ?? DateTime.now();
    final d = n.difference(t);
    if (d.inSeconds < 60) return 'Just now';
    if (d.inMinutes < 60) return '${d.inMinutes} min ago';
    if (d.inHours < 24) return '${d.inHours} h ago';
    return '${t.day} ${_months[t.month - 1]}';
  }
}
