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
