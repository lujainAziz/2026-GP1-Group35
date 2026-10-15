class LiveActivity {
  const LiveActivity({required this.samples, required this.protocols, required this.stale});
  final List<double> samples;
  final List<String> protocols;
  final bool stale;
  factory LiveActivity.fromApi(Map<String, dynamic> data) => LiveActivity(
    samples: [for (final sample in data['samples'] as List? ?? [])
      (sample['packets_per_second'] as num).toDouble()],
    protocols: List<String>.from(data['protocols'] as List? ?? []),
    stale: data['stale'] != false,
  );
}
