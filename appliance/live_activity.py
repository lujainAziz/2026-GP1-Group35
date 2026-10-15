"""Bounded capture counters for the live dashboard; no addresses or payloads."""
import json
import time
from scapy.all import ARP, DHCP, DNS, Ether, UDP, TCP


class LiveActivity:
    def __init__(self):
        self.started = time.time()
        self.buckets = {}
        self.protocol_seen = {}

    def add(self, packet):
        now = time.time()
        key = int(now // 5)
        bucket = self.buckets.setdefault(key, [0, set()])
        bucket[0] += 1
        tags = set()
        if ARP in packet:
            tags.add('ARP')
        if DHCP in packet:
            tags.add('DHCP')
        if DNS in packet:
            udp = packet.getlayer(UDP)
            ports = {int(udp.sport), int(udp.dport)} if udp else set()
            tags.add('MDNS' if 5353 in ports else 'DNS')
        if Ether in packet and int(packet[Ether].type) == 0x88cc:
            tags.add('LLDP')
        # These labels describe traffic on the corresponding service ports,
        # not a verified hardware identity or an application-content claim.
        if UDP in packet:
            ports = {int(packet[UDP].sport), int(packet[UDP].dport)}
            for port, name in ((1900, 'SSDP'), (137, 'NBNS'), (5355, 'LLMNR')):
                if port in ports:
                    tags.add(name)
        if TCP in packet:
            tags.add('TCP')
        elif UDP in packet:
            tags.add('UDP')
        for name in tags:
            self.protocol_seen[name] = now
        self.buckets = {k: v for k, v in self.buckets.items() if k >= key - 24}

    def persist(self, conn):
        now = time.time()
        end = int(now // 5)
        start = max(int(self.started // 5) + 1, end - 12)
        samples = [{'time': k * 5, 'packets_per_second': self.buckets.get(k, [0])[0] / 5}
                   for k in range(start, end)]
        protocols = sorted(p for p, seen in self.protocol_seen.items() if 0 <= now - seen < 60)
        data = {'updated_at': now, 'sample_seconds': 5, 'samples': samples,
                'protocols': protocols, 'protocol_window_seconds': 60}
        conn.execute('CREATE TABLE IF NOT EXISTS live_activity (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL)')
        conn.execute('INSERT OR REPLACE INTO live_activity VALUES (1, ?)', (json.dumps(data),))


def read_activity(conn):
    try:
        row = conn.execute('SELECT data FROM live_activity WHERE id=1').fetchone()
    except Exception as exc:
        import sqlite3
        if not isinstance(exc, sqlite3.OperationalError) or 'no such table' not in str(exc):
            raise
        row = None
    if not row:
        return {'available': False}
    data = json.loads(row[0])
    data['available'] = True
    age = time.time() - data['updated_at']
    data['stale'] = age < 0 or age > 15
    return data
