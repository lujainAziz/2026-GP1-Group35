"""Bounded, directional flow windows for passive capture (PBI-03).

Stores metadata only; payloads are never persisted. IP byte counts exclude
Ethernet headers. A flow is a directional IP/protocol/port tuple per window.
"""
import sqlite3
import threading
import time
from contextlib import closing
from datetime import datetime, timezone
from scapy.all import IP, IPv6, TCP, UDP
from live_activity import LiveActivity


class FlowStore:
    def __init__(self, path, window_seconds=60, max_flows=10000):
        self.path = path
        self.window_seconds = window_seconds
        self.max_flows = max_flows
        self.pending = {}
        self.lock = threading.RLock()
        self.activity = LiveActivity()
        with closing(sqlite3.connect(path)) as conn, conn:
            conn.execute('CREATE TABLE IF NOT EXISTS daemon_heartbeat (id INTEGER PRIMARY KEY CHECK(id=1), updated_at REAL NOT NULL)')
            conn.execute('''CREATE TABLE IF NOT EXISTS flows (
                window INTEGER NOT NULL, src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,
                protocol INTEGER NOT NULL, src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL, first_seen REAL NOT NULL,
                last_seen REAL NOT NULL, packet_count INTEGER NOT NULL,
                byte_count INTEGER NOT NULL,
                PRIMARY KEY(window, src_ip, dst_ip, protocol, src_port, dst_port))''')

    def add(self, packet):
        with self.lock:
            self.activity.add(packet)
            self._add(packet)

    def _add(self, packet):
        layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if layer is None:
            return
        stamp = float(packet.time)
        transport = layer.getlayer(TCP) or layer.getlayer(UDP)
        protocol = (6 if isinstance(transport, TCP) else 17) if transport else int(
            layer.proto if isinstance(layer, IP) else layer.nh)
        # -1 represents an unavailable port, including noninitial fragments.
        src_port = int(transport.sport) if transport else -1
        dst_port = int(transport.dport) if transport else -1
        key = (int(stamp // self.window_seconds), layer.src, layer.dst,
               protocol, src_port, dst_port)
        if key not in self.pending and len(self.pending) >= self.max_flows:
            self.flush()
        value = self.pending.setdefault(key, [stamp, stamp, 0, 0])
        value[0] = min(value[0], stamp)
        value[1] = max(value[1], stamp)
        value[2] += 1
        value[3] += len(bytes(layer))

    def flush(self):
        with self.lock:
            self._flush()

    def _flush(self):
        with closing(sqlite3.connect(self.path, timeout=5)) as conn, conn:
            self.activity.persist(conn)
            conn.execute('INSERT OR REPLACE INTO daemon_heartbeat VALUES (1, ?)', (time.time(),))
            conn.executemany('''INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(window,src_ip,dst_ip,protocol,src_port,dst_port)
                DO UPDATE SET first_seen=MIN(first_seen,excluded.first_seen),
                last_seen=MAX(last_seen,excluded.last_seen),
                packet_count=packet_count+excluded.packet_count,
                byte_count=byte_count+excluded.byte_count''',
                [(*key, *value) for key, value in self.pending.items()])
        self.pending.clear()

    @staticmethod
    def utc_timestamp(stamp):
        return datetime.fromtimestamp(stamp, timezone.utc).isoformat()
