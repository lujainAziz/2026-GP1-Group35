import sqlite3
import tempfile
import unittest
from pathlib import Path
from contextlib import closing
from scapy.all import Ether, IP, IPv6, UDP, TCP, ARP, wrpcap, PcapReader
from flows import FlowStore

class FlowTests(unittest.TestCase):
    def test_recorded_capture_counts_directions_ports_and_windows(self):
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / 'flows.db')
            pcap = str(Path(directory) / 'capture.pcap')
            a = Ether()/IP(src='192.0.2.1', dst='192.0.2.2')/UDP(sport=1234,dport=53)/b'abc'
            b = Ether()/IP(src='192.0.2.2', dst='192.0.2.1')/UDP(sport=53,dport=1234)/b'xyz'
            c = Ether()/IPv6(src='2001:db8::1', dst='2001:db8::2')/TCP(sport=9,dport=443)
            packets = [a.copy(), a.copy(), b, c, Ether()/ARP()]
            for i, packet in enumerate(packets): packet.time = 120+i
            wrpcap(pcap, packets)
            store = FlowStore(db, max_flows=1)
            with PcapReader(pcap) as reader:
                for packet in reader: store.add(packet)
            store.flush()
            store.flush()  # idempotent flush does not count packets twice
            with closing(sqlite3.connect(db)) as conn:
                rows = conn.execute('SELECT src_ip,src_port,dst_port,packet_count,byte_count FROM flows ORDER BY src_ip').fetchall()
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[0], ('192.0.2.1',1234,53,2,62))
            self.assertEqual(rows[1][3], 1)
            self.assertEqual(rows[2][1:4], (9,443,1))
            later=a.copy();later.time=180
            store.add(later);store.flush()
            with closing(sqlite3.connect(db)) as conn:
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM flows').fetchone()[0],4)

if __name__ == '__main__': unittest.main()
