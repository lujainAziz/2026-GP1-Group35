import sqlite3
import tempfile
import unittest
from pathlib import Path
from contextlib import closing
from scapy.all import Ether, IP, IPv6, UDP, TCP, ARP, ICMP, wrpcap, PcapReader
from scapy.layers.inet6 import IPv6ExtHdrHopByHop, IPv6ExtHdrFragment
from flows import FlowStore

class FlowTests(unittest.TestCase):
    def test_outer_protocol_is_not_replaced_by_quoted_or_tunneled_transport(self):
        cases = [
            (IP(src='192.0.2.1', dst='192.0.2.2')/ICMP(type=3)/
             IP(src='198.51.100.1', dst='198.51.100.2')/UDP(sport=1234, dport=53), 1),
            (IPv6(src='2001:db8::1', dst='2001:db8::2')/
             IP(src='198.51.100.1', dst='198.51.100.2')/TCP(sport=1234, dport=443), 4),
        ]
        for packet, protocol in cases:
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory() as directory:
                store = FlowStore(str(Path(directory)/'flows.db'))
                store.add(packet)
                key = next(iter(store.pending))
                self.assertEqual(key[1:3], (packet.src, packet.dst))
                self.assertEqual(key[3:], (protocol, -1, -1))

    def test_ipv6_extensions_keep_transport_and_noninitial_fragments_have_no_ports(self):
        packets = [
            (IPv6()/IPv6ExtHdrHopByHop()/UDP(sport=1234, dport=53), (17, 1234, 53)),
            (IPv6()/IPv6ExtHdrFragment(nh=17, offset=1)/b'fragment', (17, -1, -1)),
        ]
        for packet, expected in packets:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                store = FlowStore(str(Path(directory)/'flows.db'))
                store.add(packet)
                self.assertEqual(next(iter(store.pending))[3:], expected)

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
