import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from scapy.all import Ether, ARP, IP, ICMP, UDP, DNS, DNSQR
from flows import FlowStore
from live_activity import LiveActivity, read_activity


class LiveActivityTests(unittest.TestCase):
    def test_quoted_dns_in_icmp_is_not_counted_as_live_dns(self):
        activity = LiveActivity()
        activity.add(IP()/ICMP(type=3)/IP()/UDP(dport=53)/DNS(qd=DNSQR(qname='example.test')))
        self.assertEqual(activity.protocol_seen, {})
        self.assertEqual(sum(v[0] for v in activity.buckets.values()), 1)

    def test_real_capture_counts_idle_decay_stale_and_restart(self):
        with tempfile.TemporaryDirectory() as tmp, patch('live_activity.time.time', return_value=100) as clock:
            path = str(Path(tmp)/'db')
            store = FlowStore(path)
            clock.return_value = 106
            store.add(Ether()/ARP())
            store.add(Ether()/IP()/UDP(sport=5353,dport=5353)/DNS(qd=DNSQR(qname='_test.local')))
            clock.return_value = 110
            store.flush()
            with closing(sqlite3.connect(path)) as conn:
                data = read_activity(conn)
                self.assertEqual(data['samples'], [{'time':105,'packets_per_second':0.4}])
                self.assertEqual(data['protocols'], ['ARP','MDNS','UDP'])
                self.assertFalse(data['stale'])
                self.assertNotIn('qname', json.dumps(data))
                clock.return_value = 126
                self.assertTrue(read_activity(conn)['stale'])
            clock.return_value = 170
            store.flush()
            with closing(sqlite3.connect(path)) as conn:
                data = read_activity(conn)
                self.assertEqual(data['protocols'], [])
                self.assertEqual(data['samples'][-1]['packets_per_second'], 0)
                self.assertLessEqual(len(data['samples']), 12)
            store = FlowStore(path)
            store.flush()
            with closing(sqlite3.connect(path)) as conn:
                self.assertEqual(read_activity(conn)['samples'], [])

    def test_old_database_has_no_fabricated_activity(self):
        with closing(sqlite3.connect(':memory:')) as conn:
            self.assertEqual(read_activity(conn), {'available':False})
