import ipaddress
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch, Mock
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP
import discovery as d

class DiscoverySafetyTests(unittest.TestCase):
    def test_flow_storage_failure_does_not_stop_device_observation(self):
        store = Mock()
        store.add.side_effect = sqlite3.OperationalError('database is locked')
        packet = self.frame(IP(src=self.ip)/UDP())
        with patch.object(d, 'handle') as handle:
            d.process_capture(packet, store)
            handle.assert_called_once_with(packet)

    def test_inventory_storage_failure_does_not_escape_capture_callback(self):
        store = Mock()
        packet = self.frame(IP(src=self.ip)/UDP())
        with patch.object(d, 'handle', side_effect=sqlite3.OperationalError('database is locked')):
            d.process_capture(packet, store)
        store.add.assert_called_once_with(packet)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mac = '02:11:22:33:44:55'
        self.ip = '192.168.1.50'
        for name, value in [('DB_PATH',str(Path(self.tmp.name)/'test.db')),
                            ('monitored_networks',[ipaddress.ip_network('192.168.1.0/24')]),
                            ('local_macs',set()),('local_ips',set()),('write_cache',{}),
                            ('syn_fp_last',{}),('probe_attempts',{}),('oui_dict',{}),('infra_hints',{})]:
            p=patch.object(d,name,value);p.start();self.addCleanup(p.stop)
        for name in ['schedule_active_probe','schedule_mdns_probe','schedule_nbns_probe','schedule_ssdp_probe']:
            p=patch.object(d,name);p.start();self.addCleanup(p.stop)
        d.init_db()
        with closing(sqlite3.connect(d.DB_PATH)) as conn, conn:
            conn.execute('UPDATE app_settings SET active_probes=1 WHERE id=1')

    def row(self):
        with closing(sqlite3.connect(d.DB_PATH)) as conn:
            conn.row_factory=sqlite3.Row
            row=conn.execute('SELECT * FROM devices WHERE mac=?',(self.mac,)).fetchone()
            return dict(row) if row else None

    def test_persisted_equal_conflict_requires_stronger_evidence(self):
        d.update_device(self.mac, ip=self.ip, candidate=('Printer',85,'service A'))
        d.update_device(self.mac, ip=self.ip, candidate=('Computer',85,'service B'))
        self.assertEqual(self.row()['device_type'], 'Generic / Unknown')
        d.update_device(self.mac, ip=self.ip, candidate=('Printer',85,'service A'))
        self.assertEqual(self.row()['device_type'], 'Generic / Unknown')
        d.update_device(self.mac, ip=self.ip, candidate=('Printer',95,'model evidence'))
        self.assertEqual(self.row()['device_type'], 'Printer')

    def test_nmap_service_result_reaches_inventory(self):
        from test_service_fingerprints import scan_xml, fingerprint
        d.update_device(self.mac, ip=self.ip, seen_in_discovery=True)
        reply = scan_xml([(8080, fingerprint('router'), 'open')], self.ip)
        with patch.object(d, 'ENABLE_ACTIVE_PROBE', True), patch.object(d.time, 'sleep'), \
             patch.object(d.subprocess, 'check_output', return_value=reply) as run:
            d.probe_device_ports(self.mac, self.ip)
        self.assertEqual(self.row()['device_type'], 'Router')
        self.assertEqual(self.row()['class_source'], 'nmap service fingerprint')
        command = run.call_args.args[0]
        self.assertIn('-sV', command)
        self.assertIn('--version-light', command)
        self.assertIn('-n', command)
        self.assertNotIn('--allports', command)
        self.assertNotIn('-A', command)
        self.assertEqual(command[-1], self.ip)

    def test_weak_vendor_guess_gets_refined_by_service(self):
        from test_service_fingerprints import scan_xml, fingerprint
        with patch.object(d, 'schedule_active_probe') as schedule:
            d.update_device(self.mac, ip=self.ip, vendor='ASUSTek Computer Inc.')
            self.assertEqual(self.row()['device_type'], 'Computer')
            schedule.assert_called_once_with(self.mac, self.ip)
        reply = scan_xml([(8080, fingerprint('router'), 'open')], self.ip)
        with patch.object(d, 'ENABLE_ACTIVE_PROBE', True), patch.object(d.time, 'sleep'), \
             patch.object(d.subprocess, 'check_output', return_value=reply):
            d.probe_device_ports(self.mac, self.ip)
        self.assertEqual(self.row()['device_type'], 'Router')
        self.assertEqual(self.row()['class_score'], d.SCORES['service'])
        with patch.object(d, 'schedule_active_probe') as schedule:
            d.update_device(self.mac, ip=self.ip, seen_in_discovery=True)
            schedule.assert_not_called()

    def test_strong_identity_arriving_before_scan_prevents_probe(self):
        d.update_device(self.mac, ip=self.ip, candidate=('Printer',95,'model'))
        with patch.object(d, 'ENABLE_ACTIVE_PROBE', True), patch.object(d.time, 'sleep'), \
             patch.object(d.subprocess, 'check_output') as run:
            d.probe_device_ports(self.mac, self.ip)
            run.assert_not_called()

    def test_nmap_reply_cannot_apply_after_switch_disabled(self):
        from test_service_fingerprints import scan_xml, fingerprint
        d.update_device(self.mac, ip=self.ip, seen_in_discovery=True)
        def reply(*args, **kwargs):
            with closing(sqlite3.connect(d.DB_PATH)) as conn, conn:
                conn.execute('UPDATE app_settings SET active_probes=0 WHERE id=1')
            return scan_xml([(8080, fingerprint('router'), 'open')], self.ip)
        with patch.object(d, 'ENABLE_ACTIVE_PROBE', True), patch.object(d.time, 'sleep'), \
             patch.object(d.subprocess, 'check_output', side_effect=reply):
            d.probe_device_ports(self.mac, self.ip)
        self.assertIsNone(self.row()['device_type'])

    def test_migration_rebuilds_old_model_and_preserves_inventory(self):
        d.update_device(self.mac, ip=self.ip, seen_in_discovery=True)
        with closing(sqlite3.connect(d.DB_PATH)) as conn, conn:
            conn.execute("UPDATE devices SET model='Pixel Tablet', device_type='Mobile (Android)', class_score=95, class_source='device model identifier' WHERE mac=?", (self.mac,))
        before = self.row()
        d.migrate_classification_rules()
        after = self.row()
        self.assertEqual(after['device_type'], 'Tablet (Android)')
        for field in ('ip','mac','first_seen','last_seen','is_monitored'):
            self.assertEqual(before[field], after[field])
        d.migrate_classification_rules()
        self.assertEqual(self.row(), after)

    def test_migration_removes_dns_identity_but_preserves_live_service(self):
        d.update_device(self.mac, ip=self.ip, seen_in_discovery=True)
        with closing(sqlite3.connect(d.DB_PATH)) as conn, conn:
            conn.execute("UPDATE devices SET device_type='Apple Device', class_score=45, class_source='DNS query (matched: apple.com)', vendor='Apple Inc.', vendor_source='inferred: domain (captive.apple.com)' WHERE mac=?", (self.mac,))
        d.migrate_classification_rules()
        self.assertIsNone(self.row()['device_type'])
        self.assertIsNone(self.row()['vendor'])
        d.update_device(self.mac, ip=self.ip, candidate=('Printer',85,'mDNS advertisement'))
        d.migrate_classification_rules()
        self.assertEqual(self.row()['device_type'], 'Printer')

    def frame(self, payload):
        return Ether(src=self.mac,dst='00:11:22:33:44:66')/payload

    def test_icmp_quote_does_not_classify_sender_as_a_printer(self):
        d.handle(self.frame(IP(src=self.ip)/ICMP(type=3)/
                            IP(src='192.168.1.99')/TCP(sport=9100, flags='SA')))
        row = self.row()
        self.assertEqual(row['ip'], self.ip)
        self.assertIsNone(row['device_type'])
        self.assertTrue(row['is_monitored'])

    def test_tunneled_ipv4_does_not_replace_outer_ipv6_source(self):
        d.handle(self.frame(IPv6(src='fe80::1234')/
                            IP(src='192.168.1.99')/TCP(sport=9100, flags='SA')))
        self.assertEqual(self.row()['ip'], 'fe80::1234')
        self.assertIsNone(self.row()['device_type'])

    def test_upnp_rejects_description_on_a_different_device(self):
        with patch.object(d, 'probe_target_current', return_value=True), \
                patch.object(d.urllib.request, 'build_opener') as opener:
            d.enrich_upnp_metadata(self.mac, self.ip, 'http://192.168.1.99/device.xml')
            opener.assert_not_called()

    def test_upnp_redirect_cannot_leave_the_device(self):
        handler = d._LocalMetadataRedirectHandler()
        request = d.urllib.request.Request(f'http://{self.ip}/device.xml')
        for url in ('http://8.8.8.8/device.xml', 'http://192.168.1.99/device.xml'):
            self.assertIsNone(handler.redirect_request(request, None, 302, 'Found', {}, url))
        allowed = handler.redirect_request(request, None, 302, 'Found', {}, f'http://{self.ip}/new.xml')
        self.assertEqual(allowed.full_url, f'http://{self.ip}/new.xml')

    def test_unknown_syn_and_rate_limit_still_refresh_inventory(self):
        packet=self.frame(IP(src=self.ip,dst='1.1.1.1')/TCP(flags='S'))
        with patch.object(d,'fingerprint_tcp_syn',return_value=(None,None)) as fingerprint:
            d.handle(packet)
            self.assertIsNotNone(self.row())
            self.assertTrue(self.row()['is_monitored'])
            with patch.object(d,'update_device') as update:
                d.handle(packet)
                self.assertTrue(update.called)
            self.assertEqual(fingerprint.call_count,1)

    def test_foreign_syn_ack_not_attributed_to_router(self):
        d.handle(self.frame(IP(src='8.8.8.8',dst=self.ip)/TCP(sport=9100,flags='SA')))
        self.assertIsNone(self.row())

    def test_ipv6_address_is_recorded(self):
        d.handle(self.frame(IPv6(src='fe80::1234',dst='ff02::fb')/UDP(sport=9999,dport=9999)))
        self.assertEqual(self.row()['ip'],'fe80::1234')

    def test_cancel_or_changed_ip_prevents_queued_probe(self):
        d.update_device(self.mac,ip=self.ip,seen_in_discovery=True)
        for enabled, target in [(False,self.ip),(True,'192.168.1.99')]:
            with patch.object(d,'ENABLE_ACTIVE_PROBE',enabled), patch.object(d.time,'sleep'), patch.object(d.subprocess,'check_output') as send:
                d.probe_device_ports(self.mac,target)
                send.assert_not_called()

    def test_changed_ip_during_probe_discards_reply(self):
        d.update_device(self.mac,ip=self.ip,seen_in_discovery=True)
        def reply(*args,**kwargs):
            with closing(sqlite3.connect(d.DB_PATH)) as conn,conn:
                conn.execute('UPDATE devices SET ip=? WHERE mac=?',('192.168.1.99',self.mac))
            return '9100/tcp open'
        with patch.object(d,'ENABLE_ACTIVE_PROBE',True),patch.object(d.time,'sleep'),patch.object(d.subprocess,'check_output',side_effect=reply):
            d.probe_device_ports(self.mac,self.ip)
        self.assertIsNone(self.row()['device_type'])
        self.assertEqual(self.row()['ip'],'192.168.1.99')

    def test_service_corrects_legacy_hostname_classification(self):
        d.update_device(self.mac,ip=self.ip,hostname='iphone',seen_in_discovery=True)
        with closing(sqlite3.connect(d.DB_PATH)) as conn,conn:
            conn.execute("UPDATE devices SET class_score=90, class_source='hostname' WHERE mac=?",(self.mac,))
        d.update_device(self.mac,ip=self.ip,candidate=('Printer',d.SCORES['service'],'mDNS advertisement'))
        self.assertEqual(self.row()['device_type'],'Printer')
        self.assertEqual(self.row()['class_score'],d.SCORES['service'])

    def test_stronger_vendor_replaces_guess_but_weaker_does_not(self):
        d.update_device(self.mac,ip=self.ip,vendor='Guess',vendor_source='inferred: hostname')
        d.update_device(self.mac,ip=self.ip,vendor='Actual',vendor_source='inferred: UPnP manufacturer')
        d.update_device(self.mac,ip=self.ip,vendor='Guess again',vendor_source='inferred: hostname')
        self.assertEqual(self.row()['vendor'],'Actual')
        self.assertEqual(self.row()['vendor_source'],'inferred: UPnP manufacturer')

    def test_database_switch_cancels_before_periodic_flags_reload(self):
        d.update_device(self.mac,ip=self.ip,seen_in_discovery=True)
        with closing(sqlite3.connect(d.DB_PATH)) as conn,conn:
            conn.execute('UPDATE app_settings SET active_probes=0')
        with patch.object(d,'ENABLE_ACTIVE_PROBE',True),patch.object(d.time,'sleep'),patch.object(d.subprocess,'check_output') as send:
            d.probe_device_ports(self.mac,self.ip)
            send.assert_not_called()

    def test_retry_is_bounded_and_waits_between_attempts(self):
        import threading
        pending=set();lock=threading.Lock();calls=[]
        def worker(mac,ip): calls.append(ip)
        with patch.object(d,'ENABLE_ACTIVE_PROBE',True),patch.object(d.time,'monotonic',return_value=0) as clock,patch.object(d.threading,'Thread') as thread:
            for t in [0,1,61,62,122,183]:
                clock.return_value=t
                before=thread.call_count
                d.schedule_bounded_probe(self.mac,self.ip,'ENABLE_ACTIVE_PROBE',pending,lock,worker)
                if thread.call_count>before:
                    thread.call_args.kwargs['target']()
            self.assertEqual(len(calls),3)
            self.assertFalse(pending)

    def test_broadcast_and_multicast_frames_do_not_mark_monitored(self):
        for dst in ('ff:ff:ff:ff:ff:ff', '01:00:5e:00:00:fb', '33:33:00:00:00:fb'):
            d.handle(Ether(src=self.mac, dst=dst)/IP(src=self.ip, dst='255.255.255.255')/ICMP())
        row = self.row()
        self.assertIsNotNone(row)
        self.assertFalse(row['is_monitored'])

    def test_unicast_frame_marks_monitored_after_broadcast(self):
        d.handle(Ether(src=self.mac, dst='ff:ff:ff:ff:ff:ff')/IP(src=self.ip, dst='255.255.255.255')/ICMP())
        self.assertFalse(self.row()['is_monitored'])
        d.handle(self.frame(IP(src=self.ip, dst='192.168.1.1')/ICMP()))
        self.assertTrue(self.row()['is_monitored'])

    def test_span_sighting_without_monitored_evidence_stays_unmonitored(self):
        d.update_device(self.mac, ip=self.ip, seen_on_span=True, monitored_evidence=False)
        self.assertFalse(self.row()['is_monitored'])
        d.update_device(self.mac, ip=self.ip, seen_on_span=True)
        self.assertTrue(self.row()['is_monitored'])

if __name__=='__main__':unittest.main()
