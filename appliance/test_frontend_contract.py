"""HTTP contracts used by the mobile app and the appliance display."""
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock
from contextlib import closing
from unittest.mock import patch
from fastapi.testclient import TestClient
import api
from test_api import _DEVICES_SCHEMA


class FrontendContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.directory.name, 'assas.db')
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute(f'CREATE TABLE devices ({_DEVICES_SCHEMA})')
            conn.execute("INSERT INTO devices (mac, hostname, status, discovered_current) VALUES (?, ?, 'online', 1)",
                         ('00:11:22:33:44:55', 'detected-phone'))
        self.patch = patch.object(api, 'DB_PATH', self.db)
        self.patch.start()
        self.local = TestClient(api.app, client=('127.0.0.1', 1234))
        self.phone = TestClient(api.app, client=('192.0.2.10', 1234))

    def tearDown(self):
        self.local.close()
        self.phone.close()
        self.patch.stop()
        self.directory.cleanup()

    def pair(self, name='Maraheb phone'):
        code = self.local.get('/pairing/code').json()['code']
        response = self.phone.post('/pair', json={'code': code, 'device_name': name})
        self.assertEqual(response.status_code, 200, response.text)
        self.phone.headers['Authorization'] = 'Bearer ' + response.json()['token']

    def test_activity_requires_session_and_reads_capture_snapshot(self):
        from flows import FlowStore
        from scapy.all import Ether, ARP
        self.assertEqual(self.phone.get('/activity').status_code, 401)
        self.pair()
        self.assertEqual(self.phone.get('/activity').json(), {'available': False})
        capture = FlowStore(self.db)
        capture.add(Ether()/ARP())
        capture.flush()
        response = self.phone.get('/activity')
        self.assertEqual(response.status_code, 200)
        self.assertIn('ARP', response.json()['protocols'])
        self.phone.post('/unpair')
        self.assertEqual(self.phone.get('/activity').status_code, 401)

    def test_pair_rename_clear_and_revoked_session(self):
        self.assertEqual(self.phone.get('/devices').status_code, 401)
        self.pair()
        route = '/devices/00:11:22:33:44:55'
        self.assertEqual(self.phone.put(route + '/name', json={'name': ' Kitchen phone '}).status_code, 200)
        self.assertEqual(self.phone.get(route).json()['user_name'], 'Kitchen phone')
        self.assertEqual(self.phone.get('/devices').json()[0]['user_name'], 'Kitchen phone')
        self.assertEqual(self.phone.put(route + '/name', json={'name': None}).status_code, 200)
        self.assertIsNone(self.phone.get(route).json()['user_name'])
        sessions = self.local.get('/sessions').json()
        self.assertEqual(sessions[0]['device_name'], 'Maraheb phone')
        self.assertEqual(set(sessions[0]), {'id', 'device_name', 'created_at'})
        self.assertEqual(self.phone.get('/sessions').status_code, 403)
        self.assertEqual(self.phone.post('/unpair').status_code, 204)
        self.assertEqual(self.phone.get('/devices').status_code, 401)

    def test_legacy_sessions_migrate_and_empty_name_defaults(self):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('CREATE TABLE paired_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL)')
            conn.execute("INSERT INTO paired_sessions(token_hash, created_at) VALUES ('legacy', '2026-10-01')")
        self.assertEqual(self.local.get('/sessions').json()[0]['device_name'], 'Unnamed phone')
        self.pair('   ')
        self.assertEqual(self.local.get('/sessions').json()[-1]['device_name'], 'Unnamed phone')
        code = self.local.get('/pairing/code').json()['code']
        self.assertEqual(self.phone.post('/pair', json={'code': code, 'device_name': 'a' * 41}).status_code, 422)

    def test_identity_is_persistent_and_pair_matches_health(self):
        first = self.local.get('/healthz').json()['appliance_id']
        self.assertEqual(first, self.local.get('/healthz').json()['appliance_id'])
        code = self.local.get('/pairing/code').json()['code']
        result = self.phone.post('/pair', json={'code': code}).json()
        self.assertEqual(first, result['appliance_id'])

    def test_unpair_storage_failure_is_not_success(self):
        self.pair()
        with patch.object(api, '_open_writable', side_effect=sqlite3.OperationalError('locked')):
            self.assertEqual(self.phone.post('/unpair').status_code, 503)
        self.assertEqual(self.phone.get('/devices').status_code, 200)

    def test_idle_capture_heartbeat_keeps_health_live(self):
        from flows import FlowStore
        store = FlowStore(self.db)
        store.flush()
        self.assertFalse(self.local.get('/healthz').json()['daemon_stale'])
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('UPDATE daemon_heartbeat SET updated_at=0')
        self.assertTrue(self.local.get('/healthz').json()['daemon_stale'])

    def test_presence_120_second_boundary_does_not_change_monitoring(self):
        from datetime import datetime, timedelta
        now = datetime.now().astimezone()
        self.assertEqual(api._presence_from_status('observed', (now-timedelta(seconds=120)).isoformat(), now), 'online')
        self.assertEqual(api._presence_from_status('observed', (now-timedelta(seconds=121)).isoformat(), now), 'offline')
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("UPDATE devices SET status='observed', is_monitored=1, last_seen=?, last_monitored_seen=?", ((now-timedelta(seconds=121)).isoformat(), now.isoformat()))
        device = self.local.get('/devices').json()[0]
        self.assertEqual(device['presence'], 'offline')
        self.assertTrue(device['monitored'])

    def test_device_page_size_is_bounded(self):
        for limit in (-1, 0, 501):
            response = self.local.get('/devices', params={'limit': limit})
            self.assertEqual(response.status_code, 422, response.text)
        for limit in (1, 500):
            response = self.local.get('/devices', params={'limit': limit})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertLessEqual(len(response.json()), limit)

    def test_session_database_failure_is_unavailable_not_revoked(self):
        self.pair()
        connection = MagicMock()
        connection.execute.side_effect = sqlite3.OperationalError('database is locked')
        with patch.object(api.sqlite3, 'connect', return_value=connection):
            response = self.phone.get('/devices')
        self.assertEqual(response.status_code, 503, response.text)
        connection.close.assert_called_once()
        self.assertEqual(self.phone.get('/devices').status_code, 200)

    def test_missing_session_table_still_requires_pairing(self):
        self.phone.headers['Authorization'] = 'Bearer unknown'
        self.assertEqual(self.phone.get('/devices').status_code, 401)

    def test_online_filter_uses_presence_before_pagination(self):
        from datetime import datetime, timedelta
        now = datetime.now().astimezone()
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('DELETE FROM devices')
            conn.executemany('INSERT INTO devices (mac,status,last_seen) VALUES (?,?,?)', [
                ('a', 'online', (now-timedelta(seconds=121)).isoformat()),
                ('b', 'observed', now.isoformat()),
                ('c', 'offline', now.isoformat()),
                ('d', 'online', now.isoformat()),
                ('e', 'observed', 'invalid'),
            ])
        all_devices = self.local.get('/devices').json()
        expected = [d['mac'] for d in all_devices if d['presence'] == 'online']
        actual = self.local.get('/devices?online_only=true').json()
        self.assertEqual([d['mac'] for d in actual], expected)
        self.assertEqual(expected, ['b', 'd'])
        for offset, mac in enumerate(expected):
            page = self.local.get(f'/devices?online_only=true&limit=1&offset={offset}').json()
            self.assertEqual([d['mac'] for d in page], [mac])

    def test_health_accepts_timezone_aware_device_timestamps(self):
        from datetime import datetime, timezone
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('UPDATE devices SET last_seen=?', (datetime.now(timezone.utc).isoformat(),))
        response = self.local.get('/healthz')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertLess(response.json()['seconds_since_write'], 5)

    def test_settings_read_failure_is_not_reported_as_probes_disabled(self):
        connection = MagicMock()
        connection.execute.side_effect = sqlite3.OperationalError('database is locked')
        with self.assertRaises(api.HTTPException) as caught:
            api.get_settings(connection)
        self.assertEqual(caught.exception.status_code, 503)


class AlertContractTests(unittest.TestCase):
    """End-to-end (incl. pairing auth) exact-string contract for Threat Alerts."""

    def setUp(self):
        import alerts
        self.directory = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.directory.name, 'assas.db')
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute(f'CREATE TABLE devices ({_DEVICES_SCHEMA})')
            conn.execute(
                "INSERT INTO devices (mac, user_name, status, discovered_current) "
                "VALUES (?, ?, 'online', 1)", ('aa:bb:cc:dd:ee:ff', 'Front Cam'))
            alerts.ensure_schema(conn)
            conn.execute(
                "INSERT INTO alerts (device_mac, alert_type, title, rule_id, event_time, "
                "src_ip, dst_ip, src_port, dst_port, severity, state, occurrence_count, "
                "last_event_time) VALUES (?, 'Threat', ?, ?, ?, ?, ?, ?, ?, ?, 'New', ?, ?)",
                ('aa:bb:cc:dd:ee:ff', 'ET MALWARE X', 2025001, '2026-11-02T10:00:00',
                 '10.0.0.5', '8.8.8.8', 1234, 53, 'Critical', 4, '2026-11-02T10:04:00'))
        self.patch = patch.object(api, 'DB_PATH', self.db)
        self.patch.start()
        self.local = TestClient(api.app, client=('127.0.0.1', 1234))
        self.phone = TestClient(api.app, client=('192.0.2.10', 1234))

    def tearDown(self):
        self.local.close()
        self.phone.close()
        self.patch.stop()
        self.directory.cleanup()

    def pair(self):
        code = self.local.get('/pairing/code').json()['code']
        token = self.phone.post('/pair', json={'code': code, 'device_name': 'p'}).json()['token']
        self.phone.headers['Authorization'] = 'Bearer ' + token

    def test_alerts_require_auth_and_match_exact_contract(self):
        self.assertEqual(self.phone.get('/alerts').status_code, 401)
        self.pair()
        response = self.phone.get('/alerts')
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(len(data), 1)
        a = data[0]
        # Exact strings SecurityAlert.fromApi depends on (casing locked).
        self.assertEqual(a['kind'], 'threat')
        self.assertEqual(a['state'], 'new')
        self.assertEqual(a['severity'], 'critical')
        self.assertEqual(a['title'], 'ET MALWARE X')
        self.assertEqual(a['device_mac'], 'aa:bb:cc:dd:ee:ff')
        self.assertEqual(a['device_name'], 'Front Cam')
        self.assertEqual(a['time'], '2026-11-02T10:04:00')  # = last_event_time
        self.assertEqual(a['first_event_time'], '2026-11-02T10:00:00')
        self.assertEqual(a['last_event_time'], '2026-11-02T10:04:00')
        self.assertEqual(a['occurrence_count'], 4)
        self.assertEqual(a['rule_id'], 2025001)
        self.assertEqual(a['source_ip'], '10.0.0.5')
        self.assertEqual(a['destination_ip'], '8.8.8.8')
        self.assertEqual(a['src_port'], 1234)
        self.assertEqual(a['dst_port'], 53)
        self.assertIsNone(a['explanation'])
        self.assertIsNone(a['anomaly_score'])
        # single-alert + per-device endpoints
        one = self.phone.get('/alerts/' + a['id'])
        self.assertEqual(one.status_code, 200)
        self.assertEqual(one.json()['id'], a['id'])
        dev = self.phone.get('/devices/aa:bb:cc:dd:ee:ff/alerts')
        self.assertEqual(dev.status_code, 200)
        self.assertEqual(len(dev.json()), 1)
        self.assertEqual(self.phone.get('/alerts/99999').status_code, 404)

    def _insert_alert(self, state='New', mac='aa:bb:cc:dd:ee:ff', sid=3000, when='2026-11-02T09:00:00'):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute(
                "INSERT INTO alerts (device_mac, alert_type, title, rule_id, event_time, "
                "src_ip, dst_ip, severity, state, occurrence_count, last_event_time) "
                "VALUES (?, 'Threat', 'ET X', ?, ?, '10.0.0.5', '8.8.8.8', 'High', ?, 1, ?)",
                (mac, sid, when, state, when))

    def test_open_count_is_db_aggregate_of_new_and_reviewed(self):
        # setUp already has one New alert; add reviewed + resolved + new.
        self._insert_alert(state='Reviewed', sid=3001)
        self._insert_alert(state='Resolved', sid=3002)
        self._insert_alert(state='New', sid=3003)
        self.assertEqual(self.phone.get('/alerts/open_count').status_code, 401)
        self.pair()
        r = self.phone.get('/alerts/open_count')
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json(), {'open': 3})  # 2 New + 1 Reviewed, Resolved excluded
        # the literal path is matched here, not parsed as an int id
        self.assertEqual(r.json()['open'], 3)

    def test_open_count_not_capped_by_page_limit(self):
        for i in range(250):
            self._insert_alert(state='New', sid=4000 + i, when='2026-11-02T08:00:00')
        self.pair()
        # default page returns at most 200, but the count is the true total
        self.assertEqual(len(self.phone.get('/alerts').json()), 200)
        self.assertEqual(self.phone.get('/alerts/open_count').json()['open'], 251)  # 250 + setUp's 1

    def test_alerts_pagination_offset_is_stable(self):
        for i in range(250):
            self._insert_alert(state='New', sid=5000 + i, when='2026-11-02T08:00:00')
        self.pair()
        page1 = self.phone.get('/alerts?limit=100&offset=0').json()
        page2 = self.phone.get('/alerts?limit=100&offset=100').json()
        page3 = self.phone.get('/alerts?limit=100&offset=200').json()
        self.assertEqual([len(page1), len(page2), len(page3)], [100, 100, 51])
        ids = {a['id'] for a in page1 + page2 + page3}
        self.assertEqual(len(ids), 251)  # no overlap/gap across pages

    def test_alert_state_transitions_persist_and_enforce_rules(self):
        self.pair()
        aid = self.phone.get('/alerts').json()[0]['id']
        # New -> Reviewed
        r = self.phone.patch('/alerts/' + aid, json={'state': 'reviewed'})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()['state'], 'reviewed')
        # persisted across a fresh read
        self.assertEqual(self.phone.get('/alerts/' + aid).json()['state'], 'reviewed')
        # Reviewed -> Resolved
        self.assertEqual(self.phone.patch('/alerts/' + aid, json={'state': 'resolved'}).json()['state'], 'resolved')
        # Resolved is terminal: no going back
        self.assertEqual(self.phone.patch('/alerts/' + aid, json={'state': 'reviewed'}).status_code, 409)
        self.assertEqual(self.phone.patch('/alerts/' + aid, json={'state': 'new'}).status_code, 409)
        # unknown state / missing alert
        self.assertEqual(self.phone.patch('/alerts/' + aid, json={'state': 'bogus'}).status_code, 422)
        self.assertEqual(self.phone.patch('/alerts/99999', json={'state': 'reviewed'}).status_code, 404)

    def test_alert_state_change_requires_auth(self):
        aid = self.phone.get('/alerts')  # unauthenticated
        self.assertEqual(self.phone.patch('/alerts/1', json={'state': 'reviewed'}).status_code, 401)

    def test_new_to_resolved_is_allowed(self):
        self.pair()
        aid = self.phone.get('/alerts').json()[0]['id']
        self.assertEqual(self.phone.patch('/alerts/' + aid, json={'state': 'resolved'}).json()['state'], 'resolved')


if __name__ == '__main__':
    unittest.main()
