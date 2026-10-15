"""HTTP contracts used by the mobile app and the appliance display."""
import os
import sqlite3
import tempfile
import unittest
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
            conn.execute("UPDATE devices SET status='observed', is_monitored=1, last_seen=?", ((now-timedelta(seconds=121)).isoformat(),))
        device = self.local.get('/devices').json()[0]
        self.assertEqual(device['presence'], 'offline')
        self.assertTrue(device['monitored'])


if __name__ == '__main__':
    unittest.main()
