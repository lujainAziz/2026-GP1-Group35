import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch
import discovery as d
import model_db
import classification as c
from build_device_models import classify

class AuditRepairs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, 'audit.db')
        self.override = patch.object(d, 'DB_PATH', self.db)
        self.override.start()
        d.init_db()
        d.write_cache.clear()

    def tearDown(self):
        self.override.stop()
        self.tmp.cleanup()

    def test_camera_is_not_a_phone(self):
        self.assertIsNone(classify('samsung', 'Galaxy Camera 2', 'EK-GC200'))
        self.assertEqual(classify('htc', 'One M9+ (Prime Camera Edition)', 'HTC-M9'), 'Mobile (Android)')
        self.assertIsNone(classify('samsung', 'Galaxy NX', 'EK-GN120'))
        self.assertEqual(classify('fujitsu', 'ARROWS NX F-06E', 'F-06E'), 'Mobile (Android)')
        self.assertEqual(classify('tecno', 'NX', 'TECNO R8O'), 'Mobile (Android)')
        self.assertEqual(c.normalize_model('EK-GC200'), ('EK-GC200', None))
        self.assertIsNone(c.type_from_model('Galaxy Camera 2 (EK-GC200)'))

    def test_exact_hostname_code_is_low_confidence_and_real_model_wins(self):
        for name in ['android-123abc', 'My-SM-S948B', 'Samsung', 'SM-S948B.evil.local']:
            self.assertIsNone(model_db.model_from_hostname(name))
        self.assertEqual(model_db.model_from_hostname('sm-s948b.local.'), 'SM-S948B')
        mac = 'a4:00:00:00:00:99'
        d.update_device(mac, hostname='SM-S948B')
        d.rescore_stored_evidence(verbose=False)
        with closing(sqlite3.connect(self.db)) as con, con:
            model, score = con.execute('SELECT model,class_score FROM devices WHERE mac=?', (mac,)).fetchone()
        self.assertIn('Galaxy S26 Ultra', model)
        self.assertEqual(score, c.SCORES['hostname'])
        d.update_device(mac, model='SM-X710', model_score=95, model_source='mDNS model', candidate=('Tablet (Android)',95,'device model identifier'))
        with closing(sqlite3.connect(self.db)) as con, con:
            self.assertEqual(con.execute('SELECT device_type FROM devices WHERE mac=?',(mac,)).fetchone()[0], 'Tablet (Android)')

    def test_legacy_ipv4_survives_first_ipv6_packet(self):
        mac = 'a4:00:00:00:00:77'
        with closing(sqlite3.connect(self.db)) as con, con:
            con.execute("INSERT INTO devices(mac,ip,first_seen,last_seen) VALUES (?,?,'x','x')", (mac,'192.168.1.77'))
        d.init_db()
        d.update_device(mac, ip='fe80::77')
        with closing(sqlite3.connect(self.db)) as con, con:
            self.assertEqual(con.execute('SELECT last_ipv4,last_ipv6_ll FROM devices WHERE mac=?',(mac,)).fetchone(), ('192.168.1.77','fe80::77'))

    def test_database_verdict_can_be_corrected(self):
        with closing(sqlite3.connect(self.db)) as con, con:
            con.execute("INSERT INTO devices(mac,first_seen,last_seen,model,model_score,device_type,class_score,class_source) VALUES ('a4:00:00:00:00:88','x','x','SM-X710',95,'Mobile (Android)',95,'device model identifier (model database)')")
        self.assertEqual(d.reevaluate_stale_classifications(verbose=False), 1)
        with closing(sqlite3.connect(self.db)) as con, con:
            self.assertEqual(con.execute('SELECT device_type FROM devices').fetchone()[0], 'Tablet (Android)')

    def test_old_camera_verdict_is_cleared(self):
        with closing(sqlite3.connect(self.db)) as con, con:
            con.execute("INSERT INTO devices(mac,first_seen,last_seen,model,model_score,device_type,class_score,class_source) VALUES ('a4:00:00:00:00:88','x','x','Galaxy Camera 2 (EK-GC200)',95,'Mobile (Android)',95,'device model identifier (model database)')")
        self.assertEqual(d.reevaluate_stale_classifications(verbose=False), 1)
        with closing(sqlite3.connect(self.db)) as con, con:
            self.assertEqual(con.execute('SELECT device_type FROM devices').fetchone()[0], 'Android Device')

    def test_model_only_verdict_falls_back_but_other_evidence_is_kept(self):
        with closing(sqlite3.connect(self.db)) as con, con:
            # Model alone said phone; the current rules no longer type it.
            con.execute("INSERT INTO devices(mac,first_seen,last_seen,model,model_score,device_type,class_score,class_source) VALUES ('a4:00:00:00:00:91','x','x','Galaxy NX (EK-GN120)',95,'Mobile (Android)',95,'device model identifier')")
            # Same model, but the verdict came from a live-only source: untouched.
            con.execute("INSERT INTO devices(mac,first_seen,last_seen,model,model_score,device_type,class_score,class_source) VALUES ('a4:00:00:00:00:92','x','x','Galaxy NX (EK-GN120)',95,'Mobile (Android)',95,'mDNS advertisement')")
        self.assertEqual(d.reevaluate_stale_classifications(verbose=False), 1)
        with closing(sqlite3.connect(self.db)) as con, con:
            rows = dict(con.execute('SELECT mac, device_type FROM devices').fetchall())
        self.assertEqual(rows['a4:00:00:00:00:91'], 'Android Device')
        self.assertEqual(rows['a4:00:00:00:00:92'], 'Mobile (Android)')
