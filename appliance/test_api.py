"""Tests for api.py. Run with the service venv that has fastapi installed:

    .venv/bin/python -m unittest test_api.py -v

(The discovery test suite, test_discovery.py, needs scapy and runs under the
system interpreter; the two suites use different interpreters by design.)
"""
import asyncio
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta

import api

# Full devices schema, matching what discovery.py creates.
_DEVICES_SCHEMA = (
    "mac TEXT PRIMARY KEY, ip TEXT, vendor TEXT, first_seen TEXT, last_seen TEXT, "
    "status TEXT, hostname TEXT, device_type TEXT, model TEXT, dhcp_signature TEXT, "
    "class_score INTEGER, class_source TEXT, is_monitored INTEGER, last_span_seen TEXT, "
    "model_score INTEGER, model_source TEXT, session_seen INTEGER, upnp_location TEXT, "
    "vendor_class TEXT, is_ap_client INTEGER, ap_associated INTEGER, last_ap_seen TEXT, "
    "membership_source TEXT, discovered_current INTEGER, last_discovery_seen TEXT, "
    "traffic_seen INTEGER, last_traffic_seen TEXT, vendor_source TEXT"
)


class _SeededDBTest(unittest.TestCase):
    """Base: a temp devices DB and a Row-factory connection the endpoint
    functions can be called with directly (TestClient needs httpx, absent here)."""

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        con = sqlite3.connect(self.path)
        con.execute(f"CREATE TABLE devices ({_DEVICES_SCHEMA})")
        con.commit()
        con.close()
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row

    def tearDown(self):
        self.conn.close()
        os.remove(self.path)

    def insert(self, **cols):
        keys = ", ".join(cols)
        marks = ", ".join("?" for _ in cols)
        self.conn.execute(
            f"INSERT INTO devices ({keys}) VALUES ({marks})", tuple(cols.values())
        )
        self.conn.commit()


class DeviceDetailClassificationTests(_SeededDBTest):
    def test_detail_includes_classification_needles(self):
        self.insert(
            mac="72:a3:36:be:90:06", ip="192.168.1.5", device_type="Mobile (Apple)",
            model="iPhone", class_source="mDNS model (mapped identifier)", class_score=80,
            model_source="mDNS model (mapped identifier)", model_score=80,
            vendor_class="TL-SG105E", status="online", discovered_current=1,
            last_seen="2026-09-20T10:57:37",
        )
        d = api.get_device("72:a3:36:be:90:06", self.conn)
        c = d.classification
        self.assertIsNotNone(c)
        self.assertEqual(c.device_type, "Mobile (Apple)")
        self.assertEqual(c.class_source, "mDNS model (mapped identifier)")
        self.assertEqual(c.class_score, 80)
        self.assertEqual(c.model_source, "mDNS model (mapped identifier)")
        self.assertEqual(c.model_score, 80)
        # Raw evidence needle still exposed at top level.
        self.assertEqual(d.vendor_class, "TL-SG105E")
        # Backward-compat top-level field preserved.
        self.assertEqual(d.class_source, "mDNS model (mapped identifier)")

    def test_vendor_on_randomized_mac_is_inferred(self):
        self.insert(
            mac="72:a3:36:be:90:06", vendor="Apple Inc.", vendor_source=None,
            status="online", last_seen="2026-09-20T10:57:37",
        )
        d = api.get_device("72:a3:36:be:90:06", self.conn)
        self.assertEqual(d.classification.vendor_source, "inferred: private MAC")


class HealthzHeartbeatTests(_SeededDBTest):
    def test_fresh_write_not_stale(self):
        now = datetime.now().isoformat(timespec="seconds")
        self.insert(mac="a", last_seen=now, last_discovery_seen=now, last_traffic_seen=now)
        h = api.healthz(self.conn)
        self.assertTrue(h["db_available"])
        self.assertEqual(h["last_write"], now)
        self.assertLess(h["seconds_since_write"], api.HEARTBEAT_STALE_SECONDS)
        self.assertFalse(h["daemon_stale"])

    def test_old_write_is_stale(self):
        old = (datetime.now() - timedelta(seconds=api.HEARTBEAT_STALE_SECONDS + 300)).isoformat(
            timespec="seconds"
        )
        self.insert(mac="a", last_seen=old, last_discovery_seen=old, last_traffic_seen=old)
        h = api.healthz(self.conn)
        self.assertGreater(h["seconds_since_write"], api.HEARTBEAT_STALE_SECONDS)
        self.assertTrue(h["daemon_stale"])

    def test_empty_db_is_stale(self):
        h = api.healthz(self.conn)
        self.assertIsNone(h["last_write"])
        self.assertIsNone(h["seconds_since_write"])
        self.assertTrue(h["daemon_stale"])


class OnlineOnlyConsistencyTests(_SeededDBTest):
    def test_online_only_matches_status_column(self):
        self.insert(mac="a", status="online", discovered_current=1)
        self.insert(mac="b", status="observed")
        self.insert(mac="c", status="offline")
        self.insert(mac="d", status="online", ap_associated=1)
        res = api.list_devices(conn=self.conn, online_only=True, limit=100, offset=0)
        self.assertEqual(sorted(x.mac for x in res), ["a", "d"])


class EffectiveVendorSourceTests(unittest.TestCase):
    def test_randomized_null_source_becomes_inferred(self):
        # Legacy row: real vendor on a randomized MAC, vendor_source NULL.
        # An OUI never produces a vendor for a locally-administered MAC, so
        # the API must surface it as inferred rather than as certain fact.
        self.assertEqual(
            api._effective_vendor_source("72:a3:36:be:90:06", "Apple Inc.", None),
            "inferred: private MAC",
        )

    def test_real_mac_null_source_unchanged(self):
        # Genuine OUI vendor on a real MAC must stay non-inferred.
        self.assertIsNone(
            api._effective_vendor_source("28:39:5e:d7:44:0c", "Samsung Electronics", None)
        )

    def test_explicit_inferred_source_preserved(self):
        self.assertEqual(
            api._effective_vendor_source("72:a3:36:be:90:06", "Apple Inc.", "inferred: model"),
            "inferred: model",
        )

    def test_no_vendor_stays_none(self):
        self.assertIsNone(api._effective_vendor_source("72:a3:36:be:90:06", None, None))

    def test_locally_administered_bit(self):
        self.assertTrue(api._is_locally_administered_mac("02:11:22:33:44:55"))
        self.assertFalse(api._is_locally_administered_mac("dc:a6:32:11:22:33"))


def _asgi_request(method, path, headers):
    """Drive the real ASGI app (middleware included) and return
    (status, lowercased-response-headers). TestClient needs httpx, which is
    absent here, and calling endpoint functions directly bypasses middleware --
    so CORS can only be exercised by invoking the app as an ASGI callable."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    captured = {}

    async def send(message):
        if message["type"] == "http.response.start":
            captured["status"] = message["status"]
            captured["headers"] = {
                k.decode().lower(): v.decode() for k, v in message["headers"]
            }

    asyncio.run(api.app(scope, receive, send))
    return captured["status"], captured["headers"]


class CorsTests(unittest.TestCase):
    """CORS for local Flutter Web dev. Uses a seeded temp DB so an actual
    (non-preflight) request reaches a route and returns 200."""

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        con = sqlite3.connect(self.path)
        con.execute(f"CREATE TABLE devices ({_DEVICES_SCHEMA})")
        con.commit()
        con.close()
        self._orig_db_path = api.DB_PATH
        api.DB_PATH = self.path

    def tearDown(self):
        api.DB_PATH = self._orig_db_path
        os.remove(self.path)

    def test_allowed_localhost_origin_gets_acao(self):
        origin = "http://localhost:12345"
        status, headers = _asgi_request("GET", "/healthz", {"origin": origin})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("access-control-allow-origin"), origin)
        # No cookies in play, so credentials must stay off.
        self.assertNotIn("access-control-allow-credentials", headers)

    def test_allowed_loopback_ip_origin_gets_acao(self):
        origin = "http://127.0.0.1:8080"
        _, headers = _asgi_request("GET", "/healthz", {"origin": origin})
        self.assertEqual(headers.get("access-control-allow-origin"), origin)

    def test_preflight_allows_authorization_and_content_type(self):
        origin = "http://localhost:3000"
        status, headers = _asgi_request(
            "OPTIONS",
            "/devices",
            {
                "origin": origin,
                "access-control-request-method": "POST",
                "access-control-request-headers": "authorization, content-type",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("access-control-allow-origin"), origin)
        allow_headers = headers.get("access-control-allow-headers", "").lower()
        self.assertIn("authorization", allow_headers)
        self.assertIn("content-type", allow_headers)
        allow_methods = headers.get("access-control-allow-methods", "")
        self.assertIn("POST", allow_methods)

    def test_unrelated_origin_is_not_allowed(self):
        status, headers = _asgi_request(
            "GET", "/healthz", {"origin": "http://evil.example.com"}
        )
        self.assertEqual(status, 200)  # request still served; just no CORS grant
        self.assertNotIn("access-control-allow-origin", headers)

    def test_localhost_lookalike_origin_is_not_allowed(self):
        # Anchored regex must reject a domain that merely starts with localhost.
        _, headers = _asgi_request(
            "GET", "/healthz", {"origin": "http://localhost.evil.com"}
        )
        self.assertNotIn("access-control-allow-origin", headers)


if __name__ == "__main__":
    unittest.main()
