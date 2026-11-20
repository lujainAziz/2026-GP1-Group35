"""Tests for api.py. Run with the service venv that has fastapi installed:

    .venv/bin/python -m unittest test_api.py -v

(The discovery test suite, test_discovery.py, needs scapy and runs under the
system interpreter; the two suites use different interpreters by design.)
"""
import asyncio
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from collections import namedtuple
from datetime import datetime, timedelta

import alert_text
import api

# Full devices schema, matching what discovery.py creates.
_DEVICES_SCHEMA = (
    "mac TEXT PRIMARY KEY, ip TEXT, vendor TEXT, first_seen TEXT, last_seen TEXT, "
    "status TEXT, hostname TEXT, device_type TEXT, model TEXT, dhcp_signature TEXT, "
    "class_score INTEGER, class_source TEXT, is_monitored INTEGER, last_span_seen TEXT, "
    "model_score INTEGER, model_source TEXT, session_seen INTEGER, upnp_location TEXT, "
    "vendor_class TEXT, is_ap_client INTEGER, ap_associated INTEGER, last_ap_seen TEXT, "
    "membership_source TEXT, discovered_current INTEGER, last_discovery_seen TEXT, "
    "traffic_seen INTEGER, last_traffic_seen TEXT, vendor_source TEXT, "
    "user_name TEXT, "
    "last_ipv4 TEXT, last_ipv6_global TEXT, last_ipv6_ll TEXT, "
    "last_monitored_seen TEXT, "
    "trusted INTEGER NOT NULL DEFAULT 0"
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


class ModelDisplayFallbackTests(_SeededDBTest):
    """Read-time marketing-name fallback (_shown_model): a known raw model code
    is shown as "Marketing Name (CODE)"; an existing name or an empty value is
    left exactly as stored, and the DB column is never rewritten."""

    def test_raw_code_becomes_name_in_list(self):
        self.insert(mac="aa:bb:cc:dd:ee:10", status="online", model="J720AP")
        devices = api.list_devices(conn=self.conn, limit=100, offset=0)
        self.assertEqual(devices[0].model, "iPad Pro 13-inch (M4) (J720AP)")

    def test_raw_code_becomes_name_in_detail(self):
        self.insert(mac="aa:bb:cc:dd:ee:11", status="online", model="SM-G991B")
        d = api.get_device("aa:bb:cc:dd:ee:11", self.conn)
        self.assertEqual(d.model, "Galaxy S21 5G (SM-G991B)")
        # The classification needle shows the same friendly name, not the raw code.
        self.assertEqual(d.classification.model, "Galaxy S21 5G (SM-G991B)")

    def test_existing_name_stays_unchanged(self):
        # "Pixel 10" is already its own marketing name: model_db returns nothing,
        # so the stored value is passed through untouched.
        self.insert(mac="aa:bb:cc:dd:ee:12", status="online", model="Pixel 10")
        devices = api.list_devices(conn=self.conn, limit=100, offset=0)
        self.assertEqual(devices[0].model, "Pixel 10")
        d = api.get_device("aa:bb:cc:dd:ee:12", self.conn)
        self.assertEqual(d.model, "Pixel 10")

    def test_empty_model_stays_empty(self):
        self.insert(mac="aa:bb:cc:dd:ee:13", status="online", model="")
        devices = api.list_devices(conn=self.conn, limit=100, offset=0)
        self.assertEqual(devices[0].model, "")

    def test_null_model_stays_null(self):
        self.insert(mac="aa:bb:cc:dd:ee:14", status="online")  # model column NULL
        d = api.get_device("aa:bb:cc:dd:ee:14", self.conn)
        self.assertIsNone(d.model)

    def test_stored_column_is_not_rewritten(self):
        self.insert(mac="aa:bb:cc:dd:ee:15", status="online", model="J720AP")
        api.get_device("aa:bb:cc:dd:ee:15", self.conn)
        stored = self.conn.execute(
            "SELECT model FROM devices WHERE mac = ?", ("aa:bb:cc:dd:ee:15",)
        ).fetchone()[0]
        self.assertEqual(stored, "J720AP")


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
    def test_online_only_matches_displayed_presence(self):
        self.insert(mac="a", status="online", discovered_current=1)
        self.insert(mac="b", status="observed")
        self.insert(mac="c", status="offline")
        self.insert(mac="d", status="online", ap_associated=1)
        res = api.list_devices(conn=self.conn, online_only=True, limit=100, offset=0)
        self.assertEqual(sorted(x.mac for x in res), ["a", "b", "d"])


def _seconds_ago(seconds):
    """A timestamp in the format discovery writes (server-local naive ISO)."""
    return (datetime.now() - timedelta(seconds=seconds)).isoformat(timespec="seconds")


class MonitoredStateTests(_SeededDBTest):
    """The API exposes recent capture coverage (last_monitored_seen within the
    window), not presence and not the never-reset is_monitored flag."""

    def test_monitored_true_in_device_list(self):
        self.insert(mac="aa:bb:cc:dd:ee:01", status="online", is_monitored=1,
                    last_monitored_seen=_seconds_ago(5))
        devices = api.list_devices(conn=self.conn, limit=100, offset=0)
        self.assertEqual(len(devices), 1)
        self.assertIs(devices[0].monitored, True)
        self.assertEqual(devices[0].status, "online")

    def test_monitored_false_in_device_list(self):
        self.insert(mac="aa:bb:cc:dd:ee:02", status="online", is_monitored=0)
        devices = api.list_devices(conn=self.conn, limit=100, offset=0)
        self.assertEqual(len(devices), 1)
        self.assertIs(devices[0].monitored, False)
        self.assertEqual(devices[0].status, "online")

    def test_monitored_true_in_device_detail(self):
        self.insert(mac="aa:bb:cc:dd:ee:03", status="offline", is_monitored=1,
                    last_monitored_seen=_seconds_ago(5))
        device = api.get_device("aa:bb:cc:dd:ee:03", self.conn)
        self.assertIs(device.monitored, True)
        self.assertEqual(device.status, "offline")

    def test_monitored_false_in_device_detail(self):
        self.insert(mac="aa:bb:cc:dd:ee:04", status="online", is_monitored=0)
        device = api.get_device("aa:bb:cc:dd:ee:04", self.conn)
        self.assertIs(device.monitored, False)
        self.assertEqual(device.status, "online")

    def test_monitored_false_when_older_than_window(self):
        old = _seconds_ago(api.MONITORED_WINDOW_SECONDS + 60)
        self.insert(mac="aa:bb:cc:dd:ee:06", status="online", is_monitored=1,
                    last_monitored_seen=old)
        devices = api.list_devices(conn=self.conn, limit=100, offset=0)
        self.assertIs(devices[0].monitored, False)
        device = api.get_device("aa:bb:cc:dd:ee:06", self.conn)
        self.assertIs(device.monitored, False)

    def test_monitored_false_when_never_seen_even_if_flag_set(self):
        # Legacy row: is_monitored=1 but no last_monitored_seen yet.
        self.insert(mac="aa:bb:cc:dd:ee:07", status="online", is_monitored=1)
        devices = api.list_devices(conn=self.conn, limit=100, offset=0)
        self.assertIs(devices[0].monitored, False)
        device = api.get_device("aa:bb:cc:dd:ee:07", self.conn)
        self.assertIs(device.monitored, False)

    def test_offline_keeps_monitored_when_seen_close_to_last_seen(self):
        # PBI-04: measured from last_seen, not now, once the device is Offline.
        self.insert(mac="aa:bb:cc:dd:ee:09", status="online", is_monitored=1,
                    last_seen=_seconds_ago(600), last_monitored_seen=_seconds_ago(605))
        devices = api.list_devices(conn=self.conn, limit=100, offset=0)
        self.assertEqual(devices[0].presence, "offline")
        self.assertIs(devices[0].monitored, True)
        device = api.get_device("aa:bb:cc:dd:ee:09", self.conn)
        self.assertIs(device.monitored, True)

    def test_offline_stays_not_monitored_when_seen_long_before_last_seen(self):
        old = _seconds_ago(600 + api.MONITORED_WINDOW_SECONDS + 60)
        self.insert(mac="aa:bb:cc:dd:ee:0a", status="offline", is_monitored=1,
                    last_seen=_seconds_ago(600), last_monitored_seen=old)
        devices = api.list_devices(conn=self.conn, limit=100, offset=0)
        self.assertIs(devices[0].monitored, False)
        device = api.get_device("aa:bb:cc:dd:ee:0a", self.conn)
        self.assertIs(device.monitored, False)

    def test_offline_without_last_monitored_seen_is_not_monitored(self):
        self.insert(mac="aa:bb:cc:dd:ee:0b", status="offline", is_monitored=1,
                    last_seen=_seconds_ago(600))
        devices = api.list_devices(conn=self.conn, limit=100, offset=0)
        self.assertIs(devices[0].monitored, False)
        device = api.get_device("aa:bb:cc:dd:ee:0b", self.conn)
        self.assertIs(device.monitored, False)

    def test_default_window_is_120_seconds(self):
        self.assertEqual(api.MONITORED_WINDOW_SECONDS, 120)

    def test_window_comes_from_env_setting(self):
        import importlib
        from unittest.mock import patch
        self.addCleanup(importlib.reload, api)  # restore the default window
        with patch.dict(os.environ, {"ASSAS_MONITORED_WINDOW_SECONDS": "600"}):
            importlib.reload(api)
        self.assertEqual(api.MONITORED_WINDOW_SECONDS, 600)
        # 300s ago: outside the 120s default, inside the configured 600s.
        self.insert(mac="aa:bb:cc:dd:ee:08", status="online", is_monitored=1,
                    last_monitored_seen=_seconds_ago(300))
        devices = api.list_devices(conn=self.conn, limit=100, offset=0)
        self.assertIs(devices[0].monitored, True)
        device = api.get_device("aa:bb:cc:dd:ee:08", self.conn)
        self.assertIs(device.monitored, True)


class PresenceStateTests(_SeededDBTest):
    """User-facing presence, derived from the stored status column: only
    'online' maps to "online"; observed/candidate/offline map to "offline".
    status itself is always left untouched (backward compatibility)."""

    def test_online_is_present_in_device_list(self):
        self.insert(mac="aa:bb:cc:dd:ee:11", status="online")
        devices = api.list_devices(conn=self.conn, limit=100, offset=0)
        self.assertEqual(devices[0].presence, "online")
        self.assertEqual(devices[0].status, "online")

    def test_observed_is_online_in_device_list(self):
        self.insert(mac="aa:bb:cc:dd:ee:12", status="observed")
        devices = api.list_devices(conn=self.conn, limit=100, offset=0)
        self.assertEqual(devices[0].presence, "online")
        self.assertEqual(devices[0].status, "observed")

    def test_offline_is_offline_in_device_list(self):
        self.insert(mac="aa:bb:cc:dd:ee:13", status="offline")
        devices = api.list_devices(conn=self.conn, limit=100, offset=0)
        self.assertEqual(devices[0].presence, "offline")
        self.assertEqual(devices[0].status, "offline")

    def test_online_is_present_in_device_detail(self):
        self.insert(mac="aa:bb:cc:dd:ee:14", status="online")
        device = api.get_device("aa:bb:cc:dd:ee:14", self.conn)
        self.assertEqual(device.presence, "online")
        self.assertEqual(device.status, "online")

    def test_observed_is_online_in_device_detail(self):
        self.insert(mac="aa:bb:cc:dd:ee:15", status="observed")
        device = api.get_device("aa:bb:cc:dd:ee:15", self.conn)
        self.assertEqual(device.presence, "online")
        self.assertEqual(device.status, "observed")


class PresenceJSONResponseTests(_SeededDBTest):
    """presence appears in both serialized endpoints and coexists with the
    unchanged status, trusted, and monitored fields."""

    def test_presence_in_json_responses(self):
        self.insert(mac="aa:bb:cc:dd:ee:16", status="online",
                    trusted=1, is_monitored=1, last_monitored_seen=_seconds_ago(5))
        self.insert(mac="aa:bb:cc:dd:ee:17", status="observed",
                    trusted=0, is_monitored=0)
        original_path = api.DB_PATH
        api.DB_PATH = self.path
        try:
            list_response = _asgi_request("GET", "/devices", {})
            self.assertEqual(list_response.status, 200)
            by_mac = {d["mac"]: d for d in json.loads(list_response.body)}
            self.assertEqual(by_mac["aa:bb:cc:dd:ee:16"]["presence"], "online")
            self.assertEqual(by_mac["aa:bb:cc:dd:ee:16"]["status"], "online")
            self.assertIs(by_mac["aa:bb:cc:dd:ee:16"]["trusted"], True)
            self.assertIs(by_mac["aa:bb:cc:dd:ee:16"]["monitored"], True)
            self.assertEqual(by_mac["aa:bb:cc:dd:ee:17"]["presence"], "online")
            self.assertEqual(by_mac["aa:bb:cc:dd:ee:17"]["status"], "observed")

            detail_response = _asgi_request(
                "GET", "/devices/aa:bb:cc:dd:ee:17", {})
            self.assertEqual(detail_response.status, 200)
            detail = json.loads(detail_response.body)
            self.assertEqual(detail["presence"], "online")
            self.assertEqual(detail["status"], "observed")
            self.assertIs(detail["trusted"], False)
            self.assertIs(detail["monitored"], False)
        finally:
            api.DB_PATH = original_path


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


Resp = namedtuple("Resp", ["status", "headers", "body"])


def _asgi_request(method, path, headers, body=b"", client=("127.0.0.1", 12345)):
    """Drive the real ASGI app (middleware + routing) and return a Resp with
    status, lowercased response headers, and the raw body bytes. TestClient
    needs httpx, which is absent here, and calling endpoint functions directly
    bypasses middleware and request-body validation -- so CORS and the PUT
    contract can only be exercised by invoking the app as an ASGI callable."""
    if isinstance(body, str):
        body = body.encode()
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
        "client": client,
        "server": ("testserver", 80),
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    captured = {}
    chunks = []

    async def send(message):
        if message["type"] == "http.response.start":
            captured["status"] = message["status"]
            captured["headers"] = {
                k.decode().lower(): v.decode() for k, v in message["headers"]
            }
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    asyncio.run(api.app(scope, receive, send))
    return Resp(captured["status"], captured["headers"], b"".join(chunks))


def _run_lifespan_startup():
    """Drive the real ASGI lifespan protocol (startup then shutdown) so tests
    exercise the wired startup path -- i.e. ensure_trusted_column() -- exactly
    as uvicorn would, not by calling the helper directly."""
    async def _drive():
        queue = asyncio.Queue()
        await queue.put({"type": "lifespan.startup"})
        await queue.put({"type": "lifespan.shutdown"})

        async def receive():
            return await queue.get()

        async def send(_message):
            pass

        await api.app({"type": "lifespan", "asgi": {"version": "3.0"}}, receive, send)

    asyncio.run(_drive())


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
        r = _asgi_request("GET", "/healthz", {"origin": origin})
        self.assertEqual(r.status, 200)
        self.assertEqual(r.headers.get("access-control-allow-origin"), origin)
        # No cookies in play, so credentials must stay off.
        self.assertNotIn("access-control-allow-credentials", r.headers)

    def test_allowed_loopback_ip_origin_gets_acao(self):
        origin = "http://127.0.0.1:8080"
        r = _asgi_request("GET", "/healthz", {"origin": origin})
        self.assertEqual(r.headers.get("access-control-allow-origin"), origin)

    def test_preflight_allows_authorization_and_content_type(self):
        origin = "http://localhost:3000"
        r = _asgi_request(
            "OPTIONS",
            "/devices",
            {
                "origin": origin,
                "access-control-request-method": "POST",
                "access-control-request-headers": "authorization, content-type",
            },
        )
        self.assertEqual(r.status, 200)
        self.assertEqual(r.headers.get("access-control-allow-origin"), origin)
        allow_headers = r.headers.get("access-control-allow-headers", "").lower()
        self.assertIn("authorization", allow_headers)
        self.assertIn("content-type", allow_headers)
        allow_methods = r.headers.get("access-control-allow-methods", "")
        self.assertIn("POST", allow_methods)

    def test_unrelated_origin_is_not_allowed(self):
        r = _asgi_request("GET", "/healthz", {"origin": "http://evil.example.com"})
        self.assertEqual(r.status, 200)  # request still served; just no CORS grant
        self.assertNotIn("access-control-allow-origin", r.headers)

    def test_localhost_lookalike_origin_is_not_allowed(self):
        # Anchored regex must reject a domain that merely starts with localhost.
        r = _asgi_request("GET", "/healthz", {"origin": "http://localhost.evil.com"})
        self.assertNotIn("access-control-allow-origin", r.headers)


class TrustStateTests(unittest.TestCase):
    """PUT /devices/{mac}/trust and the trusted field on GET. Uses a seeded
    temp DB with api.DB_PATH pointed at it, since the trust write opens its own
    writable connection rather than taking an injected one."""

    JSON = {"content-type": "application/json"}

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        con = sqlite3.connect(self.path)
        con.execute(f"CREATE TABLE devices ({_DEVICES_SCHEMA})")
        con.execute(
            "INSERT INTO devices (mac, ip, status, last_seen) VALUES "
            "('aa:bb:cc:dd:ee:ff', '192.168.1.9', 'online', '2026-09-20T10:00:00')"
        )
        con.commit()
        con.close()
        self._orig_db_path = api.DB_PATH
        api.DB_PATH = self.path

    def tearDown(self):
        api.DB_PATH = self._orig_db_path
        os.remove(self.path)

    def _stored_trusted(self, mac):
        con = sqlite3.connect(self.path)
        try:
            return con.execute(
                "SELECT trusted FROM devices WHERE mac=?", (mac,)
            ).fetchone()[0]
        finally:
            con.close()

    def test_new_row_defaults_false(self):
        # The seeded row never set trusted, so the column default must apply.
        self.assertEqual(self._stored_trusted("aa:bb:cc:dd:ee:ff"), 0)
        r = _asgi_request("GET", "/devices/aa:bb:cc:dd:ee:ff", {})
        self.assertEqual(r.status, 200)
        self.assertIs(json.loads(r.body)["trusted"], False)

    def test_put_true_then_idempotent(self):
        for _ in range(2):  # idempotent true -> true
            r = _asgi_request(
                "PUT", "/devices/aa:bb:cc:dd:ee:ff/trust",
                self.JSON, body='{"trusted": true}',
            )
            self.assertEqual(r.status, 200)
            self.assertEqual(
                json.loads(r.body), {"mac": "aa:bb:cc:dd:ee:ff", "trusted": True}
            )
            self.assertEqual(self._stored_trusted("aa:bb:cc:dd:ee:ff"), 1)

    def test_put_false_then_idempotent(self):
        _asgi_request(
            "PUT", "/devices/aa:bb:cc:dd:ee:ff/trust",
            self.JSON, body='{"trusted": true}',
        )
        for _ in range(2):  # idempotent false -> false
            r = _asgi_request(
                "PUT", "/devices/aa:bb:cc:dd:ee:ff/trust",
                self.JSON, body='{"trusted": false}',
            )
            self.assertEqual(r.status, 200)
            self.assertIs(json.loads(r.body)["trusted"], False)
            self.assertEqual(self._stored_trusted("aa:bb:cc:dd:ee:ff"), 0)

    def _full_row(self):
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        try:
            return dict(con.execute(
                "SELECT * FROM devices WHERE mac='aa:bb:cc:dd:ee:ff'"
            ).fetchone())
        finally:
            con.close()

    def test_put_only_touches_trusted_column(self):
        before = self._full_row()
        _asgi_request(
            "PUT", "/devices/aa:bb:cc:dd:ee:ff/trust",
            self.JSON, body='{"trusted": true}',
        )
        after = self._full_row()
        changed = {k for k in before if before[k] != after[k]}
        self.assertEqual(changed, {"trusted"})

    def test_put_normalizes_mac_and_echoes_normalized(self):
        r = _asgi_request(
            "PUT", "/devices/AA-BB-CC-DD-EE-FF/trust",
            self.JSON, body='{"trusted": true}',
        )
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.body)["mac"], "aa:bb:cc:dd:ee:ff")

    def test_put_nonexistent_mac_404_creates_nothing(self):
        r = _asgi_request(
            "PUT", "/devices/00:00:00:00:00:01/trust",
            self.JSON, body='{"trusted": true}',
        )
        self.assertEqual(r.status, 404)
        con = sqlite3.connect(self.path)
        try:
            n = con.execute(
                "SELECT COUNT(*) FROM devices WHERE mac='00:00:00:00:00:01'"
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(n, 0)

    def test_put_missing_field_is_422(self):
        r = _asgi_request(
            "PUT", "/devices/aa:bb:cc:dd:ee:ff/trust", self.JSON, body="{}"
        )
        self.assertEqual(r.status, 422)
        self.assertEqual(self._stored_trusted("aa:bb:cc:dd:ee:ff"), 0)

    def test_put_non_boolean_field_is_422(self):
        # StrictBool rejects not just garbage ("maybe") but also values pydantic
        # would otherwise coerce: integer 1 and the string "true". None may
        # change the stored state.
        for raw in ('"maybe"', "1", '"true"'):
            with self.subTest(raw=raw):
                r = _asgi_request(
                    "PUT", "/devices/aa:bb:cc:dd:ee:ff/trust",
                    self.JSON, body='{"trusted": %s}' % raw,
                )
                self.assertEqual(r.status, 422)
                self.assertEqual(self._stored_trusted("aa:bb:cc:dd:ee:ff"), 0)

    def test_get_list_exposes_boolean(self):
        _asgi_request(
            "PUT", "/devices/aa:bb:cc:dd:ee:ff/trust",
            self.JSON, body='{"trusted": true}',
        )
        r = _asgi_request("GET", "/devices", {})
        self.assertEqual(r.status, 200)
        dev = next(d for d in json.loads(r.body) if d["mac"] == "aa:bb:cc:dd:ee:ff")
        self.assertIs(dev["trusted"], True)


class MonitoredJSONResponseTests(_SeededDBTest):
    """Check actual serialized GET responses and existing trusted/status fields."""

    def test_monitored_in_json_responses(self):
        self.insert(mac="aa:bb:cc:dd:ee:05", status="online", trusted=1, is_monitored=1,
                    last_monitored_seen=_seconds_ago(5))
        original_path = api.DB_PATH
        api.DB_PATH = self.path
        try:
            list_response = _asgi_request("GET", "/devices", {})
            self.assertEqual(list_response.status, 200)
            device = next(d for d in json.loads(list_response.body)
                          if d["mac"] == "aa:bb:cc:dd:ee:05")
            self.assertIs(device["monitored"], True)
            self.assertIs(device["trusted"], True)
            self.assertEqual(device["status"], "online")

            detail_response = _asgi_request("GET", "/devices/aa:bb:cc:dd:ee:05", {})
            self.assertEqual(detail_response.status, 200)
            detail = json.loads(detail_response.body)
            self.assertIs(detail["monitored"], True)
            self.assertIs(detail["trusted"], True)
            self.assertEqual(detail["status"], "online")
        finally:
            api.DB_PATH = original_path


class TrustSchemaCompatTests(unittest.TestCase):
    """Deployment safety: the API must not break when it boots against a
    pre-migration DB (no trusted column) before discovery.py is restarted."""

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        # Pre-migration schema: every current column EXCEPT trusted.
        pre = _DEVICES_SCHEMA.rsplit(",", 1)[0]
        self.assertNotIn("trusted", pre)
        con = sqlite3.connect(self.path)
        con.execute(f"CREATE TABLE devices ({pre})")
        con.execute(
            "INSERT INTO devices (mac, status, last_seen) VALUES "
            "('aa:bb:cc:dd:ee:ff', 'online', '2026-09-20T10:00:00')"
        )
        con.commit()
        con.close()
        self._orig_db_path = api.DB_PATH
        api.DB_PATH = self.path

    def tearDown(self):
        api.DB_PATH = self._orig_db_path
        os.remove(self.path)

    def test_startup_adds_column_and_get_does_not_break(self):
        # Before startup the column is absent.
        con = sqlite3.connect(self.path)
        cols = {r[1] for r in con.execute("PRAGMA table_info(devices)")}
        con.close()
        self.assertNotIn("trusted", cols)

        _run_lifespan_startup()  # the wired startup path runs ensure_trusted_column

        r = _asgi_request("GET", "/devices", {})
        self.assertEqual(r.status, 200)
        dev = next(d for d in json.loads(r.body) if d["mac"] == "aa:bb:cc:dd:ee:ff")
        self.assertIs(dev["trusted"], False)  # backfilled default

    def test_ensure_is_idempotent_and_safe_when_db_absent(self):
        _run_lifespan_startup()
        _run_lifespan_startup()  # second run must be a harmless no-op
        api.DB_PATH = self.path + ".nonexistent"
        api.ensure_trusted_column()  # missing DB must not raise or create a file
        self.assertFalse(os.path.exists(self.path + ".nonexistent"))


class DeviceNameTests(unittest.TestCase):
    """PUT /devices/{mac}/name and the user_name field on GET. Like the trust
    tests, uses a seeded temp DB with api.DB_PATH pointed at it, since the write
    opens its own writable connection rather than taking an injected one."""

    JSON = {"content-type": "application/json"}

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        con = sqlite3.connect(self.path)
        con.execute(f"CREATE TABLE devices ({_DEVICES_SCHEMA})")
        con.execute(
            "INSERT INTO devices (mac, ip, status, last_seen) VALUES "
            "('aa:bb:cc:dd:ee:ff', '192.168.1.9', 'online', '2026-09-20T10:00:00')"
        )
        con.commit()
        con.close()
        self._orig_db_path = api.DB_PATH
        api.DB_PATH = self.path

    def tearDown(self):
        api.DB_PATH = self._orig_db_path
        os.remove(self.path)

    def _stored_name(self, mac):
        con = sqlite3.connect(self.path)
        try:
            return con.execute(
                "SELECT user_name FROM devices WHERE mac=?", (mac,)
            ).fetchone()[0]
        finally:
            con.close()

    def _put(self, body, mac="aa:bb:cc:dd:ee:ff"):
        return _asgi_request("PUT", f"/devices/{mac}/name", self.JSON, body=body)

    def test_new_row_defaults_null(self):
        self.assertIsNone(self._stored_name("aa:bb:cc:dd:ee:ff"))
        r = _asgi_request("GET", "/devices/aa:bb:cc:dd:ee:ff", {})
        self.assertEqual(r.status, 200)
        self.assertIsNone(json.loads(r.body)["user_name"])

    def test_put_sets_name_and_is_idempotent(self):
        for _ in range(2):
            r = self._put('{"name": "Living Room TV"}')
            self.assertEqual(r.status, 200)
            self.assertEqual(
                json.loads(r.body),
                {"mac": "aa:bb:cc:dd:ee:ff", "user_name": "Living Room TV"},
            )
            self.assertEqual(self._stored_name("aa:bb:cc:dd:ee:ff"), "Living Room TV")

    def test_put_trims_surrounding_whitespace(self):
        r = self._put('{"name": "  Kitchen Hub  "}')
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.body)["user_name"], "Kitchen Hub")
        self.assertEqual(self._stored_name("aa:bb:cc:dd:ee:ff"), "Kitchen Hub")

    def test_null_clears_name(self):
        self._put('{"name": "Temp"}')
        r = self._put('{"name": null}')
        self.assertEqual(r.status, 200)
        self.assertIsNone(json.loads(r.body)["user_name"])
        self.assertIsNone(self._stored_name("aa:bb:cc:dd:ee:ff"))

    def test_empty_and_whitespace_clear_name(self):
        for raw in ('""', '"   "'):
            with self.subTest(raw=raw):
                self._put('{"name": "Temp"}')
                r = self._put('{"name": %s}' % raw)
                self.assertEqual(r.status, 200)
                self.assertIsNone(json.loads(r.body)["user_name"])
                self.assertIsNone(self._stored_name("aa:bb:cc:dd:ee:ff"))

    def test_exactly_40_chars_after_trim_is_accepted(self):
        name = "x" * 40
        r = self._put('{"name": "  %s  "}' % name)
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.body)["user_name"], name)
        self.assertEqual(self._stored_name("aa:bb:cc:dd:ee:ff"), name)

    def test_41_chars_is_422_and_stores_nothing(self):
        r = self._put('{"name": "%s"}' % ("x" * 41))
        self.assertEqual(r.status, 422)
        self.assertIsNone(self._stored_name("aa:bb:cc:dd:ee:ff"))

    def test_missing_field_is_422(self):
        r = self._put("{}")
        self.assertEqual(r.status, 422)
        self.assertIsNone(self._stored_name("aa:bb:cc:dd:ee:ff"))

    def test_non_string_is_422(self):
        for raw in ("5", "true", "[]"):
            with self.subTest(raw=raw):
                r = self._put('{"name": %s}' % raw)
                self.assertEqual(r.status, 422)
                self.assertIsNone(self._stored_name("aa:bb:cc:dd:ee:ff"))

    def test_nonexistent_mac_404_creates_nothing(self):
        r = self._put('{"name": "Nope"}', mac="00:00:00:00:00:01")
        self.assertEqual(r.status, 404)
        con = sqlite3.connect(self.path)
        try:
            n = con.execute(
                "SELECT COUNT(*) FROM devices WHERE mac='00:00:00:00:00:01'"
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(n, 0)

    def test_put_normalizes_mac_and_echoes_normalized(self):
        r = self._put('{"name": "Hub"}', mac="AA-BB-CC-DD-EE-FF")
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.body)["mac"], "aa:bb:cc:dd:ee:ff")

    def _full_row(self):
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        try:
            return dict(con.execute(
                "SELECT * FROM devices WHERE mac='aa:bb:cc:dd:ee:ff'"
            ).fetchone())
        finally:
            con.close()

    def test_put_only_touches_user_name_column(self):
        before = self._full_row()
        self._put('{"name": "Hub"}')
        after = self._full_row()
        changed = {k for k in before if before[k] != after[k]}
        self.assertEqual(changed, {"user_name"})

    def test_get_list_exposes_user_name(self):
        self._put('{"name": "Hub"}')
        r = _asgi_request("GET", "/devices", {})
        self.assertEqual(r.status, 200)
        dev = next(d for d in json.loads(r.body) if d["mac"] == "aa:bb:cc:dd:ee:ff")
        self.assertEqual(dev["user_name"], "Hub")


class UserNameSchemaCompatTests(unittest.TestCase):
    """Deployment safety: the API must not break when it boots against a DB that
    predates the user_name column, before discovery.py is restarted."""

    JSON = {"content-type": "application/json"}

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        # Pre-migration schema: the full current schema minus user_name.
        pre = _DEVICES_SCHEMA.replace("user_name TEXT, ", "", 1)
        self.assertNotIn("user_name", pre)
        con = sqlite3.connect(self.path)
        con.execute(f"CREATE TABLE devices ({pre})")
        con.execute(
            "INSERT INTO devices (mac, status, last_seen) VALUES "
            "('aa:bb:cc:dd:ee:ff', 'online', '2026-09-20T10:00:00')"
        )
        con.commit()
        con.close()
        self._orig_db_path = api.DB_PATH
        api.DB_PATH = self.path

    def tearDown(self):
        api.DB_PATH = self._orig_db_path
        os.remove(self.path)

    def _cols(self):
        con = sqlite3.connect(self.path)
        try:
            return {r[1] for r in con.execute("PRAGMA table_info(devices)")}
        finally:
            con.close()

    def test_startup_adds_column_and_get_does_not_break(self):
        self.assertNotIn("user_name", self._cols())
        _run_lifespan_startup()  # the wired startup path runs ensure_user_name_column
        self.assertIn("user_name", self._cols())
        r = _asgi_request("GET", "/devices", {})
        self.assertEqual(r.status, 200)
        dev = next(d for d in json.loads(r.body) if d["mac"] == "aa:bb:cc:dd:ee:ff")
        self.assertIsNone(dev["user_name"])  # backfilled NULL

    def test_put_name_after_backfill(self):
        _run_lifespan_startup()
        r = _asgi_request(
            "PUT", "/devices/aa:bb:cc:dd:ee:ff/name", self.JSON, body='{"name": "Hub"}'
        )
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.body)["user_name"], "Hub")

    def test_ensure_is_idempotent_and_safe_when_db_absent(self):
        _run_lifespan_startup()
        _run_lifespan_startup()  # second run must be a harmless no-op
        api.DB_PATH = self.path + ".nonexistent"
        api.ensure_user_name_column()  # missing DB must not raise or create a file
        self.assertFalse(os.path.exists(self.path + ".nonexistent"))


class SettingsStateTests(unittest.TestCase):
    """GET/PUT /settings. Seeds a temp DB with the app_settings table (no row)
    and points api.DB_PATH at it, since the write opens its own connection."""

    JSON = {"content-type": "application/json"}

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        con = sqlite3.connect(self.path)
        con.execute(api._APP_SETTINGS_DDL)
        con.commit()
        con.close()
        self._orig_db_path = api.DB_PATH
        api.DB_PATH = self.path

    def tearDown(self):
        api.DB_PATH = self._orig_db_path
        os.remove(self.path)

    def _stored(self):
        con = sqlite3.connect(self.path)
        try:
            row = con.execute(
                "SELECT active_probes FROM app_settings WHERE id = 1"
            ).fetchone()
            return None if row is None else row[0]
        finally:
            con.close()

    def test_default_false_when_no_row(self):
        self.assertIsNone(self._stored())
        r = _asgi_request("GET", "/settings", {})
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.body), {"active_probes": False})

    def test_get_returns_json_boolean(self):
        _asgi_request("PUT", "/settings", self.JSON, body='{"active_probes": true}')
        r = _asgi_request("GET", "/settings", {})
        self.assertIsInstance(json.loads(r.body)["active_probes"], bool)

    def test_put_true_persists_and_idempotent(self):
        for _ in range(2):
            r = _asgi_request(
                "PUT", "/settings", self.JSON, body='{"active_probes": true}'
            )
            self.assertEqual(r.status, 200)
            self.assertEqual(json.loads(r.body), {"active_probes": True})
            self.assertEqual(self._stored(), 1)

    def test_put_false_persists_and_idempotent(self):
        _asgi_request("PUT", "/settings", self.JSON, body='{"active_probes": true}')
        for _ in range(2):
            r = _asgi_request(
                "PUT", "/settings", self.JSON, body='{"active_probes": false}'
            )
            self.assertEqual(r.status, 200)
            self.assertIs(json.loads(r.body)["active_probes"], False)
            self.assertEqual(self._stored(), 0)

    def test_get_reflects_put(self):
        _asgi_request("PUT", "/settings", self.JSON, body='{"active_probes": true}')
        r = _asgi_request("GET", "/settings", {})
        self.assertIs(json.loads(r.body)["active_probes"], True)

    def test_put_missing_field_is_422(self):
        r = _asgi_request("PUT", "/settings", self.JSON, body="{}")
        self.assertEqual(r.status, 422)
        self.assertIsNone(self._stored())  # no write

    def test_put_non_boolean_is_422(self):
        # StrictBool rejects coercible values too: integer 1 and the string "true".
        for raw in ('"maybe"', "1", '"true"'):
            with self.subTest(raw=raw):
                r = _asgi_request(
                    "PUT", "/settings", self.JSON,
                    body='{"active_probes": %s}' % raw,
                )
                self.assertEqual(r.status, 422)
                self.assertIsNone(self._stored())


class SettingsSchemaCompatTests(unittest.TestCase):
    """Deployment safety: GET/PUT /settings must work when the API boots against
    a DB that has no app_settings table yet (discovery not restarted)."""

    JSON = {"content-type": "application/json"}

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        # Valid DB, but only a devices table -- no app_settings yet.
        con = sqlite3.connect(self.path)
        con.execute(f"CREATE TABLE devices ({_DEVICES_SCHEMA})")
        con.commit()
        con.close()
        self._orig_db_path = api.DB_PATH
        api.DB_PATH = self.path

    def tearDown(self):
        api.DB_PATH = self._orig_db_path
        os.remove(self.path)

    def _has_table(self):
        con = sqlite3.connect(self.path)
        try:
            return con.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='app_settings'"
            ).fetchone() is not None
        finally:
            con.close()

    def test_get_before_table_returns_default_false(self):
        self.assertFalse(self._has_table())
        r = _asgi_request("GET", "/settings", {})
        self.assertEqual(r.status, 200)
        self.assertIs(json.loads(r.body)["active_probes"], False)

    def test_startup_creates_table(self):
        self.assertFalse(self._has_table())
        _run_lifespan_startup()
        self.assertTrue(self._has_table())
        r = _asgi_request("GET", "/settings", {})
        self.assertEqual(r.status, 200)

    def test_put_creates_table_when_missing(self):
        self.assertFalse(self._has_table())
        r = _asgi_request(
            "PUT", "/settings", self.JSON, body='{"active_probes": true}'
        )
        self.assertEqual(r.status, 200)
        self.assertTrue(self._has_table())
        r2 = _asgi_request("GET", "/settings", {})
        self.assertIs(json.loads(r2.body)["active_probes"], True)

    def test_ensure_is_idempotent_and_safe_when_db_absent(self):
        _run_lifespan_startup()
        _run_lifespan_startup()  # second run must be a harmless no-op
        api.DB_PATH = self.path + ".nonexistent"
        api.ensure_settings_table()  # missing DB must not raise or create a file
        self.assertFalse(os.path.exists(self.path + ".nonexistent"))

class PairingCodeTests(unittest.TestCase):
    """GET /pairing/code: only the appliance itself (the display) may read it."""

    LAN_CLIENT = ("192.168.1.50", 5555)

    def setUp(self):
        # Start every test with no code, as on a fresh start.
        api._pairing_code = None
        api._pairing_expires_at = None

    def test_local_request_gets_valid_code(self):
        r = _asgi_request("GET", "/pairing/code", {})
        self.assertEqual(r.status, 200)
        data = json.loads(r.body)
        self.assertEqual(len(data["code"]), api.PAIRING_CODE_LENGTH)
        self.assertTrue(all(c in api.PAIRING_CODE_ALPHABET for c in data["code"]))
        expires = datetime.fromisoformat(data["expires_at"])
        seconds_left = (expires - datetime.now().astimezone()).total_seconds()
        self.assertGreater(seconds_left, 0)
        self.assertLessEqual(seconds_left, api.PAIRING_CODE_TTL_SECONDS)

    def test_code_stays_the_same_before_expiry(self):
        first = json.loads(_asgi_request("GET", "/pairing/code", {}).body)
        second = json.loads(_asgi_request("GET", "/pairing/code", {}).body)
        self.assertEqual(first, second)

    def test_new_code_after_expiry(self):
        _asgi_request("GET", "/pairing/code", {})
        # Pretend the code expired a second ago, and make the next code known.
        api._pairing_expires_at = datetime.now() - timedelta(seconds=1)
        original = api._new_pairing_code
        api._new_pairing_code = lambda: "ABC234"
        try:
            data = json.loads(_asgi_request("GET", "/pairing/code", {}).body)
        finally:
            api._new_pairing_code = original
        self.assertEqual(data["code"], "ABC234")
        self.assertGreater(datetime.fromisoformat(data["expires_at"]), datetime.now().astimezone())

    def test_lan_request_is_forbidden(self):
        r = _asgi_request("GET", "/pairing/code", {}, client=self.LAN_CLIENT)
        self.assertEqual(r.status, 403)
        self.assertNotIn("code", json.loads(r.body))


class PairingTests(unittest.TestCase):
    """POST /pair: the current code buys a token; only its hash is stored."""

    JSON = {"Content-Type": "application/json"}

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        con = sqlite3.connect(self.path)
        con.execute(f"CREATE TABLE devices ({_DEVICES_SCHEMA})")
        con.commit()
        con.close()
        self._orig_db_path = api.DB_PATH
        api.DB_PATH = self.path
        api._pairing_code = None
        api._pairing_expires_at = None
        api._pairing_failed_attempts = 0
        api._pairing_ticket_hash = None
        api._pairing_ticket_expires_at = None

    def tearDown(self):
        api.DB_PATH = self._orig_db_path
        os.remove(self.path)

    def _code(self):
        return json.loads(_asgi_request("GET", "/pairing/code", {}).body)["code"]

    def _pair(self, code):
        return _asgi_request("POST", "/pair", self.JSON, body=json.dumps({"code": code}))

    def _stored_hashes(self):
        con = sqlite3.connect(self.path)
        try:
            return [r[0] for r in con.execute("SELECT token_hash FROM paired_sessions")]
        except sqlite3.OperationalError:
            return []  # table not created yet -> no sessions
        finally:
            con.close()

    def test_correct_code_returns_token_and_stores_only_hash(self):
        r = self._pair(self._code())
        self.assertEqual(r.status, 200)
        token = json.loads(r.body)["token"]
        self.assertGreater(len(token), 30)
        hashes = self._stored_hashes()
        self.assertEqual(hashes, [api._hash_token(token)])
        self.assertNotIn(token, hashes)

    def test_lowercase_and_spaces_are_accepted(self):
        r = self._pair("  " + self._code().lower() + " ")
        self.assertEqual(r.status, 200)

    def test_wrong_code_is_401_and_stores_nothing(self):
        self._code()
        # "O" and "1" are never in a real code, so this can never match.
        r = self._pair("WRONG1")
        self.assertEqual(r.status, 401)
        self.assertNotIn("token", json.loads(r.body))
        self.assertEqual(self._stored_hashes(), [])

    def test_expired_code_is_401(self):
        code = self._code()
        api._pairing_expires_at = datetime.now() - timedelta(seconds=1)
        self.assertEqual(self._pair(code).status, 401)

    def test_too_many_wrong_guesses_burn_the_code(self):
        code = self._code()
        for _ in range(api.MAX_FAILED_PAIRING_ATTEMPTS):
            self.assertEqual(self._pair("WRONG1").status, 401)
        # Even the right code no longer works: the display must show a new one.
        self.assertEqual(self._pair(code).status, 401)

    def test_each_pairing_gets_its_own_token(self):
        t1 = json.loads(self._pair(self._code()).body)["token"]
        t2 = json.loads(self._pair(self._code()).body)["token"]
        self.assertNotEqual(t1, t2)
        self.assertEqual(len(self._stored_hashes()), 2)

    def test_missing_code_field_is_422(self):
        r = _asgi_request("POST", "/pair", self.JSON, body="{}")
        self.assertEqual(r.status, 422)

    def test_same_code_cannot_pair_twice(self):
        code = self._code()
        self.assertEqual(self._pair(code).status, 200)
        self.assertEqual(self._pair(code).status, 401)
        self.assertEqual(len(self._stored_hashes()), 1)

    def test_code_and_ticket_together_is_422(self):
        body = json.dumps({"code": self._code(), "ticket": "x", "device_name": "P"})
        r = _asgi_request("POST", "/pair", self.JSON, body=body)
        self.assertEqual(r.status, 422)

    def test_only_device_name_is_422(self):
        r = _asgi_request("POST", "/pair", self.JSON, body=json.dumps({"device_name": "P"}))
        self.assertEqual(r.status, 422)

    # Two-step pairing: POST /pair/verify trades the code for a ticket, then
    # POST /pair trades the ticket and the phone name for a token.

    def _verify(self, code, client=("127.0.0.1", 12345)):
        return _asgi_request(
            "POST", "/pair/verify", self.JSON, body=json.dumps({"code": code}), client=client
        )

    def _ticket(self):
        return json.loads(self._verify(self._code()).body)["ticket"]

    def _pair_ticket(self, ticket, device_name="Sara's phone"):
        body = json.dumps({"ticket": ticket, "device_name": device_name})
        return _asgi_request("POST", "/pair", self.JSON, body=body)

    def _stored_names(self):
        con = sqlite3.connect(self.path)
        try:
            return [r[0] for r in con.execute("SELECT device_name FROM paired_sessions")]
        finally:
            con.close()

    def test_correct_code_returns_ticket_and_burns_the_code(self):
        code = self._code()
        r = self._verify(code)
        self.assertEqual(r.status, 200)
        data = json.loads(r.body)
        self.assertGreater(len(data["ticket"]), 30)
        datetime.fromisoformat(data["expires_at"])
        self.assertEqual(api._pairing_ticket_hash, api._hash_token(data["ticket"]))
        self.assertEqual(self._verify(code).status, 401)
        self.assertEqual(self._pair(code).status, 401)
        self.assertNotEqual(self._code(), code)

    def test_wrong_code_is_401_and_counts(self):
        code = self._code()
        r = self._verify("WRONG1")
        self.assertEqual(r.status, 401)
        self.assertEqual(json.loads(r.body)["detail"], "Invalid or expired pairing code.")
        for _ in range(api.MAX_FAILED_PAIRING_ATTEMPTS - 1):
            self.assertEqual(self._verify("WRONG1").status, 401)
        self.assertEqual(self._verify(code).status, 401)

    def test_wrong_verify_and_wrong_pair_share_the_counter(self):
        code = self._code()
        for i in range(api.MAX_FAILED_PAIRING_ATTEMPTS):
            r = self._verify("WRONG1") if i % 2 else self._pair("WRONG1")
            self.assertEqual(r.status, 401)
        self.assertEqual(self._verify(code).status, 401)

    def test_valid_ticket_returns_token_and_stores_name(self):
        r = self._pair_ticket(self._ticket(), "Sara's phone")
        self.assertEqual(r.status, 200)
        token = json.loads(r.body)["token"]
        self.assertEqual(self._stored_hashes(), [api._hash_token(token)])
        self.assertEqual(self._stored_names(), ["Sara's phone"])

    def test_ticket_works_only_once(self):
        ticket = self._ticket()
        self.assertEqual(self._pair_ticket(ticket).status, 200)
        r = self._pair_ticket(ticket)
        self.assertEqual(r.status, 401)
        self.assertEqual(
            json.loads(r.body)["detail"],
            "Pairing ticket is invalid or expired. Start pairing again.",
        )
        self.assertEqual(len(self._stored_hashes()), 1)

    def test_expired_ticket_is_401(self):
        ticket = self._ticket()
        api._pairing_ticket_expires_at = datetime.now() - timedelta(seconds=1)
        self.assertEqual(self._pair_ticket(ticket).status, 401)
        self.assertEqual(self._stored_hashes(), [])

    def test_second_verify_replaces_first_ticket(self):
        first = self._ticket()
        second = self._ticket()
        self.assertEqual(self._pair_ticket(first).status, 401)
        self.assertEqual(self._pair_ticket(second).status, 200)

    def test_bad_ticket_does_not_count_as_failed_attempt(self):
        code = self._code()
        for _ in range(api.MAX_FAILED_PAIRING_ATTEMPTS + 1):
            self.assertEqual(self._pair_ticket("made-up").status, 401)
        self.assertEqual(api._pairing_failed_attempts, 0)
        self.assertEqual(self._verify(code).status, 200)

    def test_verify_needs_no_token(self):
        self._code()  # created by the display
        r = self._verify("WRONG1", client=("192.168.1.50", 5555))
        self.assertEqual(r.status, 401)
        self.assertNotIn("www-authenticate", r.headers)
        api._pairing_failed_attempts = 0
        code = self._code()
        r = self._verify(code, client=("192.168.1.50", 5555))
        self.assertEqual(r.status, 200)


class AuthTests(unittest.TestCase):
    """The gate: phones on the LAN need a paired token; the display does not."""

    JSON = {"Content-Type": "application/json"}
    LAN = ("192.168.1.50", 5555)

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        con = sqlite3.connect(self.path)
        con.execute(f"CREATE TABLE devices ({_DEVICES_SCHEMA})")
        con.commit()
        con.close()
        self._orig_db_path = api.DB_PATH
        api.DB_PATH = self.path
        api._pairing_code = None
        api._pairing_expires_at = None
        api._pairing_failed_attempts = 0
        api._pairing_ticket_hash = None
        api._pairing_ticket_expires_at = None

    def tearDown(self):
        api.DB_PATH = self._orig_db_path
        os.remove(self.path)

    def _new_token(self):
        code = json.loads(_asgi_request("GET", "/pairing/code", {}).body)["code"]
        r = _asgi_request(
            "POST", "/pair", self.JSON, body=json.dumps({"code": code}), client=self.LAN
        )
        return json.loads(r.body)["token"]

    def _bearer(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_phone_without_token_is_401(self):
        r = _asgi_request("GET", "/devices", {}, client=self.LAN)
        self.assertEqual(r.status, 401)
        self.assertEqual(r.headers.get("www-authenticate"), "Bearer")

    def test_phone_with_unknown_token_is_401(self):
        r = _asgi_request("GET", "/devices", self._bearer("made-up"), client=self.LAN)
        self.assertEqual(r.status, 401)

    def test_phone_with_paired_token_is_200(self):
        token = self._new_token()
        r = _asgi_request("GET", "/devices", self._bearer(token), client=self.LAN)
        self.assertEqual(r.status, 200)

    def test_display_needs_no_token(self):
        r = _asgi_request("GET", "/devices", {})  # default client is 127.0.0.1
        self.assertEqual(r.status, 200)

    def test_healthz_is_public(self):
        r = _asgi_request("GET", "/healthz", {}, client=self.LAN)
        self.assertEqual(r.status, 200)

    def test_paired_phone_still_cannot_read_the_code(self):
        token = self._new_token()
        r = _asgi_request("GET", "/pairing/code", self._bearer(token), client=self.LAN)
        self.assertEqual(r.status, 403)

    def test_unpair_revokes_the_token(self):
        token = self._new_token()
        r = _asgi_request("POST", "/unpair", self._bearer(token), client=self.LAN)
        self.assertEqual(r.status, 204)
        r = _asgi_request("GET", "/devices", self._bearer(token), client=self.LAN)
        self.assertEqual(r.status, 401)

    def test_unpair_ends_only_this_phones_session(self):
        mine = self._new_token()
        other = self._new_token()
        _asgi_request("POST", "/unpair", self._bearer(mine), client=self.LAN)
        r = _asgi_request("GET", "/devices", self._bearer(other), client=self.LAN)
        self.assertEqual(r.status, 200)


class ConnectionThreadTests(unittest.TestCase):
    """get_connection() is a FastAPI dependency: the connection may be opened,
    used and closed on different worker threads within one request."""

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._orig_db_path = api.DB_PATH
        api.DB_PATH = self.path

    def tearDown(self):
        api.DB_PATH = self._orig_db_path
        os.remove(self.path)

    def _in_other_thread(self, fn):
        errors = []

        def run():
            try:
                fn()
            except Exception as exc:  # collect it so the test can fail clearly
                errors.append(exc)

        t = threading.Thread(target=run)
        t.start()
        t.join()
        return errors

    def test_open_use_close_on_different_threads(self):
        gen = api.get_connection()
        conn = next(gen)  # opened on this thread
        used = self._in_other_thread(lambda: conn.execute("SELECT 1").fetchone())
        closed = self._in_other_thread(lambda: next(gen, None))
        self.assertEqual(used, [])
        self.assertEqual(closed, [])


class IpResolutionHelperTests(unittest.TestCase):
    """_resolve_display_ip / _resolve_ipv6 preference ordering, including the
    fe80:: link-local last-resort rule and legacy single-`ip` fallback."""

    def test_classify_ip_families(self):
        self.assertEqual(api._classify_ip("192.168.1.1"), "ipv4")
        self.assertEqual(api._classify_ip("2001:db8::1"), "ipv6_global")
        self.assertEqual(api._classify_ip("fe80::1"), "ipv6_ll")
        self.assertEqual(api._classify_ip("fe80::1%eth0"), "ipv6_ll")
        self.assertIsNone(api._classify_ip(None))
        self.assertIsNone(api._classify_ip(""))
        self.assertIsNone(api._classify_ip("not-an-ip"))

    def test_ipv4_preferred_over_both_ipv6_forms(self):
        self.assertEqual(
            api._resolve_display_ip("192.168.1.1", "2001:db8::1", "fe80::1", None),
            "192.168.1.1",
        )

    def test_global_ipv6_preferred_over_link_local(self):
        self.assertEqual(
            api._resolve_display_ip(None, "2001:db8::1", "fe80::1", None),
            "2001:db8::1",
        )

    def test_link_local_only_as_last_resort(self):
        self.assertEqual(
            api._resolve_display_ip(None, None, "fe80::1", None), "fe80::1"
        )

    def test_legacy_ip_folded_into_families(self):
        # Old row: only the legacy `ip` column is set (here a global IPv6).
        self.assertEqual(
            api._resolve_display_ip(None, None, None, "2001:db8::5"), "2001:db8::5"
        )
        # Legacy fe80:: is still a genuine last resort.
        self.assertEqual(
            api._resolve_display_ip(None, None, None, "fe80::5"), "fe80::5"
        )
        # A known per-family IPv4 still wins over a legacy fe80:: value.
        self.assertEqual(
            api._resolve_display_ip("10.0.0.2", None, None, "fe80::5"), "10.0.0.2"
        )

    def test_resolve_ipv6_list_order_and_empty(self):
        self.assertEqual(
            api._resolve_ipv6("192.168.1.1", "2001:db8::1", "fe80::1", None),
            ["2001:db8::1", "fe80::1"],
        )
        self.assertEqual(
            api._resolve_ipv6(None, None, "fe80::1", None), ["fe80::1"]
        )
        self.assertIsNone(api._resolve_ipv6("192.168.1.1", None, None, None))


class IpResolutionEndpointTests(_SeededDBTest):
    """The resolved address and ipv6 field as seen through the endpoints."""

    def test_summary_shows_ipv4_when_all_families_known(self):
        self.insert(
            mac="aa:bb:cc:dd:ee:01", ip="fe80::1", last_ipv4="192.168.1.50",
            last_ipv6_global="2001:db8::50", last_ipv6_ll="fe80::1",
            status="online", last_seen="2026-10-16T10:00:00",
        )
        rows = api.list_devices(conn=self.conn, limit=100, offset=0)
        row = next(r for r in rows if r.mac == "aa:bb:cc:dd:ee:01")
        self.assertEqual(row.ip, "192.168.1.50")

    def test_detail_prefers_global_ipv6_and_lists_ipv6(self):
        self.insert(
            mac="aa:bb:cc:dd:ee:02", ip="fe80::2",
            last_ipv6_global="2001:db8::2", last_ipv6_ll="fe80::2",
            status="online", last_seen="2026-10-16T10:00:00",
        )
        d = api.get_device("aa:bb:cc:dd:ee:02", self.conn)
        self.assertEqual(d.ip, "2001:db8::2")
        self.assertEqual(d.ipv6, ["2001:db8::2", "fe80::2"])

    def test_detail_link_local_last_resort(self):
        self.insert(
            mac="aa:bb:cc:dd:ee:03", ip="fe80::3", last_ipv6_ll="fe80::3",
            status="online", last_seen="2026-10-16T10:00:00",
        )
        d = api.get_device("aa:bb:cc:dd:ee:03", self.conn)
        self.assertEqual(d.ip, "fe80::3")
        self.assertEqual(d.ipv6, ["fe80::3"])

    def test_legacy_ipv4_only_row_unchanged(self):
        # Row predating the new columns: only `ip` is set. Behaviour must not
        # regress -- the app still sees the IPv4 address.
        self.insert(
            mac="aa:bb:cc:dd:ee:04", ip="192.168.1.77",
            status="online", last_seen="2026-10-16T10:00:00",
        )
        d = api.get_device("aa:bb:cc:dd:ee:04", self.conn)
        self.assertEqual(d.ip, "192.168.1.77")
        self.assertIsNone(d.ipv6)


class AlertEndpointTests(_SeededDBTest):
    """Read-only Threat Alert endpoints (PBI-14), called directly with a conn."""

    def _schema(self):
        import alerts
        alerts.ensure_schema(self.conn)

    def _add_alert(self, **cols):
        keys = ", ".join(cols)
        marks = ", ".join("?" for _ in cols)
        self.conn.execute(
            f"INSERT INTO alerts ({keys}) VALUES ({marks})", tuple(cols.values())
        )
        self.conn.commit()

    def test_missing_table_reads_as_empty(self):
        self.assertEqual(api.list_alerts(conn=self.conn, limit=200), [])

    def test_list_orders_by_last_event_and_maps_contract(self):
        self._schema()
        self.insert(mac="aa:bb:cc:dd:ee:ff", hostname="cam-1", status="online")
        self._add_alert(
            device_mac="aa:bb:cc:dd:ee:ff", alert_type="Threat", title="ET A", rule_id=1,
            event_time="2026-11-02T10:00:00", severity="High", state="New",
            occurrence_count=1, last_event_time="2026-11-02T10:00:00",
            src_ip="10.0.0.5", dst_ip="8.8.8.8", src_port=5, dst_port=53)
        self._add_alert(
            device_mac=None, alert_type="Threat", title="ET B", rule_id=2,
            event_time="2026-11-02T11:00:00", severity="Medium", state="New",
            occurrence_count=3, last_event_time="2026-11-02T11:30:00",
            src_ip="203.0.113.1", dst_ip="198.51.100.1")
        out = api.list_alerts(conn=self.conn, limit=200)
        self.assertEqual([a.title for a in out], ["ET B", "ET A"])  # newest last_event_time first
        b, a = out
        self.assertEqual((b.kind, b.state, b.severity), ("threat", "new", "medium"))
        self.assertEqual(a.severity, "high")
        self.assertIsNone(b.device_mac)
        self.assertEqual(b.device_name, "Unknown device")
        self.assertEqual(b.occurrence_count, 3)
        self.assertEqual((b.source_ip, b.destination_ip), ("203.0.113.1", "198.51.100.1"))
        self.assertEqual(a.device_name, "cam-1")  # hostname (no user_name)
        self.assertEqual(a.first_event_time, "2026-11-02T10:00:00")
        # No classtype stored -> fallback text naming the original rule; the
        # rule name also stays in title.
        self.assertEqual(a.display_title, "Network activity detected")
        self.assertEqual(
            a.explanation,
            'Assas detected network traffic that matched a security rule '
            '("ET A"). The original rule details are shown below.')
        self.assertEqual(a.rule_id, 1)  # kept in the response for internal use
        self.assertIsNone(a.device_role)
        self.assertIsNone(a.anomaly_score)

    def test_classtype_gives_plain_title_explanation_and_role(self):
        self._schema()
        self.insert(mac="aa:bb:cc:dd:ee:ff", hostname="laptop", status="online")
        self._add_alert(
            device_mac="aa:bb:cc:dd:ee:ff", alert_type="Threat",
            title="ET SCAN Suspicious inbound to mySQL port 3306", rule_id=2010937,
            event_time="2026-11-02T10:00:00", severity="Medium", state="New",
            occurrence_count=1, last_event_time="2026-11-02T10:00:00",
            src_ip="192.168.8.50", dst_ip="192.168.8.60",
            category="Detection of a Network Scan", classtype="network-scan",
            device_role="source")
        self._add_alert(
            device_mac="aa:bb:cc:dd:ee:ff", alert_type="Threat", title="ET WEB X",
            rule_id=7, event_time="2026-11-02T11:00:00", severity="High",
            state="New", occurrence_count=1, last_event_time="2026-11-02T11:00:00",
            src_ip="203.0.113.9", dst_ip="192.168.8.50",
            classtype="web-application-attack", device_role="target")
        target, source = api.list_alerts(conn=self.conn, limit=200)
        # The original rule name is kept in `title`; nothing existing is removed.
        self.assertEqual(source.title, "ET SCAN Suspicious inbound to mySQL port 3306")
        self.assertEqual(source.rule_id, 2010937)
        self.assertEqual(source.display_title, "Network scan")
        self.assertEqual(source.explanation, alert_text.CLASSTYPE_TEXT["network-scan"][1])
        self.assertEqual(source.classtype, "network-scan")
        self.assertEqual(source.category, "Detection of a Network Scan")
        self.assertEqual(source.device_role, "source")
        self.assertEqual(target.display_title, "Web attack attempt")
        self.assertEqual(target.device_role, "target")
        # Single-alert and per-device endpoints carry the same fields.
        one = api.get_alert(int(source.id), conn=self.conn)
        self.assertEqual((one.display_title, one.device_role), ("Network scan", "source"))
        dev = api.list_device_alerts("aa:bb:cc:dd:ee:ff", conn=self.conn, limit=200)
        self.assertEqual([a.display_title for a in dev], ["Web attack attempt", "Network scan"])

    def test_unknown_classtype_and_unlinked_role_fall_back(self):
        self._schema()
        self._add_alert(
            device_mac=None, alert_type="Threat", title="ASSAS TEST High",
            rule_id=1000001, event_time="2026-11-02T10:00:00", severity="High",
            state="New", occurrence_count=1, last_event_time="2026-11-02T10:00:00",
            classtype="tcp-connection", device_role="source")
        (a,) = api.list_alerts(conn=self.conn, limit=200)
        self.assertEqual(a.title, "ASSAS TEST High")
        self.assertEqual(a.severity, "high")
        self.assertEqual(a.display_title, "Network activity detected")
        self.assertIn('("ASSAS TEST High")', a.explanation)
        self.assertNotIn("1000001", a.explanation)  # rule ID never in user text
        self.assertEqual(a.rule_id, 1000001)  # but kept in the response
        self.assertIsNone(a.device_role)  # no device -> no role line

    def test_legacy_critical_and_reviewed_read_as_high_and_new(self):
        # Safety net for rows the one-time conversion has not reached.
        self._schema()
        self._add_alert(
            device_mac=None, alert_type="Threat", title="ET OLD", rule_id=9,
            event_time="2026-11-02T10:00:00", severity="Critical", state="Reviewed",
            occurrence_count=1, last_event_time="2026-11-02T10:00:00")
        (a,) = api.list_alerts(conn=self.conn, limit=200)
        self.assertEqual((a.severity, a.state), ("high", "new"))

    def test_table_without_new_columns_still_reads(self):
        # An alerts table the ingester has not migrated yet (pre-classtype).
        self.conn.execute(
            "CREATE TABLE alerts (alert_id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "device_mac TEXT, alert_type TEXT NOT NULL DEFAULT 'Threat', "
            "title TEXT NOT NULL, rule_id INTEGER, event_time TEXT NOT NULL, "
            "src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER, "
            "severity TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'New', "
            "explanation TEXT, model_version TEXT, anomaly_score REAL, "
            "threshold REAL, occurrence_count INTEGER NOT NULL DEFAULT 1, "
            "last_event_time TEXT NOT NULL)")
        self._add_alert(
            device_mac=None, alert_type="Threat", title="ET OLD", rule_id=3,
            event_time="2026-11-02T10:00:00", severity="Low", state="New",
            occurrence_count=1, last_event_time="2026-11-02T10:00:00")
        (a,) = api.list_alerts(conn=self.conn, limit=200)
        self.assertEqual(a.title, "ET OLD")
        self.assertEqual(a.display_title, "Network activity detected")
        self.assertIsNone(a.classtype)
        self.assertIsNone(a.device_role)

    def test_user_name_preferred_for_device_name(self):
        self._schema()
        self.insert(mac="aa:bb:cc:dd:ee:ff", hostname="cam-1", user_name="Front Cam",
                    status="online")
        self._add_alert(device_mac="aa:bb:cc:dd:ee:ff", alert_type="Threat", title="X",
                        rule_id=1, event_time="2026-11-02T10:00:00", severity="low",
                        state="New", occurrence_count=1, last_event_time="2026-11-02T10:00:00")
        self.assertEqual(api.list_alerts(conn=self.conn, limit=200)[0].device_name, "Front Cam")

    def test_get_alert_and_404(self):
        self._schema()
        self._add_alert(device_mac=None, alert_type="Threat", title="X", rule_id=1,
                        event_time="2026-11-02T10:00:00", severity="Medium", state="New",
                        occurrence_count=1, last_event_time="2026-11-02T10:00:00")
        self.assertEqual(api.get_alert(alert_id=1, conn=self.conn).severity, "medium")
        with self.assertRaises(api.HTTPException) as ctx:
            api.get_alert(alert_id=999, conn=self.conn)
        self.assertEqual(ctx.exception.status_code, 404)

    def test_device_alerts_filter_normalises_mac(self):
        self._schema()
        self.insert(mac="aa:bb:cc:dd:ee:ff", hostname="cam-1", status="online")
        self._add_alert(device_mac="aa:bb:cc:dd:ee:ff", alert_type="Threat", title="mine",
                        rule_id=1, event_time="2026-11-02T10:00:00", severity="low",
                        state="New", occurrence_count=1, last_event_time="2026-11-02T10:02:00")
        self._add_alert(device_mac=None, alert_type="Threat", title="other", rule_id=2,
                        event_time="2026-11-02T10:00:00", severity="low", state="New",
                        occurrence_count=1, last_event_time="2026-11-02T10:03:00")
        out = api.list_device_alerts(mac="AA:BB:CC:DD:EE:FF", conn=self.conn, limit=200)
        self.assertEqual([a.title for a in out], ["mine"])


if __name__ == "__main__":
    unittest.main()


def test_alert_device_name_matches_device_details_precedence():
    """The alert's device name follows the same precedence the app shows on
    device details: user name -> human hostname (opaque machine identifiers
    skipped) -> model -> 'Unknown device'. Inventory data only."""
    # user name always wins
    assert api._alert_device_name("Dad laptop", "0badc396-c1f4-40db-ba83-c0702b11ae58", "emu") == "Dad laptop"
    # opaque UUID hostname falls through to the model
    assert api._alert_device_name(None, "0badc396-c1f4-40db-ba83-c0702b11ae58",
                                  "emulator (sdk_gphone64_x86_64)") == "emulator (sdk_gphone64_x86_64)"
    # long-hex hostname falls through
    assert api._alert_device_name(None, "a7f3e9c1b2d84f60a7f3e9c1b2d84f60", "Smart TV") == "Smart TV"
    # human hostname is kept
    assert api._alert_device_name(None, "Living-Room-TV", "X100") == "Living-Room-TV"
    # nothing usable -> Unknown device (no guessing)
    assert api._alert_device_name(None, "0badc396-c1f4-40db-ba83-c0702b11ae58", None) == "Unknown device"
    assert api._alert_device_name(None, None, None) == "Unknown device"
