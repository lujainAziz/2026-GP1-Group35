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
import unittest
from collections import namedtuple
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
    "traffic_seen INTEGER, last_traffic_seen TEXT, vendor_source TEXT, "
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
        seconds_left = (expires - datetime.now()).total_seconds()
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
        self.assertGreater(datetime.fromisoformat(data["expires_at"]), datetime.now())

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
        code = self._code()
        t1 = json.loads(self._pair(code).body)["token"]
        t2 = json.loads(self._pair(code).body)["token"]
        self.assertNotEqual(t1, t2)
        self.assertEqual(len(self._stored_hashes()), 2)

    def test_missing_code_field_is_422(self):
        r = _asgi_request("POST", "/pair", self.JSON, body="{}")
        self.assertEqual(r.status, 422)

 
if __name__ == "__main__":
    unittest.main()
