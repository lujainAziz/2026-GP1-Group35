"""Internet addresses must never be stored as a device's own address.

Bug: discovery started with no known subnet, local_monitored_ip() failed open,
and internet servers' addresses (which arrive behind the router's MAC) were
written into the router's ip / last_ipv4 / last_ipv6_global. The alert linker
then matched a public source address to the router.

Addresses are documentation placeholders: 203.0.113.0/24 and 2001:db8:ffff::/48
stand for internet servers; 192.168.1.0/24 and 2001:db8:1::/64 are the LAN.
"""
import ipaddress
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from scapy.all import Ether, IP, IPv6, TCP

import addr_scope
import discovery as d

ROUTER = "02:00:00:00:00:01"
LAPTOP = "02:00:00:00:00:20"
OLD_NET = "02:00:00:00:00:30"
OTHER = "02:00:00:00:00:40"
APPLIANCE = "02:00:00:00:00:99"
LAN_V4 = ipaddress.ip_network("192.168.1.0/24")
LAN_V6 = ipaddress.ip_network("2001:db8:1::/64")
SERVER_V4 = "203.0.113.10"
SERVER_V6 = "2001:db8:ffff::1"


class _DB(unittest.TestCase):
    networks = [LAN_V4, LAN_V6]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for name, value in [
            ("DB_PATH", str(Path(self.tmp.name) / "test.db")),
            ("monitored_networks", list(self.networks)),
            ("ra_networks", []),
            ("local_macs", {APPLIANCE}), ("local_ips", set()), ("write_cache", {}),
            ("syn_fp_last", {}), ("probe_attempts", {}), ("oui_dict", {}), ("infra_hints", {}),
        ]:
            p = patch.object(d, name, value)
            p.start()
            self.addCleanup(p.stop)
        for name in ["schedule_active_probe", "schedule_mdns_probe",
                     "schedule_nbns_probe", "schedule_ssdp_probe"]:
            p = patch.object(d, name)
            p.start()
            self.addCleanup(p.stop)
        d.init_db()

    def row(self, mac):
        with closing(sqlite3.connect(d.DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            r = conn.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
            return dict(r) if r else None

    def addresses(self, mac):
        r = self.row(mac) or {}
        return {k: r.get(k) for k in ("ip", "last_ipv4", "last_ipv6_global")}

    def internet_packet_from_router(self, v6=False):
        # Routed internet traffic: the router's MAC, the server's address.
        l3 = (IPv6(src=SERVER_V6, dst="2001:db8:1::20") if v6
              else IP(src=SERVER_V4, dst="192.168.1.20"))
        return Ether(src=ROUTER, dst=LAPTOP) / l3 / TCP(sport=443, dport=50000, flags="A")


class AddrScopeTests(unittest.TestCase):
    def test_lan_scoped_ranges_are_explicit(self):
        for ip in ("10.1.2.3", "172.16.0.1", "192.168.1.20", "169.254.1.1",
                   "100.64.0.1", "fe80::1", "fd00::1", "fe80::1%eth0"):
            self.assertTrue(addr_scope.is_lan_scoped(ip), ip)
        # Documentation ranges stand in for the internet: never LAN-scoped
        # (Python's is_private would wrongly call them private).
        for ip in (SERVER_V4, "198.51.100.7", "192.0.2.1", SERVER_V6, "2001:db8:1::20",
                   "198.51.100.8", None, "", "not-an-ip"):
            self.assertFalse(addr_scope.is_lan_scoped(ip), ip)


class FailClosedTests(_DB):
    def test_no_known_subnet_passes_only_link_local(self):
        d.monitored_networks[:] = []
        self.assertIsNone(d.local_monitored_ip(SERVER_V4))
        self.assertIsNone(d.local_monitored_ip(SERVER_V6))
        self.assertIsNone(d.local_monitored_ip("192.168.1.20"))
        self.assertEqual(d.local_monitored_ip("fe80::1"), "fe80::1")

    def test_known_subnet_passes_lan_and_refuses_internet(self):
        self.assertEqual(d.local_monitored_ip("192.168.1.20"), "192.168.1.20")
        self.assertIsNone(d.local_monitored_ip(SERVER_V4))

    def test_internet_traffic_never_becomes_the_routers_address(self):
        # The bug: started with no known subnet (fail-open) -> server address
        # stored on the router. Both with and without a subnet now.
        for nets in ([], [LAN_V4, LAN_V6]):
            d.monitored_networks[:] = nets
            d.write_cache.clear()
            d.handle(self.internet_packet_from_router())
            d.handle(self.internet_packet_from_router(v6=True))
            self.assertEqual(self.addresses(ROUTER),
                             {"ip": None, "last_ipv4": None, "last_ipv6_global": None},
                             f"networks={nets}")

    def test_update_device_stores_lan_addresses_only(self):
        d.update_device(ROUTER, ip=SERVER_V4, seen_on_span=True)
        d.update_device(ROUTER, ip=SERVER_V6, seen_on_span=True)
        self.assertEqual(self.addresses(ROUTER),
                         {"ip": None, "last_ipv4": None, "last_ipv6_global": None})
        d.update_device(LAPTOP, ip="192.168.1.20", seen_in_discovery=True)
        d.update_device(LAPTOP, ip="2001:db8:1::20", seen_on_span=True)
        a = self.addresses(LAPTOP)
        self.assertEqual((a["last_ipv4"], a["last_ipv6_global"]), ("192.168.1.20", "2001:db8:1::20"))


class NetworkContextReloadTests(_DB):
    def _ip(self, v4_all="", v4_dev="", v6_dev="", fail=False):
        def run(cmd, **_kw):
            if fail:
                raise OSError("ip failed")
            if cmd[:2] == ["ip", "-6"]:
                return v6_dev
            return v4_dev if "dev" in cmd else v4_all
        return patch.object(d.subprocess, "check_output", side_effect=run)

    def test_reload_picks_up_a_late_subnet_and_keeps_it_on_failure(self):
        with patch.object(d, "DISCOVERY_INTERFACE", "eth0"), \
             patch.object(d, "_net_ctx", {"macs": set(), "v4_ips": set(), "v4_nets": [],
                                          "discovery_ipv4": None, "v6_ips": set(), "v6_nets": []}):
            # Startup before DHCP: no address yet -> nothing recorded.
            with self._ip():
                d.load_network_context()
                d.load_ipv6_context()
            self.assertEqual(d.monitored_networks, [])
            self.assertIsNone(d.local_monitored_ip("192.168.1.20"))
            # A later reload finds the lease.
            with self._ip(v4_all="2: eth0    inet 192.168.1.5/24 brd x\n",
                          v4_dev="2: eth0    inet 192.168.1.5/24 brd x\n",
                          v6_dev="2: eth0    inet6 2001:db8:1::5/64 scope global\n"):
                d.load_network_context()
                d.load_ipv6_context()
            self.assertEqual(d.monitored_networks, [LAN_V4, LAN_V6])
            self.assertEqual(d.local_monitored_ip("192.168.1.20"), "192.168.1.20")
            self.assertIn("192.168.1.5", d.local_ips)
            # A failing reload keeps the last good context (never empties it).
            with self._ip(fail=True):
                d.load_network_context()
                d.load_ipv6_context()
            self.assertEqual(d.monitored_networks, [LAN_V4, LAN_V6])
            self.assertIn("192.168.1.5", d.local_ips)
            self.assertIn("2001:db8:1::5", d.local_ips)

    def test_loop_reloads_periodically(self):
        class Stop(Exception):
            pass
        with patch.object(d, "NETWORK_CONTEXT_REFRESH_SECONDS", 300), \
             patch.object(d.time, "sleep", side_effect=[None, None, Stop()]) as sleep, \
             patch.object(d, "load_network_context") as v4, \
             patch.object(d, "load_ipv6_context") as v6:
            with self.assertRaises(Stop):
                d.network_context_loop()
        self.assertEqual((v4.call_count, v6.call_count), (2, 2))
        sleep.assert_called_with(300)


class ClearOfflinkAddressesTests(_DB):
    def _seed(self):
        with closing(sqlite3.connect(d.DB_PATH)) as conn, conn:
            def dev(mac, ip, v4, v6):
                conn.execute(
                    "INSERT INTO devices (mac, ip, last_ipv4, last_ipv6_global, status) "
                    "VALUES (?, ?, ?, ?, 'online')", (mac, ip, v4, v6))
            dev(ROUTER, SERVER_V4, SERVER_V4, SERVER_V6)                  # the bug
            dev(LAPTOP, "192.168.1.20", "192.168.1.20", "2001:db8:1::20")  # LAN, evidence
            dev(OLD_NET, "10.9.9.9", "10.9.9.9", None)                     # previous network
            dev(OTHER, None, None, "2001:db8:ffff::2")                     # global, no evidence
            norm, _ = d.normalize_address("2001:db8:1::20")
            conn.execute(
                "INSERT INTO device_addresses (mac, addr, family, source, first_seen, last_seen) "
                "VALUES (?, ?, 'ipv6', 'ndp', '2026-11-01T10:00:00', '2026-11-20T10:00:00')",
                (LAPTOP, norm))

    def test_clears_internet_addresses_once_and_keeps_lan_and_evidence(self):
        self._seed()
        self.assertEqual(d.clear_offlink_device_addresses(), 4)
        self.assertEqual(self.addresses(ROUTER),
                         {"ip": None, "last_ipv4": None, "last_ipv6_global": None})
        self.assertEqual(self.addresses(LAPTOP),
                         {"ip": "192.168.1.20", "last_ipv4": "192.168.1.20",
                          "last_ipv6_global": "2001:db8:1::20"})  # evidence-backed global kept
        self.assertEqual(self.addresses(OLD_NET)["last_ipv4"], "10.9.9.9")  # other network kept
        self.assertIsNone(self.addresses(OTHER)["last_ipv6_global"])
        # Runs once: a second call does nothing, even if a bad value reappears.
        with closing(sqlite3.connect(d.DB_PATH)) as conn, conn:
            conn.execute("UPDATE devices SET last_ipv4=? WHERE mac=?", (SERVER_V4, ROUTER))
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM migrations WHERE name=?",
                             (d.CLEAR_OFFLINK_ADDRESSES,)).fetchone()[0], 1)
        self.assertIsNone(d.clear_offlink_device_addresses())
        self.assertEqual(self.addresses(ROUTER)["last_ipv4"], SERVER_V4)

    def test_failure_rolls_back_and_leaves_no_marker(self):
        self._seed()
        real = d.connect_db

        class Conn:
            def __init__(self):
                self._c = real()

            def __getattr__(self, name):
                return getattr(self._c, name)

            def execute(self, sql, *args):
                if sql.startswith("INSERT INTO migrations"):
                    raise sqlite3.OperationalError("disk I/O error")
                return self._c.execute(sql, *args)

        with patch.object(d, "connect_db", Conn), self.assertRaises(sqlite3.OperationalError):
            d.clear_offlink_device_addresses()
        self.assertEqual(self.addresses(ROUTER)["last_ipv4"], SERVER_V4)  # rolled back
        self.assertEqual(d.clear_offlink_device_addresses(), 4)  # and can run again


if __name__ == "__main__":
    unittest.main()
