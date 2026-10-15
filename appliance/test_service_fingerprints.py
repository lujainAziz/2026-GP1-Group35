import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

import discovery
from classification import SCORES
from service_fingerprints import parse_nmap_identity, DEVICE_TYPES


def scan_xml(services=(), target='192.168.1.50'):
    root = ET.Element('nmaprun')
    host = ET.SubElement(root, 'host')
    ET.SubElement(host, 'address', addr=target, addrtype='ipv4')
    ports = ET.SubElement(host, 'ports')
    for number, attrs, state in services:
        port = ET.SubElement(ports, 'port', protocol='tcp', portid=str(number))
        ET.SubElement(port, 'state', state=state)
        ET.SubElement(port, 'service', **attrs)
    return '<?xml version="1.0"?><!DOCTYPE nmaprun>' + ET.tostring(root, encoding='unicode')


def fingerprint(dtype, **extra):
    return dict(name='http', method='probed', conf='10', devicetype=dtype, **extra)


class ServiceFingerprintTests(unittest.TestCase):
    def parse(self, rows):
        return parse_nmap_identity(scan_xml(rows), '192.168.1.50')

    def test_supported_classes_from_real_service_match(self):
        for raw, expected in DEVICE_TYPES.items():
            with self.subTest(raw=raw):
                candidate, ports = self.parse([(8080, fingerprint(raw), 'open')])
                self.assertEqual(candidate[:2], (expected, SCORES['service']))
                self.assertEqual(ports, [8080])

    def test_service_fingerprint_outweighs_port_guess(self):
        candidate, _ = self.parse([(554, fingerprint('storage-misc'), 'open')])
        self.assertEqual(candidate[0], 'NAS / Server')

    def test_table_lookup_is_not_fingerprint(self):
        attrs = dict(name='http', method='table', conf='10', devicetype='router')
        self.assertIsNone(self.parse([(8080, attrs, 'open')])[0])

    def test_low_invalid_confidence_ignored(self):
        for confidence in ('0', '7', '11', 'bad'):
            attrs = fingerprint('printer')
            attrs['conf'] = confidence
            self.assertIsNone(self.parse([(8080, attrs, 'open')])[0])

    def test_os_or_product_is_not_hardware_type(self):
        for osname in ('Linux', 'Windows', 'Android', 'iOS'):
            attrs = dict(name='http', method='probed', conf='10', ostype=osname,
                         product='Apache httpd')
            self.assertIsNone(self.parse([(8080, attrs, 'open')])[0])

    def test_other_host_not_attributed_to_target(self):
        xml = scan_xml([(8080, fingerprint('printer'), 'open')], target='192.168.1.51')
        self.assertEqual(parse_nmap_identity(xml, '192.168.1.50'), (None, []))

    def test_closed_filtered_not_open(self):
        for state in ('closed', 'filtered', 'open|filtered'):
            self.assertEqual(self.parse([(9100, fingerprint('printer'), state)]), (None, []))

    def test_unknown_type_does_not_invent_category(self):
        for dtype in ('general purpose', 'specialized', 'phone', 'future device'):
            self.assertIsNone(self.parse([(8080, fingerprint(dtype), 'open')])[0])

    def test_conflicting_services_are_order_independent(self):
        rows = [(8080, fingerprint('printer'), 'open'), (8443, fingerprint('router'), 'open')]
        for entries in (rows, rows[::-1]):
            self.assertEqual(self.parse(entries)[0],
                             ('Generic / Unknown', SCORES['service'], 'conflicting evidence'))

    def test_conflicting_ports_do_not_choose_first(self):
        candidate, _ = self.parse([(9100, {}, 'open'), (3389, {}, 'open')])
        self.assertEqual(candidate[0], 'Generic / Unknown')

    def test_plain_rtsp_remains_broad(self):
        self.assertEqual(self.parse([(554, {}, 'open')])[0][0], 'Video Surveillance Device')

    def test_bad_xml_and_entity_declarations_rejected(self):
        for xml in ('<nmaprun>', '<other/>', '<!DOCTYPE nmaprun SYSTEM "file:///x"><nmaprun/>',
                    '<!DOCTYPE nmaprun [<!ENTITY x "expanded">]><nmaprun/>', 'x'*2_000_001):
            with self.assertRaises(ValueError):
                parse_nmap_identity(xml, '192.168.1.50')

    def test_malformed_ports_ignored(self):
        self.assertEqual(self.parse([('x', {}, 'open'), (0, {}, 'open'), (65536, {}, 'open')]), (None, []))


class VendorDatabaseTests(unittest.TestCase):
    def test_fallback_fills_missing_prefixes_and_keeps_primary(self):
        with tempfile.TemporaryDirectory() as tmp:
            primary, fallback = Path(tmp)/'oui', Path(tmp)/'nmap'
            primary.write_text('001122 Primary\n0011223 Small block\n001122334 Tiny block\n')
            fallback.write_text('# Header\n001122 Other\nAABBCC New vendor\nxyz Invalid\n123 Bad\n')
            with patch.object(discovery, 'OUI_FILE', str(primary)), \
                 patch.object(discovery, 'OUI_FALLBACK_FILES', (str(fallback),)), \
                 patch.object(discovery, 'oui_dict', {}):
                discovery.load_oui()
                self.assertEqual(discovery.oui_dict, {'001122':'Primary', '0011223':'Small block',
                                                     '001122334':'Tiny block', 'aabbcc':'New vendor'})

    def test_missing_primary_uses_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            fallback = Path(tmp)/'nmap'
            fallback.write_text('001122 Known vendor\n')
            with patch.object(discovery, 'OUI_FILE', str(Path(tmp)/'missing')), \
                 patch.object(discovery, 'OUI_FALLBACK_FILES', (str(fallback),)), \
                 patch.object(discovery, 'oui_dict', {}):
                discovery.load_oui()
                self.assertEqual(discovery.get_vendor('00:11:22:33:44:55'), 'Known vendor')
                self.assertIsNone(discovery.get_vendor('02:11:22:33:44:55'))


if __name__ == '__main__':
    unittest.main()
