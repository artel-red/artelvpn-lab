import json
from pathlib import Path
import unittest
from lab.filter_model import Flow, evaluate

ROOT = Path(__file__).resolve().parents[1]


class FilterModelTests(unittest.TestCase):
    def scenario(self, name):
        return json.loads((ROOT / 'lab/scenarios' / (name + '.json')).read_text())

    def test_open(self):
        self.assertEqual(evaluate(self.scenario('open'), Flow('203.0.113.1', 'allowed.test', 'tcp', 20000)).delivered_bytes, 20000)

    def test_udp_block_tcp_survives(self):
        s = self.scenario('block_udp')
        self.assertFalse(evaluate(s, Flow('203.0.113.1', 'allowed.test', 'udp', 100)).admitted)
        self.assertTrue(evaluate(s, Flow('203.0.113.1', 'allowed.test', 'tcp', 100)).admitted)

    def test_allowed_name_does_not_override_ip_rule(self):
        self.assertFalse(evaluate(self.scenario('allowlist_ip_and_sni'), Flow('198.51.100.1', 'allowed.test', 'tcp', 100)).admitted)

    def test_allowed_ip_does_not_override_name_rule(self):
        self.assertFalse(evaluate(self.scenario('allowlist_ip_and_sni'), Flow('203.0.113.1', 'other.test', 'tcp', 100)).admitted)

    def test_both_rules_satisfied(self):
        self.assertTrue(evaluate(self.scenario('allowlist_ip_and_sni'), Flow('203.0.113.1', 'allowed.test', 'tcp', 100)).admitted)

    def test_handshake_sized_request_is_not_sustained_transfer(self):
        s = self.scenario('payload_stall')
        self.assertEqual(evaluate(s, Flow('203.0.113.1', 'allowed.test', 'tcp', 1000)).delivered_bytes, 1000)
        self.assertEqual(evaluate(s, Flow('203.0.113.1', 'allowed.test', 'tcp', 50000)).delivered_bytes, 16384)

    def test_total_outage(self):
        self.assertEqual(evaluate(self.scenario('total_outage'), Flow('203.0.113.1', 'allowed.test', 'tcp', 1000)).delivered_bytes, 0)

    def test_negative_bytes_rejected(self):
        with self.assertRaises(ValueError):
            evaluate({}, Flow('203.0.113.1', 'allowed.test', 'tcp', -1))
