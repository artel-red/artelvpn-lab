import unittest
from tools.check_publication import violations


class PublicationTests(unittest.TestCase):
    def test_documentation_address_allowed(self):
        self.assertEqual(violations('docs/example.md', '203.0.113.1'), [])

    def test_live_address_rejected(self):
        self.assertIn('non-documentation IPv4 address', violations('docs/example.md', '8' + '.8.8.8'))

    def test_capture_rejected(self):
        self.assertIn('forbidden file type', violations('trace.pcap', ''))

    def test_credential_rejected(self):
        self.assertIn('possible credential', violations('example.md', 'gh' + 'p_' + 'a' * 30))

    def test_privileged_workflow_rejected(self):
        self.assertIn('privileged workflow feature', violations('.github/workflows/a.yml', 'on: pull_' + 'request_target'))
