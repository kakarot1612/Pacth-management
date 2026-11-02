import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.validator import VulnerabilityValidator as Validator
from core.cve_kb_mapper import CveKbMapper
from core.wsus_client import change_approval
from core.wazuh_client import WazuhClient


class RegressionTests(unittest.TestCase):
    def test_build_requires_same_servicing_branch(self):
        for current, required, expected in [
            ('20348.1000', '17763.9000', False),
            ('10.0.20348.3000', '20348.2000', True),
            ('20348', '20348.2000', False),
            ('unknown', '20348.2000', False),
            ('20348.1000', '20348.2000', False),
        ]:
            self.assertEqual(Validator._is_build_greater_or_equal(current, required), expected)

    def test_unmatched_product_does_not_pick_arbitrary_patch(self):
        mapper = CveKbMapper()
        mapper.cache = {'CVE-TEST': {'kb_map': {'Server 2019': 'KB1234567'},
                                     'build_map': {'Server 2019': '17763.9000'}}}
        self.assertIsNone(mapper.resolve_cve('CVE-TEST', 'Server 2022')['kb'])
        self.assertIsNone(mapper.resolve_cve('CVE-TEST')['min_build'])

    def test_reboot_alone_does_not_resolve_missing_patch(self):
        result = Validator.validate_vulnerability(
            {'cve': 'CVE-TEST'}, [], {'build': '20348.1000'},
            'KB1234567', '20348.2000', is_server_reboot=True)
        self.assertEqual(result['status'], Validator.STATUS_CONFIRMED_VULNERABLE)

    def test_installed_patch_pending_reboot_still_requires_action(self):
        result = Validator.validate_vulnerability(
            {'cve': 'CVE-TEST'}, ['KB1234567'], {'build': '20348.1000'},
            'KB1234567', '20348.2000', is_server_reboot=True)
        self.assertTrue(result['action_required'])
        self.assertTrue(result['reboot_required'])
        self.assertEqual(result['status'], Validator.STATUS_CONFIRMED_VULNERABLE)

    def test_empty_scan_preserves_reboot_flag(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'config').mkdir()
            state = root / 'config/reboot_status.json'
            state.write_text(json.dumps({'001': {'reboot_pending': True}}))
            with patch('core.config.BASE_DIR', root):
                result = Validator.audit_agent('001', 'host', [], [], None, CveKbMapper())
            self.assertTrue(result['reboot_pending'])
            self.assertTrue(json.loads(state.read_text())['001']['reboot_pending'])

    def test_wsus_failure_is_not_success(self):
        with patch('core.wsus_client.subprocess.run') as run:
            run.return_value.returncode = 1
            with self.assertRaises(RuntimeError):
                change_approval('KB1234567', 'Test')

    def test_invalid_kb_never_starts_powershell(self):
        with patch('core.wsus_client.subprocess.run') as run:
            with self.assertRaises(ValueError):
                change_approval('KB123;whoami', 'Test')
            run.assert_not_called()

    def test_json_export_loads(self):
        with tempfile.TemporaryDirectory() as folder:
            export = Path(folder) / 'vulns.json'
            export.write_text(json.dumps([{'agent_id': '001', 'cve': 'CVE-TEST'}]))
            with patch('core.wazuh_client.Settings.WAZUH_VULNS_FILE', export):
                result = WazuhClient()._load_exported_vulns('001')
            self.assertEqual(result[0]['cve'], 'CVE-TEST')


if __name__ == '__main__':
    unittest.main()
