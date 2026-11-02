import base64
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
from http.server import ThreadingHTTPServer
import requests

from core.security import AuthStore, password_hash
from core.threat_intel import ThreatIntelEngine as Intel
from core.ai_advisor import AiAdvisor
from core.storage import atomic_write_text
import server


class IntelTests(unittest.TestCase):
    def setUp(self):
        Intel._cache.clear()
        Intel._cache_timestamps.clear()
        Intel._kev_cache = None
        Intel._kev_time = 0

    def test_offline_feed_never_fabricates_epss_kev_or_poc(self):
        with patch('core.threat_intel.requests.get', side_effect=requests.ConnectionError):
            data = Intel._query_direct_threat_feeds('CVE-2024-12345', 'Ransomware Zero-Day')
        self.assertIsNone(data['epss_score'])
        self.assertIsNone(data['is_cisa_kev'])
        self.assertIsNone(data['has_public_poc'])
        self.assertEqual(data['data_status'], 'unknown')

    def test_catalog_membership_and_zero_epss_are_preserved(self):
        epss = Mock()
        epss.json.return_value = {'data': [{'cve': 'CVE-2024-12345', 'epss': '0', 'percentile': '0', 'date': '2026-11-02'}]}
        kev = Mock()
        kev.json.return_value = {'dateReleased': '2026-11-02', 'vulnerabilities': []}
        with patch('core.threat_intel.requests.get', side_effect=[epss, kev]):
            data = Intel._query_direct_threat_feeds('CVE-2024-12345', 'Ransomware')
        self.assertEqual(data['epss_score'], 0)
        self.assertIs(data['is_cisa_kev'], False)
        self.assertIsNone(data['has_public_poc'])
        self.assertEqual(len(data['evidence']), 2)

    def test_mcp_string_false_does_not_become_true(self):
        data = Intel._parse_mcp_triage_result('CVE-2024-12345', json.dumps({'is_kev': 'false', 'epss_score': 5, 'has_poc': True}))
        self.assertIsNone(data['is_cisa_kev'])
        self.assertIsNone(data['epss_score'])
        self.assertIsNone(data['has_public_poc'])

    def test_prose_with_word_exploit_is_not_poc_evidence(self):
        data = Intel._parse_mcp_triage_result('CVE-2024-12345', 'No PoC or Exploit available')
        self.assertIsNone(data['has_public_poc'])
        self.assertEqual(data['data_status'], 'unknown')

    def test_stale_cache_survives_outage(self):
        data = Intel._empty_intel('CVE-2024-12345')
        data['epss_score'] = .1
        Intel._cache['CVE-2024-12345'] = data
        Intel._cache_timestamps['CVE-2024-12345'] = 0
        with patch.object(Intel, '_query_mcp_server', return_value=None), patch.object(Intel, '_query_direct_threat_feeds', return_value=Intel._empty_intel('CVE-2024-12345')):
            result = Intel.get_cve_intel('CVE-2024-12345')
        self.assertEqual(result['data_status'], 'stale')
        self.assertEqual(result['epss_score'], .1)

    def test_gemini_failure_does_not_send_data_to_openrouter(self):
        with patch.object(Intel, 'get_cve_intel', return_value={}), patch('core.ai_advisor.Settings.AI_PROVIDER', 'gemini'), patch('core.ai_advisor.Settings.GEMINI_API_KEY', 'test'), patch.object(AiAdvisor, '_query_gemini', return_value=None), patch.object(AiAdvisor, '_query_openrouter') as other:
            data = AiAdvisor.get_remediation_guidance('CVE-2024-12345', 'host')
        other.assert_not_called()
        self.assertEqual(data['status'], 'unavailable')
        self.assertTrue(data['requires_human_review'])

    def test_connection_failure_has_actionable_safe_message(self):
        with patch.object(Intel, 'get_cve_intel', return_value={}), patch('core.ai_advisor.Settings.AI_PROVIDER', 'gemini'), patch('core.ai_advisor.Settings.GEMINI_API_KEY', 'secret-key'), patch.object(AiAdvisor, '_query_gemini', side_effect=requests.ConnectionError('secret-key')):
            data = AiAdvisor.get_remediation_guidance('CVE-2024-12345', 'host')
        self.assertEqual(data['error_code'], 'connection_error')
        self.assertNotIn('secret-key', json.dumps(data))

    def test_product_reference_is_not_presented_as_verified_cve(self):
        with patch.object(Intel, 'get_cve_intel', return_value={}), patch('core.ai_advisor.Settings.AI_PROVIDER', 'gemini'), patch('core.ai_advisor.Settings.GEMINI_API_KEY', 'test'), patch.object(AiAdvisor, '_query_gemini', return_value={'guidance_markdown': 'Draft'}) as query:
            result = AiAdvisor.get_remediation_guidance('VMW-13.0', 'host')
        self.assertEqual(result['data_status'], 'not_applicable')
        self.assertIn('không phải CVE', query.call_args.args[3])

    def test_gemini_structured_response_is_validated(self):
        fields = ['assessment', 'uncertainties', 'recommended_actions', 'validation_steps', 'rollback_steps']
        response = Mock(status_code=200)
        response.json.return_value = {'candidates': [{'content': {'parts': [{'text': json.dumps({field: ['test'] for field in fields})}]}}]}
        with patch('core.ai_advisor.requests.post', return_value=response):
            data = AiAdvisor._query_gemini('CVE-2024-12345', 'host', 'Windows', 'title', 'High', 7.5)
        self.assertEqual(set(data['structured_advice']), set(fields))
        response.json.return_value['candidates'][0]['content']['parts'][0]['text'] = '{}'
        with patch('core.ai_advisor.requests.post', return_value=response):
            with self.assertRaises(ValueError):
                AiAdvisor._query_gemini('CVE-2024-12345', 'host', 'Windows', 'title', 'High', 7.5)

    def test_openrouter_success_does_not_reference_gemini_schema(self):
        response = Mock(status_code=200)
        response.json.return_value = {'choices': [{'message': {'content': 'Draft advice'}}]}
        with patch('core.ai_advisor.requests.post', return_value=response), patch('core.ai_advisor.Settings.OPENROUTER_API_KEY', 'test'):
            data = AiAdvisor._query_openrouter('CVE-2024-12345', 'host', 'Windows', 'title', 'High', 7.5)
        self.assertEqual(data['guidance_markdown'], 'Draft advice')


class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.digest = password_hash('test-password-123')

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / 'users.json'
        self.path.write_text(json.dumps({'users': {
            'reader': {'role': 'viewer', 'password_hash': self.digest},
            'admin': {'role': 'admin', 'password_hash': self.digest}}}))
        self.store = AuthStore(self.path)

    def test_password_is_hashed_and_bad_credentials_fail(self):
        self.assertNotIn('test-password', self.digest)
        header = 'Basic ' + base64.b64encode(b'admin:wrong').decode()
        self.assertIsNone(self.store.authenticate(header, '127.0.0.1'))

    def test_http_auth_roles_and_cross_origin(self):
        with patch.object(server, 'auth_store', self.store), patch.object(server, 'get_or_create_audit', return_value={'metrics': {}, 'servers': []}):
            httpd = ThreadingHTTPServer(('127.0.0.1', 0), server.PatchManagementHttpHandler)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            url = f'http://127.0.0.1:{httpd.server_port}'
            try:
                self.assertEqual(requests.get(url + '/api/status', timeout=3).status_code, 401)
                self.assertEqual(requests.get(url + '/api/status', auth=('reader', 'test-password-123'), timeout=3).status_code, 200)
                self.assertEqual(requests.post(url + '/api/scan', auth=('reader', 'test-password-123'), timeout=3).status_code, 403)
                self.assertEqual(requests.post(url + '/api/scan', auth=('admin', 'test-password-123'), headers={'Origin': 'https://attacker.invalid'}, timeout=3).status_code, 403)
                with patch('core.wsus_client.change_approval', side_effect=RuntimeError('offline')):
                    result = requests.post(url + '/api/approve-kb', auth=('admin', 'test-password-123'), json={'kb': 'KB1234567', 'group': 'Test'}, timeout=3)
                self.assertEqual(result.status_code, 502)
                self.assertFalse(result.json()['success'])
            finally:
                httpd.shutdown()
                httpd.server_close()

    def test_unconfigured_auth_blocks_mutations(self):
        self.path.unlink()
        self.assertEqual(self.store.users(), {})

    def test_atomic_file_replacement(self):
        target = Path(self.folder.name) / 'report.json'
        atomic_write_text(target, '{"state":"old"}')
        atomic_write_text(target, '{"state":"new"}')
        self.assertEqual(json.loads(target.read_text())['state'], 'new')
        self.assertEqual(list(Path(self.folder.name).glob('*.tmp')), [])


if __name__ == '__main__':
    unittest.main()
