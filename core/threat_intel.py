"""Evidence-based enrichment. Unknown is distinct from false and zero."""
import json
import re
import time
import threading
from typing import List, Dict
from datetime import datetime, timezone
import requests
from core.config import Settings, logger


class ThreatIntelEngine:
    _cache = {}
    _cache_timestamps = {}
    CACHE_TTL_SECONDS = 3600
    _kev_cache = None
    _kev_time = 0
    _kev_lock = threading.Lock()
    KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    EPSS_URL = 'https://api.first.org/data/v1/epss'

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _number(value, maximum=1):
        try:
            if isinstance(value, bool):
                return None
            number = float(value)
            return number if 0 <= number <= maximum else None
        except (TypeError, ValueError):
            return None

    @classmethod
    def _empty_intel(cls, cve_id, title='', severity='High', cvss=0):
        return dict(cve=cve_id, source='Unavailable', data_status='unknown',
                    fetched_at=cls._now(), observed_at=None, evidence=[],
                    epss_score=None, epss_percentile=None, epss_percentage_text='N/A',
                    is_cisa_kev=None, kev_details={}, has_public_poc=None,
                    mitre_attack=[], mitre_attack_status='unknown',
                    composite_risk_score=None, ssvc_decision='Unknown')

    @classmethod
    def get_cve_intel(cls, cve_id, title='', severity='High', cvss=7.5):
        cve = str(cve_id).strip().upper()
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve):
            return cls._empty_intel(cve)
        cached = cls._cache.get(cve)
        if cached and time.time() - cls._cache_timestamps.get(cve, 0) < cls.CACHE_TTL_SECONDS:
            return dict(cached)
        intel = cls._query_mcp_server(cve) if Settings.CVE_MCP_ENABLED else None
        if not intel or intel['data_status'] == 'unknown':
            intel = cls._query_direct_threat_feeds(cve, title, severity, cvss)
        if intel['data_status'] == 'unknown' and cached:
            return dict(cached, data_status='stale', refresh_failed_at=cls._now())
        cls._cache[cve] = intel
        # Failed lookups retry soon rather than hiding a recovery for one hour.
        cls._cache_timestamps[cve] = time.time() if intel['data_status'] != 'unknown' else time.time() - cls.CACHE_TTL_SECONDS + 60
        return dict(intel)

    @classmethod
    def _query_mcp_server(cls, cve_id):
        headers = {'Accept': 'application/json, text/event-stream'}
        if Settings.CVE_MCP_HOST:
            headers['Host'] = Settings.CVE_MCP_HOST
        payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                   'params': {'name': 'triage_cve', 'arguments': {'cve_id': cve_id, 'depth': 'quick'}}}
        try:
            with requests.post(Settings.CVE_MCP_URL, headers=headers, json=payload,
                               stream=True, timeout=Settings.CVE_MCP_TIMEOUT) as response:
                response.raise_for_status()
                if 'application/json' in response.headers.get('Content-Type', ''):
                    message = response.json()
                else:
                    message = None
                    started = time.monotonic()
                    size = 0
                    for line in response.iter_lines():
                        size += len(line)
                        if size > 1_000_000 or time.monotonic() - started > Settings.CVE_MCP_TIMEOUT:
                            break
                        if line.startswith(b'data:'):
                            candidate = json.loads(line[5:].strip())
                            if candidate.get('id') == 1 and 'result' in candidate:
                                message = candidate
                                break
                if not message or message.get('error'):
                    return None
                result = message.get('result', {})
                if result.get('isError'):
                    return None
                structured = result.get('structuredContent')
                raw = json.dumps(structured) if structured else ''.join(
                    item.get('text', '') for item in result.get('content', []) if item.get('type') == 'text')
                return cls._parse_mcp_triage_result(cve_id, raw)
        except (requests.RequestException, ValueError, TypeError) as error:
            logger.warning('MCP enrichment unavailable: %s', type(error).__name__)
            return None

    @classmethod
    def _parse_mcp_triage_result(cls, cve_id, raw_text):
        intel = cls._empty_intel(cve_id)
        intel['source'] = 'CVE MCP'
        try:
            data = json.loads(raw_text)
            if not isinstance(data, dict) or data.get('cve', cve_id) != cve_id:
                return intel
            intel['epss_score'] = cls._number(data.get('epss_score'))
            intel['epss_percentile'] = cls._number(data.get('epss_percentile'))
            # Only explicit booleans are accepted; string 'false' must never become True.
            kev = data.get('is_cisa_kev', data.get('is_kev', data.get('cisa_kev')))
            intel['is_cisa_kev'] = kev if isinstance(kev, bool) else None
            refs = data.get('poc_references', [])
            refs = [url for url in refs if isinstance(url, str) and url.startswith('https://')] if isinstance(refs, list) else []
            intel['has_public_poc'] = True if refs else None
            intel['poc_references'] = refs
            intel['kev_details'] = data.get('kev_details', {})
            intel['observed_at'] = data.get('observed_at')
            for field in ('epss_score', 'is_cisa_kev', 'has_public_poc'):
                if intel[field] is not None:
                    intel['evidence'].append({'field': field, 'source': Settings.CVE_MCP_URL,
                                              'observed_at': intel['observed_at'], 'fetched_at': intel['fetched_at']})
        except (ValueError, TypeError):
            # Unstructured prose is advisory only, not verified telemetry.
            intel['raw_summary'] = str(raw_text)[:600]
        return cls._finish(intel)

    @classmethod
    def _query_direct_threat_feeds(cls, cve_id, title='', severity='High', cvss=7.5):
        intel = cls._empty_intel(cve_id)
        intel['source'] = 'FIRST EPSS / CISA KEV'
        try:
            response = requests.get(cls.EPSS_URL, params={'cve': cve_id}, timeout=4)
            response.raise_for_status()
            rows = response.json().get('data', [])
            item = next((row for row in rows if row.get('cve') == cve_id), None)
            if item:
                intel['epss_score'] = cls._number(item.get('epss'))
                intel['epss_percentile'] = cls._number(item.get('percentile'))
                if intel['epss_score'] is not None:
                    intel['evidence'].append({'field': 'epss_score', 'source': cls.EPSS_URL,
                                              'observed_at': item.get('date'), 'fetched_at': intel['fetched_at']})
        except (requests.RequestException, ValueError, TypeError):
            pass
        with cls._kev_lock:
            if cls._kev_cache is None or time.time() - cls._kev_time > cls.CACHE_TTL_SECONDS:
                try:
                    response = requests.get(cls.KEV_URL, timeout=5)
                    response.raise_for_status()
                    catalog = response.json()
                    if not isinstance(catalog.get('vulnerabilities'), list):
                        raise ValueError('Invalid KEV catalog')
                    cls._kev_cache = catalog
                    cls._kev_time = time.time()
                except (requests.RequestException, ValueError, TypeError):
                    pass
            catalog = cls._kev_cache
            if catalog is not None:
                match = next((row for row in catalog['vulnerabilities'] if row.get('cveID') == cve_id), None)
                intel['is_cisa_kev'] = match is not None
                intel['kev_details'] = match or {}
                stale = time.time() - cls._kev_time > cls.CACHE_TTL_SECONDS
                intel['evidence'].append({'field': 'is_cisa_kev', 'source': cls.KEV_URL,
                                          'observed_at': catalog.get('dateReleased'),
                                          'fetched_at': datetime.fromtimestamp(cls._kev_time, timezone.utc).isoformat(),
                                          'status': 'stale' if stale else 'fresh'})
        intel['mitre_attack'] = cls._map_mitre_attack(cve_id, title)
        intel['mitre_attack_status'] = 'heuristic'
        return cls._finish(intel)

    @classmethod
    def _finish(cls, intel):
        epss = intel['epss_score']
        intel['epss_percentage_text'] = f'{epss * 100:.1f}%' if epss is not None else 'N/A'
        known = sum(intel[field] is not None for field in ('epss_score', 'is_cisa_kev', 'has_public_poc'))
        intel['data_status'] = 'fresh' if known == 3 else ('partial' if known else 'unknown')
        if any(row.get('status') == 'stale' for row in intel['evidence']):
            intel['data_status'] = 'stale'
        # A partial feed cannot support a complete numerical risk assessment.
        intel['ssvc_decision'] = 'Act' if intel['is_cisa_kev'] is True else 'Unknown'
        return intel

    @classmethod
    def _map_mitre_attack(cls, cve_id: str, title: str) -> List[Dict[str, str]]:
        """
        Maps CVE characteristics to MITRE ATT&CK Tactics & Techniques
        """
        title_lower = title.lower()
        tactics = []

        if any(w in title_lower for w in ["remote code execution", "rce", "arbitrary code"]):
            tactics.append({
                "id": "T1203",
                "name": "Exploitation for Client Execution",
                "tactic": "Execution"
            })
            tactics.append({
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access"
            })

        if any(w in title_lower for w in ["elevation of privilege", "privilege escalation", "eop"]):
            tactics.append({
                "id": "T1068",
                "name": "Exploitation for Privilege Escalation",
                "tactic": "Privilege Escalation"
            })

        if any(w in title_lower for w in ["smb", "netlogon", "active directory", "rpc"]):
            tactics.append({
                "id": "T1021.002",
                "name": "Remote Services: SMB/Windows Admin Shares",
                "tactic": "Lateral Movement"
            })

        if any(w in title_lower for w in ["outlook", "mail", "phishing", "moniker"]):
            tactics.append({
                "id": "T1566.002",
                "name": "Phishing: Spearphishing Link",
                "tactic": "Initial Access"
            })

        if not tactics:
            tactics.append({
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access"
            })

        return tactics

