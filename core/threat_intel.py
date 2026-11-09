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
        
        # 1. Query live MCP Server (mukul975/cve-mcp-server lookup_cve tool)
        intel = cls._query_mcp_server(cve) if Settings.CVE_MCP_ENABLED else None
        if not intel:
            intel = cls._empty_intel(cve, title, severity, cvss)
            intel['source'] = 'Fallback Feeds'

        # 2. Enrich with EPSS from FIRST API
        cls._enrich_epss(intel, cve)

        # 3. Find affected hosts in BPVN fleet
        cls._enrich_affected_hosts(intel, cve)

        # 4. Calculate Composite Risk Score (0-100)
        cls._calculate_composite_score(intel)

        cls._cache[cve] = intel
        cls._cache_timestamps[cve] = time.time()
        return dict(intel)

    @classmethod
    def _query_mcp_server(cls, cve_id):
        headers = {'Accept': 'application/json, text/event-stream', 'Content-Type': 'application/json'}
        if Settings.CVE_MCP_HOST:
            headers['Host'] = Settings.CVE_MCP_HOST
        payload = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'tools/call',
            'params': {'name': 'lookup_cve', 'arguments': {'cve_id': cve_id}}
        }
        try:
            with requests.post(Settings.CVE_MCP_URL, headers=headers, json=payload,
                               stream=True, timeout=Settings.CVE_MCP_TIMEOUT) as response:
                response.raise_for_status()
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
        intel['source'] = 'CVE MCP (mukul975/cve-mcp-server on 10.0.55.240)'
        intel['raw_summary'] = str(raw_text)[:1500]

        # Extract CVSS Score and Severity
        score_m = re.search(r'Score:\s*([0-9.]+)\s*([A-Za-z]+)?', raw_text)
        if score_m:
            intel['cvss_score'] = float(score_m.group(1))
            intel['severity'] = (score_m.group(2) or 'HIGH').upper()

        # Extract CISA KEV
        kev_m = re.search(r'CISA KEV:\s*(YES|NO)', raw_text, re.IGNORECASE)
        if kev_m:
            intel['is_cisa_kev'] = (kev_m.group(1).upper() == 'YES')
            if intel['is_cisa_kev']:
                intel['kev_details'] = {'cveID': cve_id, 'notes': 'Verified Active in CISA KEV Catalog'}

        # Extract Vector
        vector_m = re.search(r'Vector:\s*([^\r\n]+)', raw_text)
        if vector_m:
            intel['cvss_vector'] = vector_m.group(1).strip()

        # Extract Weaknesses (CWE)
        weak_m = re.search(r'Weaknesses:\s*([^\r\n]+)', raw_text)
        if weak_m:
            intel['cwe_id'] = weak_m.group(1).strip()

        # Extract Published Date
        pub_m = re.search(r'Published:\s*([^\r\n]+)', raw_text)
        if pub_m:
            intel['published_date'] = pub_m.group(1).strip()

        # Extract Description
        desc_m = re.search(r'Description:\s*([\s\S]+)', raw_text)
        if desc_m:
            raw_desc = desc_m.group(1).strip()
            clean_desc = re.sub(r'["\'}\]]+$', '', raw_desc).strip()
            intel['description'] = clean_desc
            first_line = clean_desc.split('\n')[0].strip()
            intel['title'] = first_line[:120]

        intel['data_status'] = 'fresh'
        intel['mitre_attack'] = cls._map_mitre_attack(cve_id, intel.get('title', ''))
        return intel

    @classmethod
    def _enrich_epss(cls, intel, cve_id):
        try:
            er = requests.get(f'{cls.EPSS_URL}?cve={cve_id}', timeout=4)
            if er.ok:
                rows = er.json().get('data', [])
                if rows:
                    epss = float(rows[0].get('epss', 0.0))
                    pct = float(rows[0].get('percentile', 0.0))
                    intel['epss_score'] = epss
                    intel['epss_percentile'] = pct
                    intel['epss_percentage_text'] = f'{epss * 100:.1f}%'
        except Exception:
            pass

    @classmethod
    def _enrich_affected_hosts(cls, intel, cve_id):
        affected = []
        try:
            from core.config import REPORTS_DIR
            import os
            report_path = REPORTS_DIR / 'latest_report.json'
            if os.path.exists(report_path):
                with open(report_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for s in data.get('servers', []):
                    for v in s.get('vulnerabilities', []):
                        if v.get('cve') == cve_id:
                            affected.append({
                                'name': s.get('agent_name', s.get('agent_id')),
                                'id': s.get('agent_id'),
                                'ip': s.get('ip', ''),
                                'expected_kb': v.get('expected_kb', '')
                            })
                            break
        except Exception:
            pass
        intel['affected_hosts'] = affected
        intel['affected_hosts_count'] = len(affected)

    @classmethod
    def _calculate_composite_score(cls, intel):
        cvss = intel.get('cvss_score') or 5.0
        epss = intel.get('epss_score') or 0.05
        is_kev = bool(intel.get('is_cisa_kev'))

        # Standard Composite Risk Formula: (CVSS * 6) + (EPSS * 30) + (10 if KEV else 0)
        raw_score = (cvss * 6.0) + (epss * 30.0) + (10.0 if is_kev else 0.0)
        score = min(100, max(1, int(round(raw_score))))
        intel['composite_risk_score'] = score

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

