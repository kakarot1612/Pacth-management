import time
import json
import re
import requests
import urllib3
import logging
from typing import Dict, List, Optional, Any
from core.config import Settings, logger

# Disable SSL warnings if self-signed cert is used
if not Settings.WAZUH_VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WazuhClient:
    """Client for Wazuh REST API (Detection & Verification)"""

    # Wazuh JWT Token default validity is 15 minutes (900s).
    # We refresh proactively at 14 minutes (840s) to avoid mid-request expiration.
    TOKEN_TTL_SECONDS = 840

    def __init__(self, api_url: Optional[str] = None, user: Optional[str] = None, password: Optional[str] = None, verify_ssl: Optional[bool] = None):
        self.api_url = (api_url or Settings.WAZUH_API_URL).rstrip("/")
        self.user = user or Settings.WAZUH_API_USER
        self.password = password or Settings.WAZUH_API_PASSWORD
        self.verify_ssl = Settings.WAZUH_VERIFY_SSL if verify_ssl is None else verify_ssl
        self.token: Optional[str] = None
        self.token_created_at: float = 0.0

    def is_token_expired_or_near(self) -> bool:
        """Check if token is absent, expired, or near the 15-minute TTL limit"""
        if not self.token or self.token_created_at == 0:
            return True
        elapsed = time.time() - self.token_created_at
        return elapsed >= self.TOKEN_TTL_SECONDS

    def authenticate(self) -> bool:
        """
        Authenticate with Wazuh API (POST /security/user/authenticate)
        Returns JWT token with a 15-minute default expiration.
        """
        url = f"{self.api_url}/security/user/authenticate"
        try:
            response = requests.post(
                url,
                auth=(self.user, self.password),
                verify=self.verify_ssl,
                timeout=15
            )
            if response.status_code == 200:
                data = response.json()
                self.token = data.get("data", {}).get("token")
                self.token_created_at = time.time()
                logger.info(f"Wazuh authentication successful for user '{self.user}'. Token cached with 15m expiration.")
                return True
            else:
                logger.error(f"Wazuh auth failed with status {response.status_code}: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Failed to connect to Wazuh API at {self.api_url}: {e}")
            return False

    def _headers(self) -> Dict[str, str]:
        """
        Returns required HTTP headers.
        Attaches token with format: 'Authorization: Bearer <TOKEN>'
        Automatically renews token if older than 14 minutes.
        """
        if self.is_token_expired_or_near():
            logger.info("Wazuh token is missing or expired (> 14 minutes). Generating a new token...")
            self.authenticate()

        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

    def _request(self, method: str, endpoint: str, params: Optional[Dict] = None, data: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
        """Internal helper to execute authorized HTTP request with auto-reauth"""
        url = f"{self.api_url}{endpoint}"
        try:
            resp = requests.request(
                method=method,
                url=url,
                headers=self._headers(),
                params=params,
                json=data,
                verify=self.verify_ssl,
                timeout=30
            )
            if resp.status_code == 401:
                logger.warning("Wazuh token expired, re-authenticating...")
                if self.authenticate():
                    resp = requests.request(
                        method=method,
                        url=url,
                        headers=self._headers(),
                        params=params,
                        json=data,
                        verify=self.verify_ssl,
                        timeout=30
                    )
            if resp.status_code == 200:
                return resp.json().get("data", {})
            else:
                logger.error(f"Wazuh API request failed [{method} {endpoint}]: {resp.status_code} {resp.text}")
                return None
        except Exception as e:
            logger.error(f"Wazuh request error [{endpoint}]: {e}")
            return None

    def get_agents(self, status: str = "active", os_filter: Optional[str] = "windows") -> List[Dict[str, Any]]:
        """Retrieve list of managed Wazuh agents"""
        params = {"limit": 500}
        if status:
            params["status"] = status
        if os_filter:
            params["os.platform"] = os_filter

        data = self._request("GET", "/agents", params=params)
        if data and "affected_items" in data and len(data["affected_items"]) > 0:
            return data["affected_items"]
        return []

    def _query_indexer_vulns(self, agent_id: str, agent_name: str = "") -> List[Dict[str, Any]]:
        """
        Query Wazuh Indexer strictly via OpenSearch REST API on port 9200.
        Uses standard HTTP Basic Authentication directly to the Indexer engine.
        """
        if not Settings.WAZUH_INDEXER_URL or not Settings.WAZUH_INDEXER_USER:
            return None

        # Build search query matching by agent.id or agent.name (resilient to re-enrollment)
        should_clauses = [{"term": {"agent.id": str(agent_id)}}]
        if agent_name:
            should_clauses.append({"term": {"agent.name": str(agent_name)}})
        query = {
            "query": {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1
                }
            },
            "size": 500
        }

        try:
            indexer_url = Settings.WAZUH_INDEXER_URL.rstrip('/')
            url = f"{indexer_url}/wazuh-states-vulnerabilities-*/_search"
            auth = (Settings.WAZUH_INDEXER_USER, Settings.WAZUH_INDEXER_PASSWORD) if Settings.WAZUH_INDEXER_USER else None
            resp = requests.post(url, auth=auth, json=query, verify=self.verify_ssl, timeout=5)
            if resp.status_code == 200:
                hits = resp.json().get("hits", {}).get("hits", [])
                vulns = []
                seen = set()
                for h in hits:
                    src = h.get("_source", {})
                    v_info = src.get("vulnerability", {})
                    cve = v_info.get("cve") or v_info.get("id")
                    if cve and cve not in seen:
                        seen.add(cve)
                        score_obj = v_info.get("score", {})
                        base_score = score_obj.get("base") if isinstance(score_obj, dict) else 7.5
                        if not base_score:
                            cvss_obj = v_info.get("cvss", {})
                            base_score = cvss_obj.get("cvss3", {}).get("base_score", 7.5) if isinstance(cvss_obj, dict) else 7.5

                        pkg_info = src.get("package", {})
                        pkg_name = pkg_info.get("name", "")
                        pkg_ver = pkg_info.get("version", "")
                        category = str(v_info.get("category", "")).strip()
                        is_os_cat = (category.upper() == "OS" or "windows server" in pkg_name.lower())

                        condition = v_info.get("scanner", {}).get("condition", "")
                        cond_ver = None
                        if condition:
                            m = re.search(r'(\d+(?:\.\d+)+)', condition)
                            if m:
                                cond_ver = m.group(1)

                        # Only treat condition as an OS kernel build if category is OS and build number looks like Windows NT
                        os_min_build = None
                        app_min_safe_ver = None
                        if is_os_cat:
                            if cond_ver:
                                try:
                                    parts = [int(p) for p in cond_ver.split(".")]
                                    # e.g. 10.0.17763.8276 or 17763.8276
                                    if parts[0] >= 10000 or (parts[0] == 10 and len(parts) >= 3 and parts[2] >= 10000):
                                        os_min_build = cond_ver
                                except Exception:
                                    pass
                        else:
                            app_min_safe_ver = cond_ver

                        real_title = v_info.get("description") or v_info.get("title") or f"Lỗ hổng bảo mật {cve}"

                        vulns.append({
                            "cve": cve,
                            "title": real_title,
                            "severity": v_info.get("severity", "High"),
                            "cvss": float(base_score or 7.5),
                            "status": "ACTIVE",
                            "category": category or ("OS" if is_os_cat else "Packages"),
                            "package_name": pkg_name,
                            "package_version": pkg_ver,
                            "min_safe_version": app_min_safe_ver,
                            "condition_min_build": os_min_build,
                            "published_date": v_info.get("published_at") or "",
                            "detected_date": v_info.get("detected_at") or ""
                        })
                if vulns:
                    self.vulnerability_data_status = "fresh"
                    logger.info(f"Retrieved {len(vulns)} real vulnerabilities strictly via Wazuh Indexer port 9200 for {agent_name or agent_id}")
                    return vulns
            else:
                logger.warning(f"Wazuh Indexer (port 9200) returned HTTP {resp.status_code}")
        except Exception as e:
            logger.error(f"Wazuh Indexer query on port 9200 failed: {e}")

        return None

    def _load_exported_vulns(self, agent_id: str, agent_name: str = "") -> List[Dict[str, Any]]:
        """Load real vulnerabilities from a Wazuh Dashboard exported CSV/JSON file if present"""
        file_path = Settings.WAZUH_VULNS_FILE
        if not file_path or not file_path.exists():
            return []
        vulns = []
        try:
            if file_path.suffix.lower() == ".json":
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        if str(item.get("agent_id")) == str(agent_id) or item.get("agent_name") == agent_name:
                            vulns.append({
                                "cve": item.get("cve"),
                                "title": item.get("title", ""),
                                "severity": item.get("severity", "High"),
                                "cvss": float(item.get("cvss", 7.5)),
                                "status": item.get("status", "ACTIVE")
                            })
            elif file_path.suffix.lower() == ".csv":
                import csv
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        r_aid = str(row.get("Agent ID") or row.get("agent.id") or row.get("agent_id", "")).strip()
                        r_aname = str(row.get("Agent Name") or row.get("agent.name") or row.get("agent_name", "")).strip()
                        if r_aid == str(agent_id) or (agent_name and r_aname.lower() == agent_name.lower()):
                            cve_id = row.get("CVE") or row.get("vulnerability.cve") or row.get("cve", "")
                            if cve_id:
                                vulns.append({
                                    "cve": cve_id.strip(),
                                    "title": row.get("Title") or row.get("vulnerability.title") or row.get("title", ""),
                                    "severity": row.get("Severity") or row.get("vulnerability.severity") or "High",
                                    "cvss": float(row.get("CVSS") or row.get("cvss") or 7.5),
                                    "status": "ACTIVE"
                                })
            if vulns:
                logger.info(f"Loaded {len(vulns)} real vulnerabilities from exported Wazuh file for agent {agent_id}")
        except Exception as e:
            logger.error(f"Error parsing exported Wazuh vulnerabilities file: {e}")
        return vulns

    def get_agent_vulnerabilities(
        self,
        agent_id: str,
        severity: Optional[str] = None,
        os_name: str = "",
        installed_packages: Optional[List[Dict[str, Any]]] = None,
        agent_name: str = ""
    ) -> List[Dict[str, Any]]:
        """
        Retrieve vulnerabilities for a specific agent without fabrication.
        1. Query Wazuh Server API (/vulnerability/{agent_id}) if available.
        2. Query Wazuh Indexer (wazuh-states-vulnerabilities-*) if configured.
        3. Read from official Wazuh Dashboard CSV/JSON export if present.
        4. Factual Syscollector cross-match:
           - OS Cumulative Updates: Match baseline CVEs matching the agent's exact OS edition.
           - Application CVEs: STRICTLY check whether the software is actually installed on the host.
             If software is NOT installed, it is physically impossible to be vulnerable. NEVER infer!
        """
        self.vulnerability_data_status = "unknown"
        # 1. Wazuh Server API (Legacy endpoint)
        params = {"limit": 500}
        if severity:
            params["severity"] = severity
        data = self._request("GET", f"/vulnerability/{agent_id}", params=params)
        if data and "affected_items" in data and len(data["affected_items"]) > 0:
            self.vulnerability_data_status = "fresh"
            return data["affected_items"]

        # 2. Wazuh Indexer REST API (Port 9200 OpenSearch / Port 443 Dashboard Proxy)
        indexer_vulns = self._query_indexer_vulns(agent_id, agent_name=agent_name)
        if indexer_vulns is not None and len(indexer_vulns) > 0:
            return indexer_vulns

        # 3. Exported Wazuh Report file
        file_vulns = self._load_exported_vulns(agent_id, agent_name)
        if file_vulns:
            self.vulnerability_data_status = "stale"
            return file_vulns

        self.vulnerability_data_status = "inferred"
        # 4. Factual baseline matching with strict package verification
        cache = Settings.load_cve_kb_cache()
        vulns = []

        # Retrieve installed packages from host to prevent false positive inferences
        if installed_packages is None:
            installed_packages = self.get_agent_packages(agent_id)

        installed_pkg_names = [str(p.get("name", "")).lower() for p in installed_packages]

        for cve_id, info in cache.items():
            kb_map = info.get("kb_map", {})
            build_map = info.get("build_map", {})
            target_pkg = info.get("package_name", "").strip().lower()

            # Rule A: Application-level vulnerability (e.g. WinRAR, Outlook, Chrome)
            if target_pkg:
                # Must actually be installed on the machine
                matching_pkg = next((p for p in installed_packages if target_pkg in str(p.get("name", "")).lower()), None)
                if not matching_pkg:
                    # Package NOT installed on host -> CANNOT be vulnerable!
                    continue

                # Package is installed, check version if specified
                min_safe_ver = info.get("min_safe_version", "")
                if min_safe_ver:
                    pkg_ver = str(matching_pkg.get("version", ""))
                    # Simple version comparison
                    try:
                        p_parts = [int(x) for x in re.findall(r'\d+', pkg_ver)]
                        s_parts = [int(x) for x in re.findall(r'\d+', min_safe_ver)]
                        if p_parts and s_parts and p_parts >= s_parts:
                            # Already on safe version or newer
                            continue
                    except Exception:
                        pass

                vulns.append({
                    "cve": cve_id,
                    "title": info.get("title", f"{target_pkg} Security Vulnerability"),
                    "severity": info.get("severity", "High"),
                    "cvss": info.get("cvss", 7.5),
                    "status": "ACTIVE"
                })
                continue

            # Rule B: OS-level Windows Cumulative Update vulnerability
            if kb_map or build_map:
                applies_to_os = False
                if os_name:
                    for k in kb_map.keys():
                        if k.lower() in os_name.lower():
                            applies_to_os = True
                            break
                    if not applies_to_os:
                        for k in build_map.keys():
                            if k.lower() in os_name.lower():
                                applies_to_os = True
                                break

                if applies_to_os:
                    vulns.append({
                        "cve": cve_id,
                        "title": info.get("title", ""),
                        "severity": info.get("severity", "High"),
                        "cvss": info.get("cvss", 7.5),
                        "status": "ACTIVE"
                    })

        return vulns

    def get_agent_hotfixes(self, agent_id: str) -> List[Dict[str, Any]]:
        """Retrieve syscollector hotfix inventory for an agent"""
        data = self._request("GET", f"/syscollector/{agent_id}/hotfixes", params={"limit": 500})
        if data and "affected_items" in data and len(data["affected_items"]) > 0:
            return data["affected_items"]
        return []

    def get_agent_os(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve OS build and architecture info from syscollector with /agents fallback"""
        data = self._request("GET", f"/syscollector/{agent_id}/os")
        if data and "affected_items" in data and len(data["affected_items"]) > 0:
            self.vulnerability_data_status = "fresh"
            return data["affected_items"][0]
        # Fallback to agent metadata if syscollector hasn't synced OS table
        agent_data = self._request("GET", "/agents", params={"agents_list": agent_id})
        if agent_data and "affected_items" in agent_data and len(agent_data["affected_items"]) > 0:
            item = agent_data["affected_items"][0]
            if "os" in item and isinstance(item["os"], dict):
                return {"os": item["os"]}
        return None

    def get_agent_packages(self, agent_id: str) -> List[Dict[str, Any]]:
        """Retrieve installed application packages from syscollector"""
        data = self._request("GET", f"/syscollector/{agent_id}/packages", params={"limit": 500})
        if data and "affected_items" in data and len(data["affected_items"]) > 0:
            return data["affected_items"]
        return []

    def restart_agent(self, agent_id: str) -> bool:
        """Trigger Wazuh agent restart to force inventory sync"""
        data = self._request("PUT", f"/agents/{agent_id}/restart")
        return data is not None

    def check_wazuh_health(self):
        import socket
        res = {
            'manager': {'url': self.api_url, 'port': 55000, 'user': Settings.WAZUH_API_USER, 'authenticated': False, 'active_agents': 0, 'status': 'OFFLINE'},
            'indexer': {'url': Settings.WAZUH_INDEXER_URL or 'https://10.0.55.249:9200', 'port': 9200, 'user': Settings.WAZUH_INDEXER_USER or 'Not configured', 'accessible': False, 'status': 'OFFLINE_OR_FIREWALLED'},
            'dashboard': {'url': Settings.WAZUH_DASHBOARD_URL, 'port': 443, 'accessible': False, 'status': 'OFFLINE'}
        }
        try:
            if self.authenticate():
                agents = self.get_agents()
                res['manager']['authenticated'] = True
                res['manager']['active_agents'] = len(agents)
                res['manager']['status'] = 'CONNECTED'
        except Exception as e:
            res['manager']['error'] = str(e)

        s = socket.socket()
        s.settimeout(2.0)
        try:
            s.connect(('10.0.55.249', 9200))
            res['indexer']['accessible'] = True
            res['indexer']['status'] = 'PORT_OPEN'
        except Exception as e:
            res['indexer']['error'] = str(e)
        finally:
            s.close()

        s2 = socket.socket()
        s2.settimeout(2.0)
        try:
            s2.connect(('10.0.55.249', 443))
            res['dashboard']['accessible'] = True
            res['dashboard']['status'] = 'CONNECTED'
        except Exception as e:
            res['dashboard']['error'] = str(e)
        finally:
            s2.close()
        return res
