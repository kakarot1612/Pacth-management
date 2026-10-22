import time
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
        if data and "affected_items" in data:
            return data["affected_items"]
        return []

    def get_agent_vulnerabilities(self, agent_id: str, severity: Optional[str] = None, os_name: str = "") -> List[Dict[str, Any]]:
        """
        Retrieve vulnerabilities for a specific agent.
        Supports both legacy Wazuh /vulnerability/{agent_id} and modern Wazuh 4.8+/4.14+
        by checking baseline security advisories matching the agent's OS.
        """
        params = {"limit": 500}
        if severity:
            params["severity"] = severity

        data = self._request("GET", f"/vulnerability/{agent_id}", params=params)
        if data and "affected_items" in data and len(data["affected_items"]) > 0:
            return data["affected_items"]

        # Fallback for modern Wazuh (4.14+)
        cache = Settings.load_cve_kb_cache()
        vulns = []
        for cve_id, info in cache.items():
            kb_map = info.get("kb_map", {})
            applies = False
            if not kb_map:
                applies = True
            elif os_name:
                for k in kb_map.keys():
                    if k.lower() in os_name.lower():
                        applies = True
                        break
            else:
                applies = True

            if applies:
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
        if data and "affected_items" in data:
            return data["affected_items"]
        return []

    def get_agent_os(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve OS build and architecture info from syscollector with /agents fallback"""
        data = self._request("GET", f"/syscollector/{agent_id}/os")
        if data and "affected_items" in data and len(data["affected_items"]) > 0:
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
        if data and "affected_items" in data:
            return data["affected_items"]
        return []

    def restart_agent(self, agent_id: str) -> bool:
        """Trigger Wazuh agent restart to force inventory sync"""
        data = self._request("PUT", f"/agents/{agent_id}/restart")
        return data is not None
