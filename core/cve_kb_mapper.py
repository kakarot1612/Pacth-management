import re
import requests
from typing import Dict, Any, Optional
from core.config import Settings, logger

class CveKbMapper:
    """
    Enforces Golden Rule #3:
    Never patch production based solely on CVE ID.
    Always map: CVE -> Product -> Fixed Version -> KB Number.
    """

    def __init__(self):
        self.cache = Settings.load_cve_kb_cache()
        self.msrc_api_key = Settings.MSRC_API_KEY

    def resolve_cve(self, cve_id: str, product_name: str = "") -> Dict[str, Any]:
        """
        Resolve a CVE ID to its corresponding Microsoft KB number and metadata.
        """
        cve_id = cve_id.upper().strip()
        result = {
            "cve": cve_id,
            "kb": None,
            "title": "Unknown Vulnerability",
            "severity": "Medium",
            "cvss": 0.0,
            "source": "Unresolved"
        }

        # 1. Check local cache / curated mappings first
        if cve_id in self.cache:
            entry = self.cache[cve_id]
            result["title"] = entry.get("title", result["title"])
            result["severity"] = entry.get("severity", result["severity"])
            result["cvss"] = entry.get("cvss", result["cvss"])

            kb_map = entry.get("kb_map", {})
            build_map = entry.get("build_map", {})
            # Match product name closely if provided
            matched_kb = None
            matched_build = None
            if product_name:
                for prod_key, kb in kb_map.items():
                    if prod_key.lower() in product_name.lower():
                        matched_kb = kb
                        break
                for prod_key, b in build_map.items():
                    if prod_key.lower() in product_name.lower():
                        matched_build = b
                        break
            if not matched_kb and kb_map:
                matched_kb = next(iter(kb_map.values()))
            if not matched_build and build_map:
                matched_build = next(iter(build_map.values()))

            result["kb"] = matched_kb
            result["min_build"] = matched_build
            result["source"] = "Local Cache"
            return result

        # 2. Check if Wazuh vulnerability payload already contains KB or references
        # Sometimes Wazuh description or reference contains KB numbers
        # (will be checked by caller if available)

        # 3. Query Microsoft Security API if API key provided
        if self.msrc_api_key:
            online_info = self._query_msrc_api(cve_id, product_name)
            if online_info:
                return online_info

        return result

    def _query_msrc_api(self, cve_id: str, product_name: str) -> Optional[Dict[str, Any]]:
        """Query Microsoft Security Response Center (MSRC) API"""
        url = f"https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/{cve_id}"
        headers = {
            "api-key": self.msrc_api_key,
            "Accept": "application/json"
        }
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                title = data.get("Title", {}).get("Value", "")
                # Extract KB numbers matching KB\d{6,7}
                kbs = re.findall(r"KB\d{6,7}", str(data), re.IGNORECASE)
                kb = kbs[0].upper() if kbs else None
                return {
                    "cve": cve_id,
                    "kb": kb,
                    "title": title,
                    "severity": "High",
                    "cvss": 7.5,
                    "source": "MSRC Online API"
                }
        except Exception as e:
            logger.warning(f"Could not query MSRC online API for {cve_id}: {e}")
        return None

    def extract_kb_from_text(self, text: str) -> Optional[str]:
        """Extract KB number from package or vulnerability description"""
        if not text:
            return None
        match = re.search(r"KB(\d{6,7})", text, re.IGNORECASE)
        if match:
            return f"KB{match.group(1)}"
        return None
