import json
import logging
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.wazuh_client import WazuhClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ScaAggregator")

def build_sca_cache():
    c = WazuhClient()
    report_file = Path("reports/latest_report.json")
    if not report_file.exists():
        logger.error("latest_report.json not found")
        return None
    
    with open(report_file, "r", encoding="utf-8") as f:
        servers = json.load(f).get("servers", [])
        
    sca_cache = {
        "summary": {
            "total_misconfigurations": 0,
            "total_passed": 0,
            "total_invalid": 0,
            "total_checks": 0,
            "scanned_hosts": 0,
            "total_hosts": len(servers),
            "avg_score": 0
        },
        "gauges": {
            "firewall_disabled": {"count": 0, "hosts": []},
            "rdp_nla_disabled": {"count": 0, "hosts": []},
            "ldap_signing_missing": {"count": 0, "hosts": []},
            "agents_active": {"count": len(servers), "total": len(servers)}
        },
        "hosts": {},
        "top_rules": []
    }

    total_score = 0
    rules_map = {}
    firewall_hosts = set()
    rdp_hosts = set()
    ldap_hosts = set()

    for s in servers:
        aid = s.get("agent_id")
        aname = s.get("agent_name")
        try:
            r = c._request("GET", f"/sca/{aid}")
            items = r.get("affected_items", [])
            if items:
                p = items[0]
                pid = p.get("policy_id")
                score = p.get("score", 0)
                total_score += score
                sca_cache["summary"]["scanned_hosts"] += 1
                sca_cache["summary"]["total_misconfigurations"] += p.get("fail", 0)
                sca_cache["summary"]["total_passed"] += p.get("pass", 0)
                sca_cache["summary"]["total_invalid"] += p.get("invalid", 0)
                sca_cache["summary"]["total_checks"] += p.get("total_checks", 0)

                sca_cache["hosts"][aname] = {
                    "agent_id": aid,
                    "policy_id": pid,
                    "policy_name": p.get("name"),
                    "score": score,
                    "fail": p.get("fail"),
                    "pass": p.get("pass"),
                    "total": p.get("total_checks")
                }

                # Fetch failed checks
                chk_res = c._request("GET", f"/sca/{aid}/checks/{pid}?result=failed&limit=60")
                for chk in chk_res.get("affected_items", []):
                    cid = chk.get("id")
                    title = chk.get("title", "")
                    t_lower = title.lower()

                    if "firewall" in t_lower and "state" in t_lower:
                        firewall_hosts.add(aname)
                    if "network level authentication" in t_lower or "nla" in t_lower or "terminal services" in t_lower:
                        rdp_hosts.add(aname)
                    if "ldap" in t_lower and "signing" in t_lower:
                        ldap_hosts.add(aname)

                    if title not in rules_map:
                        # Extract CIS benchmark section or category
                        category = "Windows Security"
                        if "firewall" in t_lower:
                            category = "Windows Firewall"
                        elif "ldap" in t_lower or "domain" in t_lower or "active directory" in t_lower:
                            category = "Active Directory / Domain"
                        elif "logon" in t_lower or "password" in t_lower or "account" in t_lower:
                            category = "Account & Logon Policy"
                        elif "network" in t_lower or "smb" in t_lower:
                            category = "Network & SMB"
                        elif "audit" in t_lower:
                            category = "Audit & Logging"

                        rules_map[title] = {
                            "id": cid,
                            "title": title,
                            "description": chk.get("description", ""),
                            "rationale": chk.get("rationale", ""),
                            "remediation": chk.get("remediation", ""),
                            "policy_id": pid,
                            "category": category,
                            "hosts": []
                        }
                    rules_map[title]["hosts"].append(aname)
        except Exception as e:
            logger.warning(f"Error fetching SCA for {aname}: {e}")

    if sca_cache["summary"]["scanned_hosts"] > 0:
        sca_cache["summary"]["avg_score"] = round(total_score / sca_cache["summary"]["scanned_hosts"], 1)

    sca_cache["gauges"]["firewall_disabled"] = {"count": len(firewall_hosts), "hosts": sorted(list(firewall_hosts))}
    sca_cache["gauges"]["rdp_nla_disabled"] = {"count": len(rdp_hosts), "hosts": sorted(list(rdp_hosts))}
    sca_cache["gauges"]["ldap_signing_missing"] = {"count": len(ldap_hosts), "hosts": sorted(list(ldap_hosts))}

    sorted_rules = sorted(rules_map.values(), key=lambda x: len(x["hosts"]), reverse=True)
    sca_cache["top_rules"] = sorted_rules[:30]

    out_file = Path("reports/sca_cache.json")
    out_file.parent.mkdir(exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(sca_cache, f, indent=2, ensure_ascii=False)

    logger.info(f"SCA cache generated at {out_file} with {len(sorted_rules)} unique rules across {sca_cache['summary']['scanned_hosts']} hosts.")
    return sca_cache

if __name__ == "__main__":
    build_sca_cache()
