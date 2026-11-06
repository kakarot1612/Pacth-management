import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.wazuh_client import WazuhClient

def build_software_inventory():
    c = WazuhClient()
    report_file = BASE_DIR / "reports" / "latest_report.json"
    if not report_file.exists():
        print("latest_report.json not found")
        return []

    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        servers = data.get("servers", [])

    # Map of vulnerable packages from all servers' CVEs
    vulnerable_packages = {}
    for s in servers:
        aname = s.get("agent_name", "")
        for v in s.get("vulnerabilities", []):
            pkg_name = v.get("package_name", "").strip().lower()
            if pkg_name:
                if pkg_name not in vulnerable_packages:
                    vulnerable_packages[pkg_name] = []
                vulnerable_packages[pkg_name].append({
                    "cve": v.get("cve"),
                    "severity": v.get("severity", "High"),
                    "cvss": v.get("cvss", 0.0),
                    "title": v.get("title", ""),
                    "host": aname,
                    "condition": v.get("min_safe_version", "")
                })

    pkg_map = {}
    for s in servers:
        aid = s.get("agent_id")
        aname = s.get("agent_name", "")
        ip = s.get("ip", "")
        pkgs = c.get_agent_packages(aid)
        for p in pkgs:
            name = p.get("name", "").strip()
            if not name or len(name) < 2:
                continue
            vendor = p.get("vendor", "").strip() or "Standard / Microsoft"
            version = p.get("version", "").strip()
            arch = p.get("architecture", "").strip()
            key = name.lower()

            if key not in pkg_map:
                pkg_map[key] = {
                    "name": name,
                    "vendor": vendor,
                    "version": version,
                    "arch": arch,
                    "hosts": [],
                    "vulnerabilities": []
                }
            
            # Avoid duplicate host entries
            if not any(h["name"] == aname for h in pkg_map[key]["hosts"]):
                pkg_map[key]["hosts"].append({
                    "name": aname,
                    "id": aid,
                    "ip": ip,
                    "version": version
                })

    # Cross-match vulnerabilities
    total_vuln_count = 0
    for key, p in pkg_map.items():
        matched_vulns = []
        for v_pkg_name, v_list in vulnerable_packages.items():
            if v_pkg_name in key or key in v_pkg_name:
                for v in v_list:
                    # check if host matches
                    if any(h["name"] == v["host"] for h in p["hosts"]):
                        matched_vulns.append(v)
        
        # Deduplicate CVEs
        cve_seen = set()
        unique_vulns = []
        for mv in matched_vulns:
            if mv["cve"] not in cve_seen:
                cve_seen.add(mv["cve"])
                unique_vulns.append(mv)
        
        p["vulnerabilities"] = unique_vulns
        if unique_vulns:
            total_vuln_count += 1
            max_sev = "Low"
            for u in unique_vulns:
                s_u = u.get("severity", "").upper()
                if s_u == "CRITICAL":
                    max_sev = "Critical"
                    break
                elif s_u == "HIGH":
                    max_sev = "High"
                elif s_u == "MEDIUM" and max_sev != "High":
                    max_sev = "Medium"
            p["status"] = f"Vulnerable ({len(unique_vulns)} CVEs - {max_sev})"
            p["status_level"] = "danger"
            cve_names = ", ".join([u["cve"] for u in unique_vulns[:2]])
            p["action"] = f"Khắc phục ({cve_names})"
        else:
            p["status"] = "Secured (Đạt chuẩn)"
            p["status_level"] = "success"
            p["action"] = "Giám sát định kỳ"

    # Sort packages: Vulnerable packages first, then by host count descending
    sorted_packages = sorted(
        pkg_map.values(),
        key=lambda x: (len(x["vulnerabilities"]) > 0, len(x["hosts"])),
        reverse=True
    )

    out_file = BASE_DIR / "reports" / "software_inventory.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(sorted_packages, f, indent=2, ensure_ascii=False)

    print(f"Software inventory generated: {len(sorted_packages)} packages ({total_vuln_count} vulnerable).")
    return sorted_packages

if __name__ == "__main__":
    build_software_inventory()

