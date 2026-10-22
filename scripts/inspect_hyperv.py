import sys
import os
import json
from dotenv import load_dotenv
load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.wazuh_client import WazuhClient

w = WazuhClient()
w.authenticate()

all_agents = w.get_agents()
targets = [a for a in all_agents if "HYPERV01" in a.get("name", "").upper() or "HYPERV02" in a.get("name", "").upper()]

print("=" * 70)
print("            HYPER-V HOSTS AUDIT DETAILS (WAZUH LIVE)")
print("=" * 70)

for a in targets:
    aid = a.get("id")
    name = a.get("name")
    ip = a.get("ip")
    os_info = a.get("os", {})
    os_name = os_info.get("name")
    os_ver = os_info.get("version")
    os_build = os_info.get("build")
    
    print(f"\n[+] HOST: {name} (Agent ID: {aid}, IP: {ip})")
    print(f"    OS: {os_name} {os_ver} | Kernel Build: {os_build}")
    
    # Hotfixes
    hotfixes = w.get_agent_hotfixes(aid)
    hf_names = [h.get("hotfix") for h in hotfixes if h.get("hotfix")]
    print(f"    Total Installed Hotfixes ({len(hf_names)}):")
    print(f"    {sorted(hf_names)}")
    
    # Packages (to see if latest KB updates or servicing stacks appear in packages)
    packages = w.get_agent_packages(aid)
    print(f"    Total Installed Software Packages: {len(packages)}")
    kb_packages = [p for p in packages if "KB" in p.get("name", "").upper()]
    if kb_packages:
        print(f"    KB-related packages: {[p.get('name') for p in kb_packages[:10]]}")

print("\n" + "=" * 70)
