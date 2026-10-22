import os
import json
from dotenv import load_dotenv
load_dotenv()
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.wazuh_client import WazuhClient

w = WazuhClient()
print("=" * 60)
print("           WAZUH INTEGRATION HEALTH CHECK")
print("=" * 60)
print(f"[*] API URL: {w.api_url}")
print(f"[*] User   : {w.user}")

if w.authenticate():
    print("[+] Status: AUTHENTICATED SUCCESSFULLY (JWT Token Valid)")
    agents = w.get_agents()
    print(f"[+] Total Windows Agents active: {len(agents)}")
    for a in agents:
        aid = a.get("id")
        name = a.get("name")
        ip = a.get("ip")
        os_info = a.get("os", {})
        os_name = f"{os_info.get('name', '')} {os_info.get('version', '')} ({os_info.get('build', '')})"
        print(f"    - [{aid}] {name:<20} | IP: {ip:<15} | OS: {os_name}")
    
    # Check hotfixes on first 3 agents
    print("\n[*] Testing Syscollector Hotfix Retrieval:")
    for a in agents[:3]:
        aid = a.get("id")
        name = a.get("name")
        hfs = w.get_agent_hotfixes(aid)
        hf_names = [h.get("hotfix") for h in hfs[:4]]
        print(f"    - Agent {name}: {len(hfs)} installed hotfixes detected. Samples: {hf_names}")
else:
    print("[-] FAILED to authenticate to Wazuh API")
