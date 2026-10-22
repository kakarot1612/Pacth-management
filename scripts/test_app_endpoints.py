import requests
import json
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

base_url = "http://localhost:8080"

print("=" * 60)
print("       PATCH MANAGEMENT WEB APP API HEALTH CHECK")
print("=" * 60)

get_endpoints = [
    "/api/status",
    "/api/servers",
    "/api/groups",
    "/api/scheduler-status",
    "/api/wsus-approvals",
    "/api/env-status"
]

for ep in get_endpoints:
    url = f"{base_url}{ep}"
    try:
        r = requests.get(url, timeout=10)
        status = r.status_code
        data = r.json()
        print(f"[+] GET {ep:<25} -> Status: {status}")
        if ep == "/api/status":
            print(f"    - Online: {data.get('status')}, Wazuh Configured: {data.get('wazuh_configured')}")
            print(f"    - Metrics: {data.get('metrics', {})}")
        elif ep == "/api/servers":
            servers = data.get("servers", [])
            print(f"    - Active Servers count: {len(servers)}")
            if servers:
                s0 = servers[0]
                print(f"    - Sample: ID={s0.get('agent_id')} Name={s0.get('agent_name')} IP={s0.get('ip')} Group={s0.get('wsus_group')}")
                print(f"      Installed Hotfixes: {len(s0.get('installed_hotfixes', []))}, Missing KBs: {len(s0.get('missing_kbs', []))}")
        elif ep == "/api/groups":
            groups = data.get("groups", [])
            print(f"    - Configured Groups: {[g.get('name') for g in groups]}")
        elif ep == "/api/scheduler-status":
            print(f"    - Auto Vulnerability Scanner: Running={data.get('running')}, Interval={data.get('interval_minutes')}m, Last={data.get('last_run')}")
        elif ep == "/api/wsus-approvals":
            print(f"    - Tracked Approvals: {list(data.get('approvals', {}).keys())}")
    except Exception as e:
        print(f"[-] GET {ep:<25} -> ERROR: {e}")

# Test Approval Workflow (State tracking & prevent duplicate)
print("\n[*] Testing Approval Logic API:")
test_kb = "KB5040437"
test_group = "BPVN-Server"

# Test 1: Approve
try:
    r = requests.post(f"{base_url}/api/approve-kb", json={"kb": test_kb, "group": test_group}, timeout=10)
    res = r.json()
    print(f"  -> 1. Approve {test_kb}: Success={res.get('success')} | Message: {res.get('message')}")
except Exception as e:
    print(f"  -> 1. Approve failed: {e}")

# Test 2: Approve again (should inform already approved / prevent duplicate)
try:
    r = requests.post(f"{base_url}/api/approve-kb", json={"kb": test_kb, "group": test_group}, timeout=10)
    res = r.json()
    print(f"  -> 2. Re-Approve {test_kb} (Duplicate check): Success={res.get('success')}, AlreadyApproved={res.get('already_approved')} | Message: {res.get('message')}")
except Exception as e:
    print(f"  -> 2. Re-Approve check failed: {e}")

# Test 3: Unapprove
try:
    r = requests.post(f"{base_url}/api/unapprove-kb", json={"kb": test_kb, "group": test_group}, timeout=10)
    res = r.json()
    print(f"  -> 3. Unapprove {test_kb}: Success={res.get('success')} | Message: {res.get('message')}")
except Exception as e:
    print(f"  -> 3. Unapprove check failed: {e}")

# Test 4: Trigger Scan
print("\n[*] Testing Vulnerability Scan Trigger API:")
try:
    r = requests.post(f"{base_url}/api/scan", timeout=15)
    res = r.json()
    print(f"  -> POST /api/scan: Success={res.get('success')} | Metrics: {res.get('metrics')}")
except Exception as e:
    print(f"  -> POST /api/scan failed: {e}")

print("=" * 60)
