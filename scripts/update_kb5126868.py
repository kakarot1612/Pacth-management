import json

# 1. Update config/cve_kb_cache.json
cache_file = "config/cve_kb_cache.json"
with open(cache_file, "r", encoding="utf-8") as f:
    text = f.read()

new_text = text.replace('"Windows Server 2016": "KB5123099"', '"Windows Server 2016": "KB5126868"')
with open(cache_file, "w", encoding="utf-8") as f:
    f.write(new_text)
print("Updated config/cve_kb_cache.json with KB5126868")

# 2. Update config/wsus_approvals.json
wsus_file = "config/wsus_approvals.json"
with open(wsus_file, "r", encoding="utf-8") as f:
    wsus_data = json.load(f)

approvals = wsus_data.setdefault("approvals", {})
if "KB5126868_BPVN-Server" not in approvals:
    approvals["KB5126868_BPVN-Server"] = {
        "kb": "KB5126868",
        "group": "BPVN-Server",
        "status": "APPROVED",
        "approved_at": "2026-10-21 08:30:00",
        "source": "WSUS Push / 2026-10 Cumulative Update"
    }

if "KB5126649_BPVN-Server" not in approvals:
    approvals["KB5126649_BPVN-Server"] = {
        "kb": "KB5126649",
        "group": "BPVN-Server",
        "status": "APPROVED",
        "approved_at": "2026-10-21 08:30:00",
        "source": "WSUS Push / 2026-10 Servicing Stack Update"
    }

with open(wsus_file, "w", encoding="utf-8") as f:
    json.dump(wsus_data, f, indent=2, ensure_ascii=False)
print("Updated config/wsus_approvals.json with KB5126868 & KB5126649")
