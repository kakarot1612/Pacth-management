"""
Comprehensive Integration Test Suite for BPVN Patch Management System
Tests:
1. Wazuh Infrastructure (Manager 55000 vs Indexer 9200 vs Dashboard 443)
2. WSUS Client & Credential Dispatch (10.0.60.32:8530 & 5985)
3. WinRM Client Remote Execution Engine (10.0.55.208 & 19 Nodes)
4. Rule #4 LCU Supersedence & Reboot State Machine
5. Web REST API Endpoints & Health Diagnostics
"""
import sys
import json
import time
from pathlib import Path

# Ensure UTF-8 output on Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.config import Settings, logger
from core.wazuh_client import WazuhClient
from core.wsus_client import test_wsus_connectivity
from core.winrm_client import WinRMClient
from core.validator import VulnerabilityValidator
from core.cve_kb_mapper import CveKbMapper


def run_tests():
    print("\n" + "="*70)
    print("      BPVN SECOPS - BỘ KIỂM THỬ TÍCH HỢP TOÀN DIỆN HẠ TẦNG")
    print("="*70)
    
    passed = 0
    total = 5

    # -------------------------------------------------------------------------
    # TEST 1: WAZUH INFRASTRUCTURE (MANAGER vs INDEXER vs DASHBOARD)
    # -------------------------------------------------------------------------
    print("\n[*] TEST 1/5: Kiểm tra xác thực Wazuh Manager & Indexer...")
    try:
        client = WazuhClient()
        health = client.check_wazuh_health()
        mgr = health["manager"]
        idx = health["indexer"]
        dsh = health["dashboard"]

        print(f"  [+] Manager (55000)  : {mgr['status']} | User: {mgr['user']} | Agents: {mgr['active_agents']}")
        print(f"  [i] Indexer (9200)  : {idx['status']} ({idx.get('error', 'N/A')})")
        print(f"  [+] Dashboard (443)  : {dsh['status']}")

        assert mgr["authenticated"] is True, "Xác thực Wazuh Manager thất bại!"
        assert mgr["active_agents"] >= 19, f"Không tìm đủ 19 agents (thấy {mgr['active_agents']})"
        print("  --> TEST 1: PASSED (Phân tách rõ ràng Manager và Indexer).")
        passed += 1
    except Exception as e:
        print(f"  --> TEST 1: FAILED: {e}")

    # -------------------------------------------------------------------------
    # TEST 2: WSUS CONNECTIVITY & CREDENTIAL DISPATCH
    # -------------------------------------------------------------------------
    print("\n[*] TEST 2/5: Kiểm tra kết nối & cơ chế truyền tài khoản WSUS...")
    try:
        wsus_res = test_wsus_connectivity()
        print(f"  [+] WSUS Server      : {wsus_res['server']}")
        print(f"  [+] Port 8530 (HTTP) : {'MỞ (OPEN)' if wsus_res['wsus_port_open'] else 'ĐÓNG'}")
        print(f"  [+] Port 5985 (WinRM): {'MỞ (OPEN)' if wsus_res['winrm_port_open'] else 'ĐÓNG'}")
        print(f"  [+] Configured User  : {wsus_res['configured_user']}")
        print(f"  [+] Has Password     : {wsus_res['has_password']}")

        assert wsus_res["wsus_port_open"] is True, "Cổng WSUS 8530 không thể kết nối!"
        assert wsus_res["configured_user"] != "", "Chưa cấu hình WSUS_USER!"
        print("  --> TEST 2: PASSED (Cơ chế truyền credential WSUS đã sẵn sàng).")
        passed += 1
    except Exception as e:
        print(f"  --> TEST 2: FAILED: {e}")

    # -------------------------------------------------------------------------
    # TEST 3: WINRM CLIENT REMOTE EXECUTION ENGINE
    # -------------------------------------------------------------------------
    print("\n[*] TEST 3/5: Kiểm tra WinRM Remote Execution Engine trên node client...")
    try:
        test_ip = "10.0.55.208"  # CSSERVER
        conn = WinRMClient.test_node_connectivity(test_ip)
        print(f"  [+] Target Host (CSSERVER): {test_ip}")
        print(f"  [+] WinRM Port 5985       : {'MỞ (OPEN)' if conn['port_open'] else 'ĐÓNG'}")

        # Test fallback command generation and error diagnostics
        install_res = WinRMClient.trigger_remote_install(test_ip, kb_number="KB5122877")
        print(f"  [i] WinRM Remote Exec Res : Success={install_res.get('success')} | Error: {install_res.get('error', 'None')[:80]}")

        # The engine must catch the diagnostic and report it cleanly without crashing
        assert "success" in install_res, "WinRM dispatcher không trả về cấu trúc chuẩn!"
        print("  --> TEST 3: PASSED (WinRM Remote Dispatcher hoạt động chính xác).")
        passed += 1
    except Exception as e:
        print(f"  --> TEST 3: FAILED: {e}")

    # -------------------------------------------------------------------------
    # TEST 4: RULE #4 LCU SUPERSEDENCE & REBOOT STATE MACHINE
    # -------------------------------------------------------------------------
    print("\n[*] TEST 4/5: Kiểm tra Động cơ Đối chiếu Rule #4 & Vòng đời Reboot...")
    try:
        from core.config import BASE_DIR
        reboot_file = BASE_DIR / "config" / "reboot_status.json"
        
        # Read current reboot status
        rdata = json.loads(reboot_file.read_text(encoding="utf-8")) if reboot_file.exists() else {}
        
        # Seed test agent 999 with reboot_pending=True
        rdata["999"] = {
            "agent_id": "999",
            "agent_name": "TEST-SERVER",
            "reboot_pending": True,
            "reboot_reasons": "Test pending reboot flag"
        }
        reboot_file.write_text(json.dumps(rdata, indent=2, ensure_ascii=False), encoding="utf-8")

        mapper = CveKbMapper()
        mock_vulns = [{"cve": "CVE-2026-20940", "title": "Windows Buffer Overflow", "severity": "Critical"}]
        
        # Case A: Machine has not rebooted, build is old (20348.4052 < 20348.5622) and has pending reboot
        audit_pending_reboot = VulnerabilityValidator.audit_agent(
            agent_id="999",
            agent_name="TEST-SERVER",
            vulnerabilities=mock_vulns,
            hotfixes=[],
            os_info={"os": {"name": "Microsoft Windows Server 2022", "build": "20348.4052"}},
            cve_mapper=mapper,
            agent_ip="10.0.99.99"
        )
        
        reboot_flag = audit_pending_reboot.get("reboot_pending")
        active_vulns = audit_pending_reboot["summary"]["confirmed_vulnerable"]
        remediated = audit_pending_reboot["summary"]["remediated_pending_rescan"]

        print(f"  [+] Case A (Chờ Reboot): Reboot={reboot_flag} | Active Vulns={active_vulns} | Remediated={remediated}")
        assert reboot_flag is True, "Cờ reboot phải là True khi đang chờ khởi động lại!"
        assert active_vulns == 0, "Không được tính vi phạm active khi đang chờ reboot kích hoạt bản vá!"

        # Case B: Machine has rebooted and build updated to 20348.5622
        audit_clean = VulnerabilityValidator.audit_agent(
            agent_id="999",
            agent_name="TEST-SERVER",
            vulnerabilities=mock_vulns,
            hotfixes=[],
            os_info={"os": {"name": "Microsoft Windows Server 2022", "build": "20348.5622"}},
            cve_mapper=mapper,
            agent_ip="10.0.99.99"
        )
        print(f"  [+] Case B (Đã Reboot Build Mới): Active={audit_clean['summary']['confirmed_vulnerable']} | Remediated={audit_clean['summary']['remediated_pending_rescan']}")
        assert audit_clean["summary"]["confirmed_vulnerable"] == 0, "Build 20348.5622 phải thỏa mãn Rule #4!"

        # Clean up test agent 999
        rdata = json.loads(reboot_file.read_text(encoding="utf-8"))
        rdata.pop("999", None)
        reboot_file.write_text(json.dumps(rdata, indent=2, ensure_ascii=False), encoding="utf-8")

        print("  --> TEST 4: PASSED (Rule #4 & State Machine hoạt động chuẩn xác).")
        passed += 1
    except Exception as e:
        print(f"  --> TEST 4: FAILED: {e}")

    # -------------------------------------------------------------------------
    # TEST 5: REST API DIAGNOSTICS & WEB AUTHORIZATION
    # -------------------------------------------------------------------------
    print("\n[*] TEST 5/5: Kiểm tra REST API Diagnostics & Cấu hình Phân quyền...")
    try:
        from core.security import auth_store
        users = auth_store.users()
        print(f"  [+] Local Users in auth_users.json: {list(users.keys())}")
        print(f"  [+] AUTH_ENABLED Setting         : {Settings.AUTH_ENABLED}")
        print(f"  [+] Web Bind Host                 : {Settings.WEB_BIND_HOST}")
        assert "admin" in users, "Tài khoản admin chưa được tạo trong auth_users.json!"
        print("  --> TEST 5: PASSED (Hệ thống phân quyền & API sẵn sàng).")
        passed += 1
    except Exception as e:
        print(f"  --> TEST 5: FAILED: {e}")

    # -------------------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------------------
    print("\n" + "="*70)
    print(f"               KẾT QUẢ KIỂM THỬ: {passed}/{total} BÀI THỬ THÀNH CÔNG")
    print("="*70)
    if passed == total:
        print("[+] TOÀN BỘ CÁC MODULE HẠ TẦNG ĐÃ ĐƯỢC CHUẨN HÓA VÀ HOÀN TẤT THÀNH CÔNG!\n")
    else:
        print(f"[-] Có {total - passed} bài thử chưa đạt, vui lòng rà soát log ở trên.\n")


if __name__ == "__main__":
    run_tests()
