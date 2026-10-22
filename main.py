import argparse
import sys
import json
from pathlib import Path

# Ensure UTF-8 output on Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
from core.config import Settings, REPORTS_DIR, logger
from core.wazuh_client import WazuhClient
from core.cve_kb_mapper import CveKbMapper
from core.validator import VulnerabilityValidator
from core.sla_tracker import SlaTracker
from core.exception_manager import ExceptionManager
from core.notifier import AlertNotifier
from core.reporter import AuditReporter

def check_env():
    """Verify system configuration and output missing items"""
    print("\n" + "="*60)
    print("      KIỂM TRA CẤU HÌNH HỆ THỐNG & BIẾN MÔI TRƯỜNG (.env)")
    print("="*60)

    checks = [
        ("Wazuh API URL", Settings.WAZUH_API_URL, Settings.WAZUH_API_URL != "https://127.0.0.1:55000"),
        ("Wazuh User", Settings.WAZUH_API_USER, bool(Settings.WAZUH_API_USER)),
        ("Wazuh Password", "******" if Settings.WAZUH_API_PASSWORD else "", bool(Settings.WAZUH_API_PASSWORD)),
        ("WSUS Server", Settings.WSUS_SERVER_FQDN, Settings.WSUS_SERVER_FQDN != "localhost"),
        ("WSUS Port", str(Settings.WSUS_PORT), True),
        ("AD Domain", Settings.AD_DOMAIN, bool(Settings.AD_DOMAIN)),
        ("WinRM Service Account", Settings.WINRM_USER, bool(Settings.WINRM_USER)),
        ("Alert Webhook", Settings.ALERT_WEBHOOK_URL or "Chưa cấu hình", bool(Settings.ALERT_WEBHOOK_URL)),
        ("SLA P1 (Critical)", f"{Settings.SLA_P1_CRITICAL_HOURS} hours", True),
        ("SLA P2 (High)", f"{Settings.SLA_P2_HIGH_DAYS} days", True),
    ]

    all_ready = True
    for name, val, is_set in checks:
        status = "[ OK ]" if is_set else "[ CHƯA ĐIỀN ]"
        if not is_set and "Alert" not in name and "WinRM" not in name:
            all_ready = False
        print(f"{status:<15} {name:<25}: {val}")

    print("-" * 60)
    if all_ready:
        print("Trạng thái: Cấu hình cơ bản đã sẵn sàng kết nối.")
    else:
        print("LƯU Ý: Vui lòng tạo file .env từ .env.example và điền thông tin Wazuh / WSUS thực tế.")
    print("="*60 + "\n")

def test_connection():
    """Test connection to Wazuh API"""
    print("[*] Testing Wazuh API authentication...")
    client = WazuhClient()
    success = client.authenticate()
    if success:
        print("[+] Kết nối Wazuh API thành công!")
        agents = client.get_agents()
        print(f"[+] Tìm thấy {len(agents)} Windows agents đang hoạt động.")
    else:
        print("[-] Không thể xác thực với Wazuh API. Kiểm tra lại thông tin trong .env.")

def run_scan(mock: bool = False):
    """Run full vulnerability detection and Rule #4 cross-validation"""
    print("[*] Starting vulnerability audit and cross-validation cycle...")
    cve_mapper = CveKbMapper()
    exc_mgr = ExceptionManager()

    audit_results = []

    if mock or not Settings.is_wazuh_configured():
        print("[i] Đang chạy chế độ kiểm thử / mẫu (Mock Mode) với dữ liệu giả lập chuẩn...")
        # Create realistic mock dataset based on architecture
        sample_servers = [
            {
                "id": "001",
                "name": "DC01.corp.local",
                "os": {"os_name": "Windows Server 2022", "os_version": "Datacenter", "os_build": "20348.2655"},
                "hotfixes": [{"hotfix": "KB5040437"}, {"hotfix": "KB5039227"}, {"hotfix": "KB5034770"}],
                "vulns": [
                    {"cve": "CVE-2024-38077", "severity": "Critical", "cvss": 9.8, "status": "ACTIVE", "title": "Windows Remote Desktop Licensing Service RCE"},
                    {"cve": "CVE-2024-30078", "severity": "High", "cvss": 8.8, "status": "SOLVED", "title": "Windows Wi-Fi Driver RCE"}
                ]
            },
            {
                "id": "002",
                "name": "HYPERV-HOST01",
                "os": {"os_name": "Windows Server 2022", "os_version": "Datacenter", "os_build": "20348.2407"},
                "hotfixes": [{"hotfix": "KB5034770"}],
                "vulns": [
                    {"cve": "CVE-2024-38077", "severity": "Critical", "cvss": 9.8, "status": "ACTIVE", "title": "Windows Remote Desktop Licensing Service RCE"}
                ]
            },
            {
                "id": "003",
                "name": "LEGACY-APP01",
                "os": {"os_name": "Windows Server 2019", "os_version": "Standard", "os_build": "17763.5000"},
                "hotfixes": [{"hotfix": "KB5020000"}],
                "vulns": [
                    {"cve": "CVE-2023-EXAMPLE", "severity": "High", "cvss": 7.8, "status": "ACTIVE", "title": "Legacy Service Vulnerability"}
                ]
            }
        ]

        for srv in sample_servers:
            res = VulnerabilityValidator.audit_agent(
                agent_id=srv["id"],
                agent_name=srv["name"],
                vulnerabilities=srv["vulns"],
                hotfixes=srv["hotfixes"],
                os_info=srv["os"],
                cve_mapper=cve_mapper
            )
            audit_results.append(res)
    else:
        # Live Wazuh Connection
        client = WazuhClient()
        if not client.authenticate():
            print("[-] Cannot authenticate to Wazuh API. Aborting live scan.")
            return

        agents = client.get_agents(status="active", os_filter="windows")
        print(f"[+] Found {len(agents)} active Windows agents.")

        for agent in agents:
            a_id = agent.get("id")
            a_name = agent.get("name")
            print(f"[*] Auditing agent: {a_name} (ID: {a_id})...")

            hotfixes = client.get_agent_hotfixes(a_id)
            os_info = client.get_agent_os(a_id)
            agent_os_name = ""
            if os_info:
                inner_os = os_info.get("os") if isinstance(os_info.get("os"), dict) else os_info
                agent_os_name = inner_os.get("name") or inner_os.get("os_name", "")
            vulns = client.get_agent_vulnerabilities(a_id, os_name=agent_os_name)

            res = VulnerabilityValidator.audit_agent(
                agent_id=a_id,
                agent_name=a_name,
                vulnerabilities=vulns,
                hotfixes=hotfixes,
                os_info=os_info,
                cve_mapper=cve_mapper,
                agent_ip=agent.get("ip", "")
            )
            audit_results.append(res)

    # Check for P1 alerts & dispatch notifications
    for server in audit_results:
        for v in server.get("vulnerabilities", []):
            if v.get("status") == VulnerabilityValidator.STATUS_CONFIRMED_VULNERABLE:
                priority = SlaTracker.determine_priority(v, host_role=server.get("agent_name", ""))
                if priority == "P1":
                    AlertNotifier.send_emergency_alert(
                        cve_id=v.get("cve"),
                        host_name=server.get("agent_name"),
                        priority=priority,
                        details=v
                    )

    # Generate Reports
    active_exceptions = exc_mgr.exceptions
    report = AuditReporter.generate_report(audit_results, active_exceptions)

    print("\n" + "="*60)
    print("                 KẾT QUẢ KIỂM TOÁN VÁ LỖI                ")
    print("="*60)
    m = report["metrics"]
    print(f"Tổng số máy chủ       : {m['total_servers']}")
    print(f"Tổng số lỗ hổng phát hiện : {m['total_vulnerabilities']}")
    print(f"Lỗ hổng chưa vá (Active): {m['confirmed_vulnerable']} (Critical: {m['critical_confirmed']})")
    print(f"Đã vá (Chờ Wazuh Rescan): {m['remediated_pending_rescan']} [Áp dụng Rule #4 thành công!]")
    print(f"Tỷ lệ Tuân thủ (Compliance) : {m['overall_compliance_percent']}% (Mục tiêu: >= {m['target_compliance_percent']}%)")
    print(f"Trạng thái Tuân thủ   : {m['compliance_status']}")
    print(f"\n[+] Báo cáo HTML đã tạo tại : {REPORTS_DIR / 'latest_dashboard.html'}")
    print(f"[+] Dữ liệu JSON đã tạo tại : {REPORTS_DIR / 'latest_report.json'}")
    print("="*60 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Vulnerability & Patch Management Automation Toolkit")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    subparsers.add_parser("check-env", help="Check .env file and show list of required parameters")
    subparsers.add_parser("test-conn", help="Test connection to Wazuh API")
    
    scan_parser = subparsers.add_parser("scan", help="Run audit scan & cross-validation")
    scan_parser.add_argument("--mock", action="store_true", help="Run in mock/simulation mode")

    subparsers.add_parser("demo", help="Run simulated full-cycle demonstration")

    web_parser = subparsers.add_parser("web", help="Launch interactive Web Application Dashboard")
    web_parser.add_argument("--port", type=int, default=8080, help="Port to listen on (Default: 8080)")

    exc_parser = subparsers.add_parser("add-exception", help="Add a vulnerability exception")
    exc_parser.add_argument("--cve", required=True, help="CVE ID")
    exc_parser.add_argument("--server", required=True, help="Server name or *")
    exc_parser.add_argument("--reason", required=True, help="Justification")
    exc_parser.add_argument("--control", required=True, help="Compensating control")
    exc_parser.add_argument("--owner", required=True, help="Owner team")
    exc_parser.add_argument("--approved-by", required=True, help="Approver")
    exc_parser.add_argument("--expires", required=True, help="Expiration date (YYYY-MM-DD)")

    args = parser.parse_args()

    if args.command == "check-env":
        check_env()
    elif args.command == "test-conn":
        test_connection()
    elif args.command == "scan":
        run_scan(mock=args.mock)
    elif args.command == "demo":
        run_scan(mock=True)
    elif args.command == "web":
        from server import run_server
        run_server(port=args.port)
    elif args.command == "add-exception":
        mgr = ExceptionManager()
        mgr.add_exception(
            cve=args.cve,
            server=args.server,
            reason=args.reason,
            compensating_control=args.control,
            owner=args.owner,
            approved_by=args.approved_by,
            expiration_date=args.expires
        )
        print(f"[+] Đã thêm ngoại lệ thành công cho {args.cve} trên {args.server}")
    else:
        # Default behavior: if no args, run check-env and demo
        check_env()
        print("Để chạy thử hệ thống ngay bây giờ, sử dụng: python main.py demo")
        print("Để xem trợ giúp: python main.py --help")

if __name__ == "__main__":
    main()
