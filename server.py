import os
import sys
import json
import mimetypes
from pathlib import Path
from datetime import datetime
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Set UTF-8 encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from core.config import Settings, REPORTS_DIR, BASE_DIR, logger
from core.wazuh_client import WazuhClient
from core.cve_kb_mapper import CveKbMapper
from core.validator import VulnerabilityValidator
from core.sla_tracker import SlaTracker
from core.exception_manager import ExceptionManager
from core.ai_advisor import GeminiAiAdvisor
from core.reporter import AuditReporter

WEB_DIR = BASE_DIR / "web"

# In-memory cached audit results
CURRENT_AUDIT_DATA = None

def get_or_create_audit():
    global CURRENT_AUDIT_DATA
    latest_file = REPORTS_DIR / "latest_report.json"
    if latest_file.exists():
        try:
            with open(latest_file, "r", encoding="utf-8") as f:
                CURRENT_AUDIT_DATA = json.load(f)
                return CURRENT_AUDIT_DATA
        except Exception as e:
            logger.error(f"Error reading latest report: {e}")

    # Generate initial sample dataset
    from main import run_scan
    run_scan(mock=True)
    if latest_file.exists():
        with open(latest_file, "r", encoding="utf-8") as f:
            CURRENT_AUDIT_DATA = json.load(f)
            return CURRENT_AUDIT_DATA
    return {"metrics": {}, "servers": []}

class PatchManagementHttpHandler(SimpleHTTPRequestHandler):
    """Handles REST APIs and serves web static files"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def _send_json(self, status_code: int, data: dict):
        response_bytes = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(response_bytes)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            audit = get_or_create_audit()
            metrics = audit.get("metrics", {})
            servers = audit.get("servers", [])
            reboot_file = BASE_DIR / "config" / "reboot_status.json"
            reboot_data = {}
            if reboot_file.exists():
                try:
                    with open(reboot_file, "r", encoding="utf-8") as f:
                        reboot_data = json.load(f)
                except Exception:
                    pass
            reboot_pending_count = 0
            for s in servers:
                aid = str(s.get("agent_id"))
                is_p = bool(reboot_data[aid].get("reboot_pending", False)) if aid in reboot_data else bool(s.get("reboot_pending", False))
                if is_p:
                    reboot_pending_count += 1
            metrics["reboot_pending_count"] = reboot_pending_count
            self._send_json(200, {
                "status": "online",
                "wazuh_configured": Settings.is_wazuh_configured(),
                "metrics": metrics
            })
            return

        elif path == "/api/servers":
            audit = get_or_create_audit()
            servers = audit.get("servers", [])
            # Dynamically assign WSUS group from config/groups.json
            configured_groups = Settings.load_groups()
            group_names = [g.get("name") for g in configured_groups] if configured_groups else ["BPVN-Server"]
            default_group = group_names[0]

            # Load explicit reboot states
            reboot_file = BASE_DIR / "config" / "reboot_status.json"
            reboot_data = {}
            if reboot_file.exists():
                try:
                    with open(reboot_file, "r", encoding="utf-8") as f:
                        reboot_data = json.load(f)
                except Exception:
                    pass

            for s in servers:
                s["wsus_group"] = default_group
                aid = str(s.get("agent_id"))
                if aid in reboot_data:
                    s["reboot_pending"] = bool(reboot_data[aid].get("reboot_pending", False))
                    s["reboot_reasons"] = reboot_data[aid].get("reboot_reasons", s.get("reboot_reasons", ""))
                else:
                    s["reboot_pending"] = bool(s.get("reboot_pending", False))
                    s["reboot_reasons"] = s.get("reboot_reasons", "")
            self._send_json(200, {"servers": servers})
            return

        elif path.startswith("/api/server/"):
            agent_id = path.replace("/api/server/", "").strip()
            audit = get_or_create_audit()
            servers = audit.get("servers", [])
            match = next((s for s in servers if s.get("agent_id") == agent_id), None)
            if match:
                self._send_json(200, match)
            else:
                self._send_json(404, {"error": "Server not found"})
            return

        elif path == "/api/groups":
            groups = Settings.load_groups()
            self._send_json(200, {"groups": groups})
            return

        elif path == "/api/scheduler-status":
            from core.scheduler import scheduler
            self._send_json(200, scheduler.get_status())
            return

        elif path == "/api/wsus-approvals":
            approvals_file = BASE_DIR / "config" / "wsus_approvals.json"
            data = {"approvals": {}}
            if approvals_file.exists():
                try:
                    with open(approvals_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    pass
            self._send_json(200, data)
            return

        elif path == "/api/env-status":
            self._send_json(200, {
                "wazuh_api_url": Settings.WAZUH_API_URL,
                "wazuh_user": Settings.WAZUH_API_USER,
                "wazuh_configured": Settings.is_wazuh_configured(),
                "wsus_server": Settings.WSUS_SERVER_FQDN,
                "wsus_port": Settings.WSUS_PORT,
                "gemini_configured": bool(Settings.GEMINI_API_KEY)
            })
            return

        elif path == "/api/audit-logs":
            from core.audit_logger import AuditLogger
            params = parse_qs(parsed.query)
            limit = int(params.get("limit", [150])[0])
            action = params.get("action", [None])[0]
            server_filter = params.get("server", [None])[0]
            search = params.get("q", [None])[0]
            logs = AuditLogger.get_logs(limit=limit, action_filter=action, server_filter=server_filter, search=search)
            self._send_json(200, {"logs": logs, "total": len(logs)})
            return

        elif path == "/api/export-audit-csv":
            from core.audit_exporter import AuditExporter
            from core.audit_logger import AuditLogger
            audit = get_or_create_audit()
            csv_data = AuditExporter.generate_server_csv(audit.get("servers", []), audit.get("metrics", {}))
            AuditLogger.log_event("EXPORT_REPORT", details="Xuất báo cáo ma trận kiểm toán máy chủ (CSV - Excel).")
            response_bytes = csv_data.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="BPVN_Patch_Audit_Report.csv"')
            self.send_header("Content-Length", str(len(response_bytes)))
            self.end_headers()
            self.wfile.write(response_bytes)
            return

        elif path == "/api/export-vulns-csv":
            from core.audit_exporter import AuditExporter
            from core.audit_logger import AuditLogger
            audit = get_or_create_audit()
            csv_data = AuditExporter.generate_vulns_csv(audit.get("servers", []))
            AuditLogger.log_event("EXPORT_REPORT", details="Xuất báo cáo chi tiết lỗ hổng CVE và đối chiếu Rule #4 (CSV - Excel).")
            response_bytes = csv_data.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="BPVN_Vulnerability_Audit_Detail.csv"')
            self.send_header("Content-Length", str(len(response_bytes)))
            self.end_headers()
            self.wfile.write(response_bytes)
            return

        elif path == "/api/audit-report-html":
            from core.audit_exporter import AuditExporter
            audit = get_or_create_audit()
            html_data = AuditExporter.generate_printable_html_report(audit)
            response_bytes = html_data.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(response_bytes)))
            self.end_headers()
            self.wfile.write(response_bytes)
            return

        # Fallback to static web files
        if path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        payload = {}
        if body:
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                pass

        if path == "/api/scan":
            global CURRENT_AUDIT_DATA
            from main import run_scan
            from core.audit_logger import AuditLogger
            use_mock = not Settings.is_wazuh_configured()
            run_scan(mock=use_mock)
            CURRENT_AUDIT_DATA = get_or_create_audit()
            AuditLogger.log_event(
                action="SCAN_CYCLE",
                server_name="Toàn bộ 19 Máy chủ",
                agent_id="ALL",
                details=f"Hoàn tất chu kỳ rà soát lỗ hổng & Rule #4. Tỷ lệ tuân thủ: {CURRENT_AUDIT_DATA.get('metrics', {}).get('overall_compliance_percent')}%",
                source="Web UI / Admin"
            )
            self._send_json(200, {"success": True, "metrics": CURRENT_AUDIT_DATA.get("metrics", {})})
            return

        elif path == "/api/trigger-rescan":
            agent_id = str(payload.get("agent_id", "")).strip()
            if not agent_id:
                self._send_json(400, {"success": False, "message": "Thiếu mã agent_id."})
                return

            logger.info(f"Triggering live Wazuh audit & rescan for agent {agent_id}")
            if Settings.is_wazuh_configured():
                try:
                    client = WazuhClient()
                    # Best-effort restart signal
                    try:
                        client.restart_agent(agent_id)
                    except Exception:
                        pass

                    cve_mapper = CveKbMapper()
                    hotfixes = client.get_agent_hotfixes(agent_id)
                    os_info = client.get_agent_os(agent_id)
                    agent_os_name = ""
                    if os_info:
                        inner_os = os_info.get("os") if isinstance(os_info.get("os"), dict) else os_info
                        agent_os_name = inner_os.get("name") or inner_os.get("os_name", "")
                    vulns = client.get_agent_vulnerabilities(agent_id, os_name=agent_os_name)

                    agent_name = ""
                    agent_ip = ""
                    agent_data = client._request("GET", "/agents", params={"agents_list": agent_id})
                    if agent_data and "affected_items" in agent_data and len(agent_data["affected_items"]) > 0:
                        a_item = agent_data["affected_items"][0]
                        agent_name = a_item.get("name", "")
                        agent_ip = a_item.get("ip", "")

                    if not agent_name:
                        current_audit = get_or_create_audit()
                        existing_srv = next((s for s in current_audit.get("servers", []) if str(s.get("agent_id")) == agent_id), None)
                        if existing_srv:
                            agent_name = existing_srv.get("agent_name", f"Agent-{agent_id}")
                            agent_ip = existing_srv.get("ip", "")

                    new_server_audit = VulnerabilityValidator.audit_agent(
                        agent_id=agent_id,
                        agent_name=agent_name,
                        vulnerabilities=vulns,
                        hotfixes=hotfixes,
                        os_info=os_info,
                        cve_mapper=cve_mapper,
                        agent_ip=agent_ip
                    )

                    # Update in-memory and persisted report
                    current_audit = get_or_create_audit()
                    servers_list = current_audit.get("servers", [])
                    idx = next((i for i, s in enumerate(servers_list) if str(s.get("agent_id")) == agent_id), -1)
                    if idx >= 0:
                        servers_list[idx] = new_server_audit
                    else:
                        servers_list.append(new_server_audit)

                    exc_mgr = ExceptionManager()
                    updated_report = AuditReporter.generate_report(servers_list, exc_mgr.exceptions)
                    CURRENT_AUDIT_DATA = updated_report

                    from core.audit_logger import AuditLogger
                    AuditLogger.log_event(
                        action="AGENT_RESCAN",
                        server_name=agent_name,
                        agent_id=agent_id,
                        details=f"Kiểm toán live Syscollector & Rule #4: {len(new_server_audit.get('installed_hotfixes', []))} KBs đã cài. Lỗ hổng active: {new_server_audit.get('summary', {}).get('confirmed_vulnerable')}. Cần reboot: {new_server_audit.get('reboot_pending')}.",
                        source="Web UI / Admin"
                    )

                    self._send_json(200, {
                        "success": True,
                        "message": f"Đã quét lại thành công máy chủ {agent_name} (ID: {agent_id})!",
                        "server": new_server_audit,
                        "metrics": updated_report.get("metrics", {})
                    })
                except Exception as e:
                    logger.error(f"Error during agent live rescan: {e}")
                    self._send_json(500, {"success": False, "message": f"Lỗi quét lại: {str(e)}"})
            else:
                self._send_json(200, {"success": True, "message": "Chế độ mô phỏng: Đã kích hoạt quét lại thành công."})
            return

        elif path == "/api/approve-kb":
            kb = payload.get("kb", "").strip().upper()
            group = payload.get("group", "BPVN-Server").strip()
            approvals_file = BASE_DIR / "config" / "wsus_approvals.json"
            appr_data = {"approvals": {}}
            if approvals_file.exists():
                try:
                    with open(approvals_file, "r", encoding="utf-8") as f:
                        appr_data = json.load(f)
                except Exception:
                    pass

            appr_key = f"{kb}_{group}"
            existing = appr_data.get("approvals", {}).get(appr_key)
            if existing and existing.get("status") == "APPROVED":
                self._send_json(200, {
                    "success": False,
                    "already_approved": True,
                    "kb": kb,
                    "group": group,
                    "message": f"Bản vá {kb} ĐÃ ĐƯỢC PHÊ DUYỆT từ trước cho nhóm [{group}]. Hệ thống đã chặn đẩy trùng lặp!"
                })
                return

            # Record approval
            appr_data.setdefault("approvals", {})[appr_key] = {
                "kb": kb,
                "group": group,
                "status": "APPROVED",
                "approved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            try:
                with open(approvals_file, "w", encoding="utf-8") as f:
                    json.dump(appr_data, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error(f"Error saving wsus_approvals: {e}")

            logger.info(f"Approved {kb} for group {group} in WSUS")
            from core.audit_logger import AuditLogger
            AuditLogger.log_event(
                action="WSUS_APPROVE",
                server_name=f"Group: {group}",
                details=f"Phê duyệt thành công bản vá {kb} trên WSUS cho nhóm [{group}].",
                source="Web UI / Admin"
            )
            self._send_json(200, {
                "success": True,
                "already_approved": False,
                "kb": kb,
                "group": group,
                "message": f"Đã phê duyệt thành công bản vá {kb} cho nhóm [{group}]."
            })
            return

        elif path == "/api/unapprove-kb":
            kb = payload.get("kb", "").strip().upper()
            group = payload.get("group", "BPVN-Server").strip()
            approvals_file = BASE_DIR / "config" / "wsus_approvals.json"
            appr_data = {"approvals": {}}
            if approvals_file.exists():
                try:
                    with open(approvals_file, "r", encoding="utf-8") as f:
                        appr_data = json.load(f)
                except Exception:
                    pass

            appr_key = f"{kb}_{group}"
            if appr_key in appr_data.get("approvals", {}):
                appr_data["approvals"][appr_key]["status"] = "UNAPPROVED"
                appr_data["approvals"][appr_key]["unapproved_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    with open(approvals_file, "w", encoding="utf-8") as f:
                        json.dump(appr_data, f, indent=2, ensure_ascii=False)
                except Exception:
                    pass

            logger.info(f"Unapproved {kb} for group {group}")
            from core.audit_logger import AuditLogger
            AuditLogger.log_event(
                action="WSUS_UNAPPROVE",
                server_name=f"Group: {group}",
                details=f"Hủy phê duyệt bản vá {kb} trên WSUS cho nhóm [{group}].",
                source="Web UI / Admin"
            )
            self._send_json(200, {
                "success": True,
                "kb": kb,
                "group": group,
                "message": f"Đã HỦY PHÊ DUYỆT (Unapproved) bản vá {kb} khỏi nhóm [{group}]."
            })
            return

        elif path == "/api/server-reboot-status":
            agent_id = str(payload.get("agent_id", "")).strip()
            reboot_pending = bool(payload.get("reboot_pending", False))
            reboot_reasons = payload.get("reboot_reasons", "")
            reboot_file = BASE_DIR / "config" / "reboot_status.json"
            reboot_data = {}
            if reboot_file.exists():
                try:
                    with open(reboot_file, "r", encoding="utf-8") as f:
                        reboot_data = json.load(f)
                except Exception:
                    pass
            reboot_data[agent_id] = {
                "agent_id": agent_id,
                "reboot_pending": reboot_pending,
                "reboot_reasons": reboot_reasons,
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            try:
                with open(reboot_file, "w", encoding="utf-8") as f:
                    json.dump(reboot_data, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error(f"Error saving reboot status: {e}")

            logger.info(f"Updated reboot status for agent {agent_id}: pending={reboot_pending}")
            from core.audit_logger import AuditLogger
            AuditLogger.log_event(
                action="REBOOT_FLAG_CHANGE",
                server_name=f"Agent ID: {agent_id}",
                agent_id=agent_id,
                details=f"Cập nhật cờ Reboot = {reboot_pending}. Lý do: {reboot_reasons or 'Thủ công từ Admin'}",
                source="Web UI / Admin"
            )
            self._send_json(200, {
                "success": True,
                "agent_id": agent_id,
                "reboot_pending": reboot_pending,
                "message": f"Đã cập nhật trạng thái Reboot cho máy chủ (Pending={reboot_pending})."
            })
            return

        elif path == "/api/install-kb":
            kb = payload.get("kb", "").strip().upper()
            server_name = payload.get("server", "").strip()
            logger.info(f"Triggering install for {kb} on {server_name}")
            cmd = f"powershell -ExecutionPolicy Bypass -File scripts\\Install-PendingUpdates.ps1 -KbNumber {kb}"
            self._send_json(200, {
                "success": True,
                "kb": kb,
                "server": server_name,
                "command": cmd,
                "message": f"Lệnh cài đặt bản vá {kb} đã sẵn sàng thực thi trên {server_name}."
            })
            return

        elif path == "/api/gemini-advice":
            cve = payload.get("cve", "CVE-UNKNOWN")
            server = payload.get("server", "Server01")
            os_name = payload.get("os", "Windows Server")
            advice = GeminiAiAdvisor.get_remediation_guidance(
                cve_id=cve,
                server_name=server,
                os_name=os_name,
                vuln_details=payload
            )
            self._send_json(200, advice)
            return

        elif path == "/api/exception":
            mgr = ExceptionManager()
            new_exc = mgr.add_exception(
                cve=payload.get("cve"),
                server=payload.get("server"),
                reason=payload.get("reason"),
                compensating_control=payload.get("control"),
                owner=payload.get("owner", "InfraOps"),
                approved_by=payload.get("approved_by", "SecOps"),
                expiration_date=payload.get("expires", "2026-12-31")
            )
            self._send_json(200, {"success": True, "exception": new_exc})
            return

        self._send_json(404, {"error": "Endpoint not found"})

def run_server(port: int = 8080):
    from core.scheduler import scheduler
    scheduler.start()

    server_address = ("0.0.0.0", port)
    httpd = ThreadingHTTPServer(server_address, PatchManagementHttpHandler)
    print("\n" + "="*60)
    print("      HỆ THỐNG WEB QUẢN LÝ VULNERABILITY & PATCH MANAGEMENT")
    print("="*60)
    print(f"[+] Web Server đang chạy tại : http://localhost:{port}")
    print(f"[+] Giao diện điều khiển UI : http://127.0.0.1:{port}")
    print(f"[+] Trạng thái Wazuh        : {'Đã cấu hình' if Settings.is_wazuh_configured() else 'Chạy Mock / Sẵn sàng nhận .env'}")
    print(f"[+] Đặt lịch Quét Tự Động   : BẬT (Chu kỳ mỗi 30 phút tự động kiểm tra 19 agents)")
    print(f"[+] AI Gemini Advisor       : {'Kích hoạt Live Gemini API' if Settings.GEMINI_API_KEY else 'Built-in Security Expert Engine'}")
    print("-" * 60)
    print("Nhấn Ctrl+C để dừng máy chủ web.")
    print("="*60 + "\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Đang dừng máy chủ web...")
        scheduler.stop()
        httpd.server_close()

if __name__ == "__main__":
    port = int(os.getenv("WEB_PORT", "8080"))
    run_server(port)
