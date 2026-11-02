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
from core.wsus_client import test_wsus_connectivity
from core.cve_kb_mapper import CveKbMapper
from core.validator import VulnerabilityValidator
from core.sla_tracker import SlaTracker
from core.exception_manager import ExceptionManager
from core.ai_advisor import GeminiAiAdvisor, AiAdvisor
from core.reporter import AuditReporter
from core.security import auth_store

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
                try:
                    age = (datetime.now() - datetime.strptime(CURRENT_AUDIT_DATA['generated_at'], '%Y-%m-%d %H:%M:%S')).total_seconds()
                    state = 'stale' if age > Settings.DATA_MAX_AGE_MINUTES * 60 else CURRENT_AUDIT_DATA.get('data_status', 'unknown')
                except (KeyError, ValueError, TypeError):
                    state = 'unknown'
                CURRENT_AUDIT_DATA['data_status'] = state
                if state in ('stale', 'unknown', 'partial', 'demo'):
                    CURRENT_AUDIT_DATA.setdefault('metrics', {})['compliance_status'] = 'UNVERIFIED'
                return CURRENT_AUDIT_DATA
        except Exception as e:
            logger.error(f"Error reading latest report: {e}")

    # Never manufacture demo inventory on a configured live installation.
    from main import run_scan
    run_scan(mock=not Settings.is_wazuh_configured())
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
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(response_bytes)

    def _authorize(self, path, mutation=False):
        origin = self.headers.get("Origin")
        if mutation and (self.headers.get("Sec-Fetch-Site") == "cross-site" or
                         (origin and urlparse(origin).netloc != self.headers.get("Host"))):
            self._send_json(403, {"success": False, "message": "Cross-origin request denied."})
            return False
        if not Settings.AUTH_ENABLED:
            self.auth_user = {"username": "local_admin", "role": "admin"}
            return True

        if not auth_store.users():
            if mutation or path.startswith("/api/"):
                self._send_json(503, {"success": False, "message": "Chưa có tài khoản. Chạy python scripts/manage_users.py admin --role admin trên máy chủ."})
                return False
            return True
        user = auth_store.authenticate(self.headers.get("Authorization"), self.client_address[0])
        if not user:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="BPVN Patch Management", charset="UTF-8"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False
        if mutation and not auth_store.allowed(user, path):
            self._send_json(403, {"success": False, "message": "Tài khoản không có quyền thực hiện thao tác."})
            return False
        self.auth_user = user
        return True

    def do_OPTIONS(self):
        self._send_json(405, {"error": "Cross-origin API access is disabled."})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if not self._authorize(path):
            return

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
                "data_status": audit.get("data_status", "unknown"),
                "generated_at": audit.get("generated_at"),
                "ai_provider": Settings.AI_PROVIDER,
                "metrics": metrics
            })
            return

        elif path == "/api/infra-health":
            wazuh_health = WazuhClient().check_wazuh_health()
            wsus_health = test_wsus_connectivity()
            self._send_json(200, {
                "wazuh": wazuh_health,
                "wsus": wsus_health,
                "ai": {
                    "provider": Settings.AI_PROVIDER,
                    "configured": Settings.is_ai_configured(),
                    "gemini_model": Settings.GEMINI_MODEL
                },
                "mcp": {
                    "url": Settings.CVE_MCP_URL,
                    "enabled": Settings.CVE_MCP_ENABLED
                },
                "auth": {
                    "enabled": Settings.AUTH_ENABLED,
                    "users_count": len(auth_store.users())
                }
            })
            return

        elif path == "/api/mcp-health":
            import requests, time
            start = time.time()
            mcp_url = Settings.CVE_MCP_URL
            headers = {"Host": Settings.CVE_MCP_HOST} if Settings.CVE_MCP_HOST else {}
            try:
                r = requests.get(mcp_url, headers=headers, timeout=2.5)
                latency = round((time.time() - start) * 1000, 1)
                self._send_json(200, {
                    "status": "connected" if r.status_code in (200, 404, 405) else "misconfigured",
                    "status_code": r.status_code,
                    "latency_ms": latency,
                    "url": mcp_url,
                    "host": Settings.CVE_MCP_HOST,
                    "enabled": Settings.CVE_MCP_ENABLED,
                    "fallback_ready": True
                })
            except Exception as e:
                self._send_json(200, {
                    "status": "offline_or_blocked",
                    "error": str(e),
                    "url": mcp_url,
                    "host": Settings.CVE_MCP_HOST,
                    "enabled": Settings.CVE_MCP_ENABLED,
                    "fallback_ready": True
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

            from core.threat_intel import ThreatIntelEngine
            for s in servers:
                s["wsus_group"] = default_group
                aid = str(s.get("agent_id"))
                if aid in reboot_data:
                    s["reboot_pending"] = bool(reboot_data[aid].get("reboot_pending", False))
                    s["reboot_reasons"] = reboot_data[aid].get("reboot_reasons", s.get("reboot_reasons", ""))
                else:
                    s["reboot_pending"] = bool(s.get("reboot_pending", False))
                    s["reboot_reasons"] = s.get("reboot_reasons", "")

                # Enrich active & pending vulnerabilities with Threat Intelligence
                for v in s.get("vulnerabilities", []):
                    c_id = v.get("cve")
                    if c_id and not v.get("threat_intel"):
                        try:
                            v["threat_intel"] = ThreatIntelEngine.get_cve_intel(
                                c_id,
                                title=v.get("title", ""),
                                severity=v.get("severity", "High"),
                                cvss=float(v.get("cvss", 7.5))
                            )
                        except Exception:
                            pass

            self._send_json(200, {"servers": servers})
            return

        elif path.startswith("/api/cve-intel/"):
            cve_id = path.replace("/api/cve-intel/", "").strip().upper()
            from core.threat_intel import ThreatIntelEngine
            intel = ThreatIntelEngine.get_cve_intel(cve_id)
            self._send_json(200, intel)
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

        elif path.startswith("/api/server-packages/"):
            agent_id = path.replace("/api/server-packages/", "").strip()
            try:
                client = WazuhClient()
                pkgs = client.get_agent_packages(agent_id)
                self._send_json(200, {"agent_id": agent_id, "packages": pkgs})
            except Exception as e:
                self._send_json(500, {"error": str(e), "packages": []})
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
            data["approvals"] = {key: entry for key, entry in data.get("approvals", {}).items()
                                 if entry.get("source") == "WSUS"}
            self._send_json(200, data)
            return

        elif path == "/api/env-status":
            self._send_json(200, {
                "wazuh_api_url": Settings.WAZUH_API_URL,
                "wazuh_user": Settings.WAZUH_API_USER,
                "wazuh_configured": Settings.is_wazuh_configured(),
                "wsus_server": Settings.WSUS_SERVER_FQDN,
                "wsus_port": Settings.WSUS_PORT,
                "openrouter_configured": bool(Settings.OPENROUTER_API_KEY),
                "openrouter_model": Settings.OPENROUTER_MODEL,
                "gemini_configured": bool(Settings.GEMINI_API_KEY),
                "ai_configured": Settings.is_ai_configured(),
                "active_ai_provider": "OpenRouter (DeepSeek)" if Settings.OPENROUTER_API_KEY else ("Google Gemini" if Settings.GEMINI_API_KEY else "Offline Security Playbook")
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
        global CURRENT_AUDIT_DATA
        parsed = urlparse(self.path)
        path = parsed.path

        if not self._authorize(path, mutation=True):
            return
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if not 0 <= content_length <= 1_000_000:
                raise ValueError()
        except ValueError:
            self._send_json(413, {"success": False, "message": "Invalid or oversized request."})
            return
        body = self.rfile.read(content_length)
        payload = {}
        if body:
            try:
                payload = json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._send_json(400, {"success": False, "message": "JSON không hợp lệ."})
                return
        if not isinstance(payload, dict):
            self._send_json(400, {"success": False, "message": "JSON phải là object."})
            return

        if path == "/api/scan":
            from main import run_scan
            from core.audit_logger import AuditLogger
            use_mock = not Settings.is_wazuh_configured()
            try:
                run_scan(mock=use_mock)
            except Exception as e:
                logger.error(f"Scan failed: {e}")
                self._send_json(502, {"success": False, "message": "Quét thất bại; giữ nguyên báo cáo trước đó."})
                return
            CURRENT_AUDIT_DATA = get_or_create_audit()
            AuditLogger.log_event(
                action="SCAN_CYCLE",
                server_name="Toàn bộ 19 Máy chủ",
                agent_id="ALL",
                details=f"Hoàn tất chu kỳ rà soát lỗ hổng & Rule #4. Tỷ lệ tuân thủ: {CURRENT_AUDIT_DATA.get('metrics', {}).get('overall_compliance_percent')}%",
                source=f"Web UI / {self.auth_user['username']}"
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
                    cve_mapper = CveKbMapper()
                    hotfixes = client.get_agent_hotfixes(agent_id)
                    os_info = client.get_agent_os(agent_id)
                    agent_os_name = ""
                    if os_info:
                        inner_os = os_info.get("os") if isinstance(os_info.get("os"), dict) else os_info
                        agent_os_name = inner_os.get("name") or inner_os.get("os_name", "")

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

                    packages = client.get_agent_packages(agent_id)
                    vulns = client.get_agent_vulnerabilities(
                        agent_id=agent_id,
                        os_name=agent_os_name,
                        installed_packages=packages,
                        agent_name=agent_name
                    )

                    new_server_audit = VulnerabilityValidator.audit_agent(
                        agent_id=agent_id,
                        agent_name=agent_name,
                        vulnerabilities=vulns,
                        hotfixes=hotfixes,
                        os_info=os_info,
                        cve_mapper=cve_mapper,
                        agent_ip=agent_ip
                    )

                    new_server_audit["data_status"] = getattr(client, "vulnerability_data_status", "unknown")
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
                        source=f"Web UI / {self.auth_user['username']}"
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
            from core.wsus_client import change_approval
            try:
                change_approval(kb, group, approve=True)
            except ValueError as e:
                self._send_json(400, {"success": False, "message": str(e)})
                return
            except Exception as e:
                logger.error(f"WSUS operation failed: {e}")
                self._send_json(502, {"success": False, "message": "WSUS chưa xác nhận thao tác. Kiểm tra kết nối, WSUS Console và quyền tài khoản chạy app."})
                return
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
            if existing and existing.get("status") == "APPROVED" and existing.get("source") == "WSUS":
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
                "source": "WSUS",
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
                source=f"Web UI / {self.auth_user['username']}"
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
            from core.wsus_client import change_approval
            try:
                change_approval(kb, group, approve=False)
            except ValueError as e:
                self._send_json(400, {"success": False, "message": str(e)})
                return
            except Exception as e:
                logger.error(f"WSUS operation failed: {e}")
                self._send_json(502, {"success": False, "message": "WSUS chưa xác nhận thao tác. Kiểm tra kết nối, WSUS Console và quyền tài khoản chạy app."})
                return
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
                source=f"Web UI / {self.auth_user['username']}"
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

            # Instantly re-evaluate the server against Rule #4 with the new reboot flag
            current_audit = get_or_create_audit()
            servers_list = current_audit.get("servers", [])
            idx = next((i for i, s in enumerate(servers_list) if str(s.get("agent_id")) == agent_id), -1)
            updated_server = None
            if idx >= 0:
                old_server = servers_list[idx]
                cve_mapper = CveKbMapper()
                # Run audit_agent with current server data and updated reboot state
                new_server_audit = VulnerabilityValidator.audit_agent(
                    agent_id=agent_id,
                    agent_name=old_server.get("agent_name", ""),
                    vulnerabilities=old_server.get("vulnerabilities", []),
                    hotfixes=[{"hotfix": hf} for hf in old_server.get("installed_hotfixes", [])],
                    os_info={"os": {"name": old_server.get("os_name", ""), "build": old_server.get("os_build", "")}},
                    cve_mapper=cve_mapper,
                    agent_ip=old_server.get("ip", "")
                )
                servers_list[idx] = new_server_audit
                updated_server = new_server_audit
                exc_mgr = ExceptionManager()
                CURRENT_AUDIT_DATA = AuditReporter.generate_report(servers_list, exc_mgr.exceptions)

            logger.info(f"Updated reboot status for agent {agent_id}: pending={reboot_pending}")
            from core.audit_logger import AuditLogger
            AuditLogger.log_event(
                action="REBOOT_FLAG_CHANGE",
                server_name=f"Agent ID: {agent_id}",
                agent_id=agent_id,
                details=f"Cập nhật cờ Reboot = {reboot_pending}. Lý do: {reboot_reasons or 'Thủ công từ Admin'}",
                source=f"Web UI / {self.auth_user['username']}"
            )
            self._send_json(200, {
                "success": True,
                "agent_id": agent_id,
                "reboot_pending": reboot_pending,
                "server": updated_server,
                "metrics": CURRENT_AUDIT_DATA.get("metrics", {}) if CURRENT_AUDIT_DATA else {},
                "message": f"Đã cập nhật trạng thái Reboot cho máy chủ (Pending={reboot_pending})."
            })
            return

        elif path == "/api/install-kb":
            kb = payload.get("kb", "").strip().upper()
            server_name = payload.get("server", "").strip()
            agent_id = str(payload.get("agent_id", "")).strip()
            target_ip = payload.get("ip", "").strip()
            if not target_ip:
                audit = get_or_create_audit()
                for s in audit.get("servers", []):
                    if (agent_id and str(s.get("agent_id")) == agent_id) or (server_name and s.get("agent_name") == server_name):
                        target_ip = s.get("ip", "")
                        break
            target_host = target_ip or server_name or "localhost"
            logger.info(f"Triggering WinRM remote install for {kb} on {server_name} ({target_host})")
            from core.winrm_client import WinRMClient
            winrm_result = WinRMClient.trigger_remote_install(target_host, kb_number=kb)
            fallback_cmd = f"powershell -ExecutionPolicy Bypass -File scripts\\Install-PendingUpdates.ps1 -KbNumber {kb}"
            if winrm_result.get("success"):
                data = winrm_result.get("data", {})
                reboot_req = bool(data.get("RebootRequired", False))
                msg = f"Đã kích hoạt cài đặt bản vá {kb} thành công từ xa qua WinRM trên {server_name}."
                if reboot_req:
                    msg += " Máy chủ yêu cầu Khởi động lại (Reboot Required) để hoàn tất cập nhật."
                from core.audit_logger import AuditLogger
                AuditLogger.log_event(
                    action="WINRM_INSTALL_KB",
                    server_name=server_name,
                    agent_id=agent_id,
                    details=f"WinRM Install {kb}: {msg}",
                    source=f"Web UI / {getattr(self, 'auth_user', {}).get('username', 'admin')}"
                )
                self._send_json(200, {
                    "success": True,
                    "remote_execution": True,
                    "kb": kb,
                    "server": server_name,
                    "host": target_host,
                    "winrm_status": data.get("Status", "SUCCESS"),
                    "reboot_required": reboot_req,
                    "installed_count": data.get("InstalledCount", 1),
                    "command": fallback_cmd,
                    "message": msg
                })
            else:
                err_detail = winrm_result.get("error") or "Không thể kết nối WinRM"
                logger.warning(f"WinRM remote install to {target_host} failed: {err_detail}. Providing fallback command.")
                self._send_json(200, {
                    "success": False,
                    "remote_execution": False,
                    "kb": kb,
                    "server": server_name,
                    "host": target_host,
                    "winrm_error": err_detail,
                    "command": fallback_cmd,
                    "message": f"WinRM chưa kết nối được tới {target_host} ({err_detail}). Quản trị viên có thể thực thi lệnh thủ công sau trên node:"
                })
            return

        elif path == "/api/client-reboot-check":
            host = payload.get("host") or payload.get("ip") or payload.get("server", "")
            from core.winrm_client import WinRMClient
            result = WinRMClient.check_remote_pending_reboot(host)
            self._send_json(200, result)
            return

        elif path in ("/api/ai-advice", "/api/gemini-advice"):
            cve = payload.get("cve") or payload.get("cve_id") or "CVE-UNKNOWN"
            server = payload.get("server") or payload.get("server_name") or "Server01"
            os_name = payload.get("os") or payload.get("os_name") or "Windows Server"
            advice = AiAdvisor.get_remediation_guidance(
                cve_id=cve,
                server_name=server,
                os_name=os_name,
                vuln_details=payload
            )
            self._send_json(200, advice)
            return

        elif path == "/api/bulk-cve-intel":
            from core.threat_intel import ThreatIntelEngine
            cves = payload.get("cves", [])
            results = {}
            for item in cves:
                if isinstance(item, str):
                    c_id = item
                    t = ""
                else:
                    c_id = item.get("cve", "")
                    t = item.get("title", "")
                if c_id:
                    results[c_id] = ThreatIntelEngine.get_cve_intel(c_id, title=t)
            self._send_json(200, {"threat_intel": results})
            return

        elif path == "/api/exception":
            mgr = ExceptionManager()
            new_exc = mgr.add_exception(
                cve=payload.get("cve"),
                server=payload.get("server"),
                reason=payload.get("reason"),
                compensating_control=payload.get("control"),
                owner=payload.get("owner", "InfraOps"),
                approved_by=self.auth_user["username"],
                expiration_date=payload.get("expires", "2026-12-31")
            )
            self._send_json(200, {"success": True, "exception": new_exc})
            return

        self._send_json(404, {"error": "Endpoint not found"})

def run_server(port: int = 8080):
    from core.scheduler import scheduler
    server_address = (Settings.WEB_BIND_HOST, port)
    httpd = ThreadingHTTPServer(server_address, PatchManagementHttpHandler)
    scheduler.start()
    print("\n" + "="*60)
    print("      HỆ THỐNG WEB QUẢN LÝ VULNERABILITY & PATCH MANAGEMENT")
    print("="*60)
    print(f"[+] Web Server đang chạy tại : http://localhost:{port}")
    print(f"[+] Giao diện điều khiển UI : http://127.0.0.1:{port}")
    print(f"[+] Trạng thái Wazuh        : {'Đã cấu hình' if Settings.is_wazuh_configured() else 'Chạy Mock / Sẵn sàng nhận .env'}")
    print(f"[+] Đặt lịch Quét Tự Động   : BẬT (Chu kỳ mỗi 30 phút tự động kiểm tra 19 agents)")
    print(f"[+] AI Gemini Advisor       : {Settings.AI_PROVIDER} (configured={Settings.is_ai_configured()})")
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
