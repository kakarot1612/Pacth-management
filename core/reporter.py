import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from core.storage import atomic_write_text
from core.config import Settings, REPORTS_DIR, logger

class AuditReporter:
    """Generates comprehensive Compliance Dashboards, HTML reports, and JSON summaries"""

    @classmethod
    def generate_report(cls, audit_results: List[Dict[str, Any]], exceptions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculates global metrics and builds reporting objects"""
        total_servers = len(audit_results)
        # Exclude servers with INCOMPLETE_TELEMETRY from compliance denominators so missing telemetry doesn't distort audit
        valid_servers = [a for a in audit_results if a.get("inventory_status") != "INCOMPLETE_TELEMETRY"]
        total_vulns = sum(a.get("summary", {}).get("total", 0) for a in valid_servers)
        confirmed_vulns = sum(a.get("summary", {}).get("confirmed_vulnerable", 0) for a in valid_servers)
        remediated_pending_rescan = sum(a.get("summary", {}).get("remediated_pending_rescan", 0) for a in valid_servers)
        solved_vulns = sum(a.get("summary", {}).get("solved", 0) for a in valid_servers)
        critical_confirmed = sum(a.get("summary", {}).get("critical_confirmed", 0) for a in valid_servers)
        incomplete_inventory_count = sum(1 for a in audit_results if a.get("inventory_status") == "INCOMPLETE_TELEMETRY")

        # Compliance rate calculations
        # Effective solved = Solved + Remediated (Pending Wazuh Rescan)
        effective_resolved = solved_vulns + remediated_pending_rescan
        total_eval = total_vulns if total_vulns > 0 else 1
        compliance_rate = round((effective_resolved / total_eval) * 100, 2) if total_vulns > 0 else 100.0

        # Critical compliance
        total_critical = critical_confirmed + sum(
            1 for a in audit_results for v in a.get("vulnerabilities", [])
            if str(v.get("severity")).upper() == "CRITICAL" and v.get("status") in ("SOLVED", "REMEDIATED_PENDING_WAZUH_RESCAN")
        )
        critical_compliance = round((1 - (critical_confirmed / (total_critical if total_critical > 0 else 1))) * 100, 2)

        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        data_status = 'fresh' if audit_results and all(a.get('data_status') == 'fresh' for a in audit_results) else 'partial'
        if audit_results and all(a.get('data_status') == 'demo' for a in audit_results):
            data_status = 'demo'
        report_data = {
            "data_status": data_status,
            "generated_at": timestamp_str,
            "metrics": {
                "total_servers": total_servers,
                "total_vulnerabilities": total_vulns,
                "confirmed_vulnerable": confirmed_vulns,
                "remediated_pending_rescan": remediated_pending_rescan,
                "solved": solved_vulns,
                "critical_confirmed": critical_confirmed,
                "overall_compliance_percent": compliance_rate,
                "critical_compliance_percent": critical_compliance,
                "target_compliance_percent": Settings.TARGET_COMPLIANCE_RATE,
                "target_critical_compliance_percent": Settings.TARGET_CRITICAL_COMPLIANCE_RATE,
                "compliance_status": ("UNVERIFIED" if data_status != "fresh" else
                    ("COMPLIANT" if compliance_rate >= Settings.TARGET_COMPLIANCE_RATE else "ACTION_REQUIRED")),
                "active_exceptions_count": len(exceptions),
                "reboot_pending_count": sum(1 for a in audit_results if a.get("reboot_pending")),
                "incomplete_inventory_count": incomplete_inventory_count
            },
            "servers": audit_results,
            "exceptions": exceptions
        }

        # Save JSON
        json_file = REPORTS_DIR / f"patch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        latest_json = REPORTS_DIR / "latest_report.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        atomic_write_text(latest_json, json.dumps(report_data, indent=2, ensure_ascii=False))

        # Generate HTML Dashboard
        html_file = REPORTS_DIR / f"patch_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        latest_html = REPORTS_DIR / "latest_dashboard.html"
        html_content = cls._build_html_dashboard(report_data)
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        atomic_write_text(latest_html, html_content)

        logger.info(f"Generated compliance report: {html_file}")
        return report_data

    @classmethod
    def _build_html_dashboard(cls, data: Dict[str, Any]) -> str:
        metrics = data["metrics"]
        compliance_color = "#10b981" if metrics["compliance_status"] == "COMPLIANT" else "#ef4444"

        # Build server rows
        server_rows = []
        for s in data["servers"]:
            srv_summary = s.get("summary", {})
            status_badge = (
                '<span class="badge badge-success">Sạch</span>'
                if srv_summary.get("confirmed_vulnerable", 0) == 0
                else f'<span class="badge badge-danger">{srv_summary.get("confirmed_vulnerable")} Chưa vá</span>'
            )
            rescan_badge = (
                f'<span class="badge badge-warning">{srv_summary.get("remediated_pending_rescan")} Chờ Wazuh quét lại</span>'
                if srv_summary.get("remediated_pending_rescan", 0) > 0
                else '<span class="badge badge-secondary">0</span>'
            )
            server_rows.append(f"""
            <tr>
                <td><strong>{s.get('agent_name')}</strong> (ID: {s.get('agent_id')})</td>
                <td>{s.get('os_name') or 'Windows Server'}<br><small style="color:#64748b">Build: {s.get('os_build') or 'N/A'}</small></td>
                <td>{s.get('installed_hotfix_count', 0)} KBs</td>
                <td>{srv_summary.get('critical_confirmed', 0)}</td>
                <td>{srv_summary.get('high_confirmed', 0)}</td>
                <td>{rescan_badge}</td>
                <td>{status_badge}</td>
            </tr>
            """)

        # Exceptions rows
        exc_rows = []
        for e in data.get("exceptions", []):
            exc_rows.append(f"""
            <tr>
                <td><code>{e.get('cve')}</code></td>
                <td><strong>{e.get('server')}</strong></td>
                <td>{e.get('reason')}</td>
                <td><small>{e.get('compensating_control')}</small></td>
                <td>{e.get('owner')} / {e.get('approved_by')}</td>
                <td><code>{e.get('expiration_date')}</code></td>
            </tr>
            """)

        html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability & Patch Management Executive Dashboard</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --primary: #3b82f6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 24px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border);
        }}
        .header h1 {{ font-size: 24px; color: #fff; }}
        .header .meta {{ color: var(--text-muted); font-size: 14px; }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--surface);
            border-radius: 8px;
            padding: 16px 20px;
            border: 1px solid var(--border);
        }}
        .kpi-title {{ font-size: 13px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-bottom: 8px; }}
        .kpi-value {{ font-size: 28px; font-weight: bold; color: #fff; }}
        .kpi-sub {{ font-size: 12px; color: var(--text-muted); margin-top: 4px; }}
        .card {{
            background: var(--surface);
            border-radius: 8px;
            border: 1px solid var(--border);
            padding: 20px;
            margin-bottom: 24px;
        }}
        .card-title {{
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        th, td {{
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background-color: rgba(15, 23, 42, 0.6);
            color: var(--text-muted);
            font-weight: 600;
        }}
        tr:hover td {{
            background-color: var(--surface-hover);
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        .badge-success {{ background: rgba(16, 185, 129, 0.15); color: #34d399; }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.15); color: #f87171; }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; }}
        .badge-secondary {{ background: rgba(148, 163, 184, 0.15); color: #94a3b8; }}
        .rules-box {{
            background: rgba(59, 130, 246, 0.08);
            border-left: 4px solid var(--primary);
            padding: 14px 18px;
            border-radius: 4px;
            font-size: 13px;
            margin-bottom: 20px;
        }}
        .rules-box strong {{ color: var(--primary); }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Hệ thống Quản lý Vulnerability & Patch Management</h1>
            <div class="meta">Wazuh Detection & Verification | WSUS Deployment | Active Directory GPO</div>
        </div>
        <div style="text-align: right;">
            <div style="font-weight: 600; color: {compliance_color}; font-size: 18px;">{metrics['compliance_status']}</div>
            <div class="meta">Tạo lúc: {data['generated_at']}</div>
        </div>
    </div>

    <div class="rules-box">
        <strong>Nguyên tắc vàng:</strong> Wazuh chỉ phát hiện và xác minh; WSUS phân phối độc quyền. Không patch theo mã CVE thuần túy (phải qua map KB). Khi Wazuh báo Active, hệ thống tự động đối chiếu Hotfix & OS Build (Rule #4) để loại bỏ false-positive do chưa quét lại syscollector.
    </div>

    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Tuân thủ Tổng thể (Compliance)</div>
            <div class="kpi-value" style="color: {compliance_color};">{metrics['overall_compliance_percent']}%</div>
            <div class="kpi-sub">Mục tiêu SLA: ≥ {metrics['target_compliance_percent']}%</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Tuân thủ Critical (P1)</div>
            <div class="kpi-value" style="color: {'#10b981' if metrics['critical_compliance_percent'] >= 98 else '#ef4444'};">{metrics['critical_compliance_percent']}%</div>
            <div class="kpi-sub">Mục tiêu: ≥ {metrics['target_critical_compliance_percent']}%</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Chưa vá (Confirmed Active)</div>
            <div class="kpi-value" style="color: {'#ef4444' if metrics['confirmed_vulnerable'] > 0 else '#10b981'};">{metrics['confirmed_vulnerable']}</div>
            <div class="kpi-sub">Critical: {metrics['critical_confirmed']} | High: {sum(s.get('summary', {}).get('high_confirmed', 0) for s in data['servers'])}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Đã cài (Chờ Wazuh Rescan)</div>
            <div class="kpi-value" style="color: #fbbf24;">{metrics['remediated_pending_rescan']}</div>
            <div class="kpi-sub">Đã có HotFix, chờ chu kỳ Syscollector</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Ngoại lệ phê duyệt (Exceptions)</div>
            <div class="kpi-value">{metrics['active_exceptions_count']}</div>
            <div class="kpi-sub">Có biện pháp giảm nhẹ (Compensating controls)</div>
        </div>
    </div>

    <div class="card">
        <div class="card-title">Danh sách Máy chủ & Trạng thái Vá lỗi</div>
        <table>
            <thead>
                <tr>
                    <th>Máy chủ</th>
                    <th>Hệ điều hành & Build</th>
                    <th>Hotfixes</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Chờ quét lại</th>
                    <th>Trạng thái</th>
                </tr>
            </thead>
            <tbody>
                {''.join(server_rows) if server_rows else '<tr><td colspan="7">Chưa có dữ liệu máy chủ</td></tr>'}
            </tbody>
        </table>
    </div>

    <div class="card">
        <div class="card-title">Sổ đăng ký Ngoại lệ Lỗ hổng (Vulnerability Exception Registry)</div>
        <table>
            <thead>
                <tr>
                    <th>Mã CVE</th>
                    <th>Máy chủ</th>
                    <th>Lý do ngoại lệ</th>
                    <th>Biện pháp bù đắp (Compensating Control)</th>
                    <th>Người phụ trách / Phê duyệt</th>
                    <th>Hạn ngoại lệ</th>
                </tr>
            </thead>
            <tbody>
                {''.join(exc_rows) if exc_rows else '<tr><td colspan="6">Không có ngoại lệ nào đang hoạt động</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>"""
        return html
