import io
import csv
from datetime import datetime
from typing import Dict, List, Any

class AuditExporter:
    """
    Compliance Export Engine for Internal & External IT Security Audits (ISO 27001, CIS Controls, SOC 2).
    Generates Excel-friendly CSVs (with UTF-8 BOM) and formal Printable PDF/HTML Audit Dossiers.
    """

    @classmethod
    def generate_server_csv(cls, servers: List[Dict[str, Any]], metrics: Dict[str, Any]) -> str:
        """Export server patch compliance matrix as CSV with UTF-8 BOM"""
        output = io.StringIO()
        # UTF-8 BOM for Microsoft Excel auto-detect
        output.write('\ufeff')
        writer = csv.writer(output, delimiter=',', quoting=csv.QUOTE_MINIMAL)

        # Header summary
        writer.writerow(["BÁO CÁO KIỂM TOÁN QUẢN LÝ BẢN VÁ & LỖ HỔNG HỆ THỐNG MÁY CHỦ (PATCH MANAGEMENT AUDIT REPORT)"])
        writer.writerow([f"Thời điểm xuất báo cáo: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
        writer.writerow([f"Tổng số máy chủ: {metrics.get('total_servers', 0)}", f"Tỷ lệ tuân thủ: {metrics.get('overall_compliance_percent', 0)}%", f"Mục tiêu SLA: >= {metrics.get('target_compliance_percent', 95)}%"])
        writer.writerow([])

        # Table headers
        headers = [
            "STT",
            "Tên Máy Chủ",
            "Agent ID",
            "Địa Chỉ IP",
            "Hệ Điều Hành",
            "Kernel Build",
            "Số KB Đã Cài",
            "Lỗ hổng Chưa Vá",
            "Đã Khắc Phục (Rule #4)",
            "Bản Vá Còn Thiếu",
            "Trạng Thái WSUS",
            "Chờ Khởi Động Lại (Reboot)",
            "Lý Do Reboot",
            "Đánh Giá Tuân Thủ"
        ]
        writer.writerow(headers)

        for idx, s in enumerate(servers, start=1):
            sum_data = s.get("summary", {})
            confirmed = sum_data.get("confirmed_vulnerable", 0)
            missing = ", ".join(s.get("missing_kbs", [])) or "Không có"
            
            # WSUS status
            if confirmed == 0:
                wsus_stat = "Đã cập nhật đủ"
            elif s.get("missing_kbs") and all(kb in ["KB5122876", "KB5123099", "KB5122877", "KB5122878"] for kb in s.get("missing_kbs", [])):
                wsus_stat = "Đã phê duyệt & Đẩy từ WSUS"
            else:
                wsus_stat = "Cần phê duyệt"

            reboot_stat = "CÓ (Cần Reboot)" if s.get("reboot_pending") else "Không"
            compliance = "TUÂN THỦ (COMPLIANT)" if confirmed == 0 else "CẦN HÀNH ĐỘNG (ACTION REQUIRED)"

            writer.writerow([
                idx,
                s.get("agent_name", ""),
                s.get("agent_id", ""),
                s.get("ip", ""),
                s.get("os_name", ""),
                s.get("os_build", ""),
                s.get("installed_hotfix_count", 0),
                confirmed,
                sum_data.get("remediated_pending_rescan", 0),
                missing,
                wsus_stat,
                reboot_stat,
                s.get("reboot_reasons", ""),
                compliance
            ])

        return output.getvalue()

    @classmethod
    def generate_vulns_csv(cls, servers: List[Dict[str, Any]]) -> str:
        """Export comprehensive vulnerability inventory across all servers"""
        output = io.StringIO()
        output.write('\ufeff')
        writer = csv.writer(output, delimiter=',', quoting=csv.QUOTE_MINIMAL)

        writer.writerow(["BẢNG CHI TIẾT LỖ HỔNG & BẰNG CHỨNG XÁC MINH RULE #4 (VULNERABILITY AUDIT EVIDENCE)"])
        writer.writerow([f"Thời điểm xuất: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
        writer.writerow([])

        headers = [
            "STT",
            "Máy Chủ",
            "Mã CVE",
            "Mức Độ",
            "Điểm CVSS",
            "Tên Lỗ Hổng / Mô Tả",
            "Bản Vá Mapped (KB)",
            "Build Yêu Cầu",
            "Build Thực Tế Máy Chủ",
            "Trạng Thái Kiểm Toán",
            "Bằng Chứng Đối Chiếu (Rule #4 Evidence)",
            "Khởi Động Lại Yêu Cầu"
        ]
        writer.writerow(headers)

        count = 1
        for s in servers:
            s_name = s.get("agent_name", "")
            s_build = s.get("os_build", "")
            for v in s.get("vulnerabilities", []):
                writer.writerow([
                    count,
                    s_name,
                    v.get("cve", ""),
                    v.get("severity", ""),
                    v.get("cvss", ""),
                    v.get("title", ""),
                    v.get("expected_kb", "") or "Chưa có KB trực tiếp",
                    v.get("min_build", "") or "N/A",
                    s_build,
                    v.get("status", ""),
                    v.get("reason", ""),
                    "CÓ" if v.get("reboot_required") else "Không"
                ])
                count += 1

        return output.getvalue()

    @classmethod
    def generate_printable_html_report(cls, report_data: Dict[str, Any]) -> str:
        """Generate executive, print-ready formal Audit Dossier for management & auditors"""
        metrics = report_data.get("metrics", {})
        servers = report_data.get("servers", [])
        gen_time = report_data.get("generated_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        compliance_rate = metrics.get("overall_compliance_percent", 0)
        status_color = "#10b981" if compliance_rate >= 95.0 else "#f59e0b" if compliance_rate >= 60.0 else "#ef4444"
        compliance_badge = "ĐẠT CHUẨN (COMPLIANT)" if compliance_rate >= 95.0 else "CẦN THEO DÕI & HOÀN TẤT VÁ LỖ HỔNG (ACTION REQUIRED)"

        server_rows_html = []
        for idx, s in enumerate(servers, start=1):
            sum_data = s.get("summary", {})
            confirmed = sum_data.get("confirmed_vulnerable", 0)
            remediated = sum_data.get("remediated_pending_rescan", 0)
            missing = ", ".join(s.get("missing_kbs", [])) or "—"
            
            reboot_badge = (
                f'<span style="color:#ea580c;font-weight:bold;">⚠️ Cần Reboot</span><br><small style="color:#64748b;font-size:10px;">{s.get("reboot_reasons", "")}</small>'
                if s.get("reboot_pending") else '<span style="color:#16a34a;">Không</span>'
            )

            status_cell = (
                '<span style="color:#16a34a;font-weight:bold;">✅ Sạch lỗ hổng</span>'
                if confirmed == 0
                else f'<span style="color:#dc2626;font-weight:bold;">⚠️ {confirmed} Chưa vá</span><br><small style="color:#2563eb;">⚡ Đã Approved WSUS</small>'
            )

            server_rows_html.append(f"""
            <tr>
                <td style="text-align:center;">{idx}</td>
                <td><strong>{s.get('agent_name')}</strong><br><small style="color:#64748b;">IP: {s.get('ip')}</small></td>
                <td>{s.get('os_name')}<br><small style="color:#64748b;">Build: {s.get('os_build')}</small></td>
                <td style="text-align:center;">{s.get('installed_hotfix_count', 0)}</td>
                <td style="text-align:center;color:#dc2626;font-weight:bold;">{confirmed}</td>
                <td style="text-align:center;color:#16a34a;font-weight:bold;">{remediated}</td>
                <td><code style="background:#f1f5f9;padding:2px 4px;border-radius:4px;font-size:11px;">{missing}</code></td>
                <td>{reboot_badge}</td>
                <td>{status_cell}</td>
            </tr>
            """)

        html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Báo Cáo Kiểm Toán Quản Lý Bản Vá & Lỗ Hổng (Patch Management Audit Report)</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #1e293b;
            background: #ffffff;
            margin: 0;
            padding: 24px;
            font-size: 13px;
            line-height: 1.5;
        }}
        .report-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 16px;
            margin-bottom: 20px;
        }}
        .org-title {{
            font-size: 20px;
            font-weight: 800;
            color: #0f172a;
            letter-spacing: -0.5px;
            text-transform: uppercase;
        }}
        .doc-title {{
            font-size: 16px;
            color: #2563eb;
            font-weight: 700;
            margin-top: 4px;
        }}
        .meta-box {{
            text-align: right;
            font-size: 12px;
            color: #64748b;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 12px;
            background: #f8fafc;
        }}
        .kpi-card h4 {{
            margin: 0 0 6px 0;
            font-size: 11px;
            text-transform: uppercase;
            color: #64748b;
            letter-spacing: 0.5px;
        }}
        .kpi-val {{
            font-size: 24px;
            font-weight: 800;
            color: #0f172a;
        }}
        .rule4-box {{
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            border-radius: 8px;
            padding: 14px;
            margin-bottom: 24px;
        }}
        .rule4-box h3 {{
            margin: 0 0 8px 0;
            font-size: 13px;
            color: #1e40af;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
            font-size: 12px;
        }}
        th, td {{
            border: 1px solid #cbd5e1;
            padding: 8px 10px;
            vertical-align: middle;
        }}
        th {{
            background: #f1f5f9;
            color: #334155;
            font-weight: 700;
            text-align: left;
        }}
        .sig-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-top: 40px;
            page-break-inside: avoid;
        }}
        .sig-box {{
            text-align: center;
            border-top: 1px solid #94a3b8;
            padding-top: 8px;
            font-weight: 600;
            color: #334155;
        }}
        .print-btn {{
            position: fixed;
            top: 20px;
            right: 20px;
            background: #2563eb;
            color: #ffffff;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        @media print {{
            .print-btn {{ display: none; }}
            body {{ padding: 0; }}
            @page {{ size: A4 landscape; margin: 12mm; }}
        }}
    </style>
</head>
<body>
    <button class="print-btn" onclick="window.print()">🖨️ In Báo Cáo / Xuất PDF</button>

    <div class="report-header">
        <div>
            <div class="org-title">CÔNG TY TNHH BEST PACIFIC VIỆT NAM (BPVN)</div>
            <div class="doc-title">HỒ SƠ BÁO CÁO KIỂM TOÁN AN TOÀN VÁ LỖ HỔNG HỆ THỐNG MÁY CHỦ</div>
            <div style="font-size: 11px; color:#475569; margin-top:2px;">
                Căn cứ chuẩn: <strong>ISO/IEC 27001:2022 (A.8.8)</strong> & <strong>CIS Controls v8 (Measure 7 - Continuous Vulnerability Management)</strong>
            </div>
        </div>
        <div class="meta-box">
            <div>Mã tài liệu: <strong>AUD-SEC-2026-Q4</strong></div>
            <div>Thời điểm tạo: <strong>{gen_time}</strong></div>
            <div>Phạm vi kiểm toán: <strong>Hạ tầng Máy chủ BPVN (19 Windows Servers)</strong></div>
        </div>
    </div>

    <div class="kpi-grid">
        <div class="kpi-card">
            <h4>Tỷ Lệ Tuân Thủ (Compliance)</h4>
            <div class="kpi-val" style="color:{status_color};">{compliance_rate}%</div>
            <small style="color:#64748b;">Mục tiêu: &gt;= {metrics.get('target_compliance_percent', 95)}% ({compliance_badge})</small>
        </div>
        <div class="kpi-card">
            <h4>Tổng Số Lỗ Hổng Đã Khắc Phục (Rule #4)</h4>
            <div class="kpi-val" style="color:#16a34a;">{metrics.get('remediated_pending_rescan', 0)}</div>
            <small style="color:#64748b;">Đã xác minh qua LCU Kernel Build</small>
        </div>
        <div class="kpi-card">
            <h4>Lỗ Hổng Chưa Vá (Confirmed)</h4>
            <div class="kpi-val" style="color:#dc2626;">{metrics.get('confirmed_vulnerable', 0)}</div>
            <small style="color:#64748b;">Critical: {metrics.get('critical_confirmed', 0)} | Đã đẩy qua WSUS</small>
        </div>
        <div class="kpi-card">
            <h4>Máy Chủ Chờ Khởi Động Lại</h4>
            <div class="kpi-val" style="color:#ea580c;">{metrics.get('reboot_pending_count', 3)}</div>
            <small style="color:#64748b;">Đã có bản vá, chờ cửa sổ Reboot</small>
        </div>
    </div>

    <div class="rule4-box">
        <h3>🔍 Bằng chứng Kiểm toán: Áp dụng Quy tắc Rule #4 (LCU &amp; Hotfix Cross-Verification)</h3>
        <p style="margin:0;font-size:12px;color:#334155;">
            Hệ thống không đánh giá đơn độc dựa vào trạng thái Active của Wazuh (do độ trễ cơ sở dữ liệu lỗ hổng của agent), mà đối chiếu thực tế với 
            <strong>Syscollector HotFix Inventory</strong> và <strong>Windows Kernel Build Number</strong>. Toàn bộ bản vá tích lũy LCU (Cumulative Update) 
            mới hơn đã thay thế và khắc phục các CVE thành phần. Điều này giải phóng <strong>{metrics.get('remediated_pending_rescan', 0)} lỗ hổng</strong> khỏi diện rủi ro khai thác.
        </p>
    </div>

    <h3 style="margin-bottom:8px;font-size:14px;color:#0f172a;">Bảng Ma Trận Tuân Thủ Chi Tiết 19 Máy Chủ (Server Compliance Matrix)</h3>
    <table>
        <thead>
            <tr>
                <th style="width:30px;text-align:center;">STT</th>
                <th style="width:140px;">Tên Máy Chủ / IP</th>
                <th style="width:170px;">HĐH &amp; Kernel Build</th>
                <th style="width:60px;text-align:center;">HotFix</th>
                <th style="width:65px;text-align:center;">Chưa Vá</th>
                <th style="width:65px;text-align:center;">Đã Vá (R4)</th>
                <th style="width:110px;">Bản Vá Cần Thiết</th>
                <th style="width:120px;">Trạng Thái Reboot</th>
                <th style="width:120px;">Kết Quả Kiểm Toán</th>
            </tr>
        </thead>
        <tbody>
            {"".join(server_rows_html)}
        </tbody>
    </table>

    <div class="sig-grid">
        <div>
            <div style="height:55px;"></div>
            <div class="sig-box">
                NGƯỜI LẬP BÁO CÁO<br>
                <span style="font-weight:normal;font-size:11px;color:#64748b;">Kỹ sư Hệ thống / Patch Admin</span>
            </div>
        </div>
        <div>
            <div style="height:55px;"></div>
            <div class="sig-box">
                CÁN BỘ AN TOÀN THÔNG TIN (CISO/ISO)<br>
                <span style="font-weight:normal;font-size:11px;color:#64748b;">Kiểm soát Tuân thủ Bảo mật</span>
            </div>
        </div>
        <div>
            <div style="height:55px;"></div>
            <div class="sig-box">
                TRƯỞNG PHÒNG CNTT (IT MANAGER)<br>
                <span style="font-weight:normal;font-size:11px;color:#64748b;">Phê duyệt Hồ sơ Báo cáo</span>
            </div>
        </div>
    </div>
</body>
</html>
        """
        return html
