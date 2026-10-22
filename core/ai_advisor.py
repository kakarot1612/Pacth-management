import requests
import json
import logging
from typing import Dict, Any
from core.config import Settings, logger

class GeminiAiAdvisor:
    """
    Integrates with Google Gemini API to analyze vulnerabilities lacking vendor KBs
    and provide actionable remediation playbooks, registry hardening, and compensating controls.
    """

    @classmethod
    def get_remediation_guidance(
        cls,
        cve_id: str,
        server_name: str,
        os_name: str = "Windows Server",
        vuln_details: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        vuln_details = vuln_details or {}
        title = vuln_details.get("title", "Unknown Security Vulnerability")
        severity = vuln_details.get("severity", "High")
        cvss = vuln_details.get("cvss", 7.5)

        # 1. If GEMINI_API_KEY is configured, call Google Generative AI REST API
        if Settings.GEMINI_API_KEY:
            try:
                model_name = Settings.GEMINI_MODEL or "gemini-2.5-flash"
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={Settings.GEMINI_API_KEY}"

                prompt = f"""
Bạn là Chuyên gia Cao cấp về An ninh Mạng Windows và Quản lý Lỗ hổng (Windows Infrastructure Security Engineer).
Một máy chủ trong hệ thống của chúng tôi đang gặp lỗ hổng bảo mật sau nhưng HIỆN TẠI KHÔNG CÓ BẢN VÁ KB TRỰC TIẾP (hoặc là ứng dụng legacy/0-day/cấu hình):

- Máy chủ: {server_name} ({os_name})
- Mã CVE: {cve_id}
- Tiêu đề: {title}
- Mức độ rủi ro: {severity} (CVSS: {cvss})

Hãy phân tích và viết hướng dẫn khắc phục chi tiết, chuẩn chỉ và khả thi cho Quản trị viên hệ thống Windows. Trình bày rõ ràng theo các mục:
1. 🔍 Phân tích nguyên nhân & Vector tấn công (Root Cause & Attack Vector)
2. 🛡️ Biện pháp khắc phục / Giảm thiểu tạm thời (Workaround & Compensating Controls: tắt service, chặn port qua Windows Firewall, sửa Registry hoặc GPO)
3. 💻 Kịch bản PowerShell / Lệnh thực thi ngay để áp dụng biện pháp phòng vệ
4. 🧪 Các bước kiểm tra & xác nhận (Verification Steps)
5. 📝 Đề xuất nội dung làm phiếu Ngoại lệ (Vulnerability Exception) nếu không thể vá:
   - Lý do chấp nhận rủi ro:
   - Biện pháp bù đắp:
   - Thời hạn đề xuất:

Hãy trả lời bằng Tiếng Việt, định dạng Markdown rõ ràng, chuyên nghiệp.
"""

                payload = {
                    "contents": [{
                        "parts": [{"text": prompt}]
                    }],
                    "generationConfig": {
                        "temperature": 0.2,
                        "maxOutputTokens": 2048
                    }
                }

                headers = {"Content-Type": "application/json"}
                resp = requests.post(url, headers=headers, json=payload, timeout=25)

                if resp.status_code == 200:
                    resp_data = resp.json()
                    candidates = resp_data.get("candidates", [])
                    if candidates and "content" in candidates[0]:
                        parts = candidates[0]["content"].get("parts", [])
                        if parts:
                            ai_text = parts[0].get("text", "")
                            return {
                                "cve": cve_id,
                                "server": server_name,
                                "source": f"Google Gemini API ({model_name})",
                                "is_live_ai": True,
                                "guidance_markdown": ai_text
                            }
                else:
                    logger.warning(f"Gemini API returned status {resp.status_code}: {resp.text}")
            except Exception as e:
                logger.error(f"Error querying Gemini API: {e}")

        # 2. Fallback Intelligent Expert Engine (Structured Security Playbook)
        return cls._generate_expert_playbook(cve_id, server_name, os_name, title, severity, cvss)

    @classmethod
    def _generate_expert_playbook(
        cls,
        cve_id: str,
        server_name: str,
        os_name: str,
        title: str,
        severity: str,
        cvss: float
    ) -> Dict[str, Any]:
        """Built-in Security Workaround Playbook for offline or unkeyed environments"""

        is_cve_rdp = "rdp" in title.lower() or "remote desktop" in title.lower()
        is_cve_smb = "smb" in title.lower() or "file sharing" in title.lower()
        is_cve_legacy = "legacy" in title.lower() or "app" in title.lower()

        if is_cve_rdp:
            attack_vector = "Dịch vụ Remote Desktop Licensing / RDP lắng nghe trên cổng 3389 có thể bị tấn công thực thi mã từ xa (RCE) qua các gói tin giả mạo."
            mitigation_text = (
                "- **Bật NLA (Network Level Authentication)**: Yêu cầu xác thực tài khoản trước khi thiết lập phiên RDP.\n"
                "- **Giới hạn phạm vi IP truy cập**: Dùng Windows Firewall chỉ cho phép dải IP nội bộ hoặc IP Jumpbox quản trị kết nối port 3389.\n"
                "- **Tạm dừng dịch vụ không cần thiết**: Nếu máy chủ không phải là RDP Licensing Server, vô hiệu hóa service `TermServLicensing`."
            )
            ps_script = """# 1. Bật Network Level Authentication (NLA)
Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1

# 2. Khóa cổng RDP 3389 qua Windows Firewall, chỉ cho phép dải IP quản trị (VD: 10.0.0.0/24)
Set-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP" -RemoteAddress "10.0.0.0/24" -Action Allow

# 3. Kiểm tra trạng thái dịch vụ RDP
Get-Service -Name TermService | Select-Object Name, Status, StartType"""
        elif is_cve_smb:
            attack_vector = "Giao thức chia sẻ tệp SMBv1/v2 hoặc RPC có điểm yếu cho phép đối tượng dò quét và tấn công leo thang đặc quyền."
            mitigation_text = (
                "- **Tắt SMBv1 hoàn toàn**: SMBv1 tiềm ẩn rủi ro rất cao và đã lỗi thời.\n"
                "- **Bật SMB Signing**: Ngăn chặn tấn công Man-in-the-Middle (MitM).\n"
                "- **Khóa port 445/139 ra Internet**."
            )
            ps_script = """# 1. Vô hiệu hóa SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# 2. Bắt buộc SMB Signing trên máy chủ
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

# 3. Kiểm tra cấu hình SMB hiện tại
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature"""
        else:
            attack_vector = f"Lỗ hổng {cve_id} tác động đến phần mềm hoặc tiến trình chạy trên {os_name}, cho phép khai thác rủi ro {severity} (CVSS {cvss})."
            mitigation_text = (
                f"- **Cách ly mạng (Network Segmentation)**: Chuyển máy chủ {server_name} vào VLAN riêng biệt và chỉ cho phép giao tiếp tối thiểu cần thiết.\n"
                "- **Áp dụng AppLocker / Software Restriction Policies**: Giới hạn quyền thực thi các file nhị phân lạ.\n"
                "- **Bật Wazuh FIM (File Integrity Monitoring)**: Giám sát toàn bộ các thay đổi trong thư mục hệ thống và registry liên quan."
            )
            ps_script = f"""# 1. Giám sát tiến trình liên quan trên máy chủ {server_name}
Get-Process | Where-Object {{ $_.Path -like "*app*" }} | Select-Object Name, Id, Path

# 2. Khóa kết nối từ dải mạng bên ngoài qua Windows Advanced Firewall
New-NetFirewallRule -DisplayName "Block-Inbound-Untrusted-{cve_id}" -Direction Inbound -Action Block -RemoteAddress Any -LocalPort Any -Protocol TCP

# 3. Kiểm tra event log bảo mật
Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625, 4672}} -MaxEvents 10"""

        markdown_content = f"""### 🛡️ Hướng dẫn Khắc phục & Biện pháp Giảm nhẹ ({cve_id})

> **Lưu ý:** Lỗ hổng này hiện **chưa có bản vá KB trực tiếp** từ WSUS hoặc là phần mềm của bên thứ 3/Legacy. Hãy áp dụng biện pháp phòng thủ chiều sâu (Defense-in-Depth) theo hướng dẫn dưới đây.

#### 1. 🔍 Phân tích Nguyên nhân & Vector Tấn công
- **Máy chủ ảnh hưởng:** `{server_name}` ({os_name})
- **Đánh giá rủi ro:** Mức độ **{severity}** (Điểm CVSS: **{cvss}**)
- **Bề mặt tấn công:** {attack_vector}

#### 2. 🛡️ Biện pháp Bù đắp & Kiểm soát Kỹ thuật (Compensating Controls)
{mitigation_text}

#### 3. 💻 Kịch bản PowerShell Thực thi Ngay
```powershell
{ps_script}
```

#### 4. 🧪 Các bước Kiểm tra & Xác nhận (Verification)
1. Chạy kịch bản kiểm tra trên để đảm bảo quy tắc Firewall/Registry đã được áp dụng.
2. Kiểm tra log hệ thống trong Event Viewer (`Event ID 4625`, `4688`).
3. Khởi động lại dịch vụ hoặc máy chủ nếu có yêu cầu.

#### 5. 📝 Thông tin để Đăng ký Phiếu Ngoại lệ (Exception Ticket)
Nếu hệ thống chưa thể cập nhật ngay, hãy tạo ngoại lệ trên hệ thống:
- **Lý do:** Chưa có bản vá KB chính thức; hoặc phần mềm phụ thuộc tương thích ngược.
- **Biện pháp bù đắp (Compensating Control):** Đã cô lập mạng, áp dụng Firewall rule và bật giám sát Wazuh FIM.
- **Hạn đề xuất:** 90 ngày (hoặc đến khi vendor phát hành bản vá).

---
*💡 Để kích hoạt câu trả lời trực tiếp từ mô hình AI chuyên sâu Google Gemini, hãy thêm `GEMINI_API_KEY=your_key` vào file `.env`.*
"""

        return {
            "cve": cve_id,
            "server": server_name,
            "source": "Chuyên gia An ninh Hệ thống (Built-in Security Engine)",
            "is_live_ai": False,
            "guidance_markdown": markdown_content
        }
