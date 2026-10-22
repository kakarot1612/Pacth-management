# Kế hoạch Patch & SLA (Service Level Agreement)

## 1. Patch SLA
| Priority | Điều kiện | Thời gian xử lý đề xuất |
|---|---|---|
| **P1 (Critical)** | Critical CVSS, CISA KEV, Exploited, Internet-facing, DC, VPN | ≤ 72 giờ |
| **P2 (High)** | High CVSS, Local Privilege Escalation, Production/Hyper-V/App Servers | ≤ 14 ngày |
| **P3 (Medium)** | Chưa có exploit rõ ràng, rủi ro trung bình | ≤ 30 ngày (Chu kỳ tháng) |
| **P4 (Low)** | Rủi ro thấp, có mitigating control | ≤ 90 ngày |

## 2. Chu kỳ Vá định kỳ (Monthly Patch Cycle)
* **Week 1:** Microsoft release updates → WSUS Sync → Wazuh Review → CVE/KB mapping & Lập kế hoạch.
* **Week 2:** Triển khai nhóm TEST → IT Servers → App Validation.
* **Week 3:** Triển khai Production Servers → File/App/DB Servers.
* **Week 4:** Triển khai Hyper-V & Critical Infrastructure (Maintenance Window) → Wazuh Verification → Báo cáo.

## 3. Quy trình Khẩn cấp (Emergency Patch)
Kích hoạt khi có P1/Zero-day:
CVE Detected → Xác định Server ảnh hưởng → Tìm KB → Verify Backup → Emergency Test → Deploy Production → Wazuh Verification.