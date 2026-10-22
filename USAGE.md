# Hướng dẫn Vận hành & Cấu hình Hệ thống Patch Management

Hệ thống được thiết kế và xây dựng theo chuẩn quy trình trong các tài liệu thiết kế:
- [README.md](file:///d:/BPVN/Patch%20management/README.md)
- [PLAN.md](file:///d:/BPVN/Patch%20management/PLAN.md)
- [docs/wazuh.md](file:///d:/BPVN/Patch%20management/docs/wazuh.md)
- [docs/wsus.md](file:///d:/BPVN/Patch%20management/docs/wsus.md)
- [docs/vulnerability-management.md](file:///d:/BPVN/Patch%20management/docs/vulnerability-management.md)
- [docs/hyperv-patching.md](file:///d:/BPVN/Patch%20management/docs/hyperv-patching.md)

---

## 1. Danh sách Dữ liệu Đầu vào cần điền vào file `.env`

Để đảm bảo an toàn và bảo mật, thông tin tài khoản, mật khẩu, IP máy chủ **không được lưu cứng trong mã nguồn**. Hãy tạo file `.env` tại thư mục gốc từ mẫu [.env.example](file:///d:/BPVN/Patch%20management/.env.example) và điền các thông tin sau:

| Tên biến | Bắt buộc | Giá trị mặc định | Giải thích chi tiết |
|---|:---:|:---:|---|
| `WAZUH_API_URL` | **Có** | `https://127.0.0.1:55000` | URL máy chủ Wazuh Manager (ví dụ: `https://192.168.1.50:55000`) |
| `WAZUH_API_USER` | **Có** | `wazuh` | Tài khoản API của Wazuh (khuyến nghị tạo user readonly cho audit) |
| `WAZUH_API_PASSWORD` | **Có** | *(Để trống)* | Mật khẩu truy cập Wazuh API |
| `WAZUH_VERIFY_SSL` | Không | `false` | Đặt `false` nếu Wazuh dùng chứng chỉ tự ký (Self-signed certificate) |
| `WSUS_SERVER_FQDN` | **Có** | `wsus.corp.local` | Tên miền FQDN hoặc địa chỉ IP của máy chủ WSUS |
| `WSUS_PORT` | Không | `8530` | Cổng WSUS (`8530` cho HTTP, `8531` cho HTTPS) |
| `WSUS_USE_SSL` | Không | `false` | Đặt `true` nếu WSUS cấu hình HTTPS/SSL |
| `AD_DOMAIN` | Không | `CORP.LOCAL` | Tên miền Active Directory |
| `WINRM_USER` | Không | *(Để trống)* | Service Account để chạy audit WMI/HotFix từ xa trên các node |
| `WINRM_PASSWORD` | Không | *(Để trống)* | Mật khẩu của Service Account |
| `MSRC_API_KEY` | Không | *(Để trống)* | API Key của Microsoft Security Response Center (nếu muốn tra online) |
| `ALERT_WEBHOOK_URL`| Không | *(Để trống)* | URL Webhook nhận thông báo khẩn cấp P1 (Teams / Slack / Discord) |
| `ALERT_WEBHOOK_TYPE`| Không | `teams` | Loại webhook: `teams`, `slack`, hoặc `generic` |
| `ENABLE_ALERTS` | Không | `false` | Đặt `true` để bật gửi cảnh báo khi phát hiện P1 hoặc quá hạn SLA |
| `SLA_P1_CRITICAL_HOURS`| Không| `72` | SLA xử lý lỗ hổng khẩn cấp P1 (≤ 72 giờ) |
| `SLA_P2_HIGH_DAYS` | Không | `14` | SLA xử lý lỗ hổng P2 High (≤ 14 ngày) |
| `SLA_P3_MEDIUM_DAYS`| Không | `30` | SLA xử lý P3 Medium (≤ 30 ngày - theo chu kỳ tháng) |
| `SLA_P4_LOW_DAYS` | Không | `90` | SLA xử lý P4 Low (≤ 90 ngày) |
| `GEMINI_API_KEY` | Không | *(Để trống)* | Google Gemini AI Studio API Key để hướng dẫn khắc phục lỗ hổng không có KB |
| `GEMINI_MODEL` | Không | `gemini-2.5-flash` | Model AI phân tích an ninh mạng (Gemini 2.5 Flash / 1.5 Pro) |

---

## 2. Cấu trúc Module Hệ thống

```
Patch management/
│
├── config/
│   ├── groups.json             # Cấu trúc nhóm máy tính WSUS (00-Test -> 07-Production)
│   ├── exceptions.json         # Sổ đăng ký ngoại lệ lỗ hổng (Compensating Controls)
│   └── cve_kb_cache.json       # Cơ sở dữ liệu ánh xạ CVE -> Microsoft KB
│
├── core/
│   ├── config.py               # Nạp cấu hình & kiểm soát biến môi trường
│   ├── wazuh_client.py         # Kết nối Wazuh REST API (Lỗ hổng & Syscollector)
│   ├── cve_kb_mapper.py        # Thực thi Golden Rule #3: Map CVE -> KB
│   ├── validator.py            # Thực thi Golden Rule #4: Đối chiếu Hotfix & OS Build
│   ├── sla_tracker.py          # Tính toán hạn SLA P1-P4 & phát hiện quá hạn
│   ├── exception_manager.py    # Quản lý ngoại lệ, người duyệt và thời hạn
│   ├── notifier.py             # Bắn cảnh báo Webhook (Teams / Slack)
│   └── reporter.py             # Tạo Dashboard HTML Executive và JSON Audit
│
├── scripts/
│   ├── Get-NodePatchStatus.ps1 # Kiểm tra HotFix, OS Build, Pending Reboot trên máy trạm/server
│   ├── Invoke-WsusPatchFlow.ps1# Tự động hóa phân phối và approve cập nhật trên WSUS
│   └── Invoke-HyperVPatch.ps1  # Quy trình vá máy chủ ảo hóa Hyper-V (Drain VM, Reboot, Verify)
│
├── reports/                    # Lưu trữ các báo cáo tuân thủ HTML và JSON
├── .env.example                # File mẫu cấu hình biến môi trường
├── .gitignore                  # Bảo vệ file .env và báo cáo mật không bị lộ
└── main.py                     # CLI điều khiển trung tâm toàn bộ hệ thống
```

---

## 3. Các Lệnh Vận hành Chính (CLI)

### 3.1. Kiểm tra cấu hình và xem danh sách biến còn thiếu
```powershell
python main.py check-env
```

### 3.2. Chạy thử nghiệm mô phỏng toàn bộ quy trình (Demo Mode)
Chạy kịch bản hoàn chỉnh để tạo mẫu báo cáo Dashboard, kiểm tra Rule #4 và tính toán SLA:
```powershell
python main.py demo
```
Báo cáo sẽ được xuất ra file HTML tương tác tại: `reports/latest_dashboard.html`.

### 3.3. Kiểm tra kết nối tới Wazuh API thực tế
```powershell
python main.py test-conn
```

### 3.4. Quét và kiểm toán toàn diện hệ thống từ Wazuh
```powershell
python main.py scan
```

### 3.5. Đăng ký Ngoại lệ Lỗ hổng (Exception Management)
Khi một máy chủ chạy ứng dụng cũ không thể vá trong SLA, khai báo ngoại lệ chính thức:
```powershell
python main.py add-exception --cve CVE-2024-12345 --server ERP-PROD01 --reason "Phần mềm ERP của hãng thứ 3 chưa tương thích với bản vá tháng này" --control "Cô lập qua VLAN riêng, bật Windows Firewall chặn IP lạ, giám sát Wazuh FIM" --owner "ERP-Team" --approved-by "SecOps-Lead" --expires 2026-12-31
```

### 3.6. Khởi chạy Giao diện Web Trực quan (Web Dashboard & AI Gemini Advisor)
Khởi chạy máy chủ giao diện Web tương tác:
```powershell
python main.py web
# Hoặc: python server.py
```
Truy cập trình duyệt tại: **`http://localhost:8080`**

**Các tính năng nổi bật trên Web:**
1. **Theo dõi trạng thái triển khai KB & Kiểm soát Phê duyệt WSUS (Tránh đẩy trùng lặp):**
   - Trạng thái `ĐÃ KHẮC PHỤC (SOLVED)` khi Wazuh xác nhận.
   - Trạng thái `ĐÃ CÀI KB • CHỜ WAZUH RESCAN` (Áp dụng **Golden Rule #4**: đối chiếu Hotfix thực tế để phát hiện máy chủ đã vá thành công nhưng chưa tới chu kỳ quét syscollector).
   - Nhận biết trạng thái `⚡ ĐÃ PHÊ DUYỆT TRÊN WSUS`: Hệ thống ghi nhớ các bản vá đã approved cho nhóm `BPVN-Server` để **chặn hoàn toàn việc đẩy lại bản vá trùng lặp**.
   - Cung cấp nút **`❌ Hủy Duyệt (Unapprove)`** để thu hồi bản vá khỏi nhóm WSUS khi cần thiết.
   - Nhận diện cờ `Reboot Pending` (CBS, WindowsUpdate, PendingFileRename).
2. **Kích hoạt Cài đặt Bản vá đã đẩy về máy chủ (`⬇️ Cài đặt ngay`):**
   - Khi máy chủ đã nhận bản vá từ WSUS về cache cục bộ nhưng chưa cài đặt, cung cấp nút **`⬇️ Cài đặt ngay (Trigger Install)`** để kích hoạt cài đặt tự động qua Windows Update Agent (`Install-PendingUpdates.ps1`).
3. **Đặt lịch Wazuh Quét Lỗ hổng Liên tục & Tự động Cập nhật Feed Hàng ngày:**
   - Hệ thống chạy ngầm bộ lập lịch `AutoScanScheduler`: Tự động rà soát 19 agents sau mỗi 30 phút.
   - Hiển thị bộ đếm chu kỳ quét tự động ngay trên thanh điều hướng Web.
   - Đi kèm file cấu hình mẫu [`config/wazuh_vulnerability_detector_config.xml`](file:///d:/BPVN/Patch%20management/config/wazuh_vulnerability_detector_config.xml) để kích hoạt quét liên tục và tự động tải CTI feed (Microsoft MSU, NVD, CISA KEV) từ Internet hàng ngày trên Wazuh Manager.
4. **Khi click vào từng máy chủ (Server Inspector):**
   - Xem thông tin chi tiết: Tên máy, OS, OS Build, nhóm WSUS, tổng số KB đã cài.
   - Danh sách chi tiết từng CVE: Tiêu đề, mức độ rủi ro (Critical/High), điểm CVSS, mã KB Microsoft tương ứng.
5. **Khi lỗ hổng KHÔNG CÓ BẢN VÁ KB:**
   - Nút **`🤖 Hỏi AI Gemini Hướng dẫn Khắc phục`**: Gọi trực tiếp mô hình Google Gemini AI để phân tích bề mặt tấn công, kịch bản giảm nhẹ, script PowerShell mẫu và biện pháp bù đắp (Compensating Controls).
   - Nút **`📋 Sao chép Lệnh PowerShell`** và **`📝 Đăng ký Ngoại lệ`** chỉ bằng 1 cú nhấp chuột.

---

## 4. Hướng dẫn sử dụng PowerShell Scripts

### 4.1. Thu thập trạng thái Node (HotFix, OS Build, Reboot Pending, Wazuh)
Chạy trực tiếp trên máy chủ mục tiêu hoặc từ xa qua WinRM:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\Get-NodePatchStatus.ps1 -OutputJson C:\Temp\node_status.json
```
Để buộc Wazuh Agent quét lại Syscollector ngay lập tức:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\Get-NodePatchStatus.ps1 -TriggerWazuhScan
```

### 4.2. Phê duyệt bản vá theo phân tầng WSUS (00-Test -> 07-Production)
Xem danh sách Computer Groups:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\Invoke-WsusPatchFlow.ps1 -Action ListGroups
```
Phê duyệt bản vá cho nhóm thử nghiệm `00-Test`:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\Invoke-WsusPatchFlow.ps1 -Action ApproveUpdate -TargetGroup "00-Test" -KbNumber "KB5040437"
```

### 4.3. Bảo trì & Vá Hyper-V Host
Tuân thủ nghiêm ngặt nguyên tắc **Verify Backup**:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\Invoke-HyperVPatch.ps1 -Mode Standalone -BackupVerified
```
Đối với Hyper-V Failover Cluster (tự động drain VMs sang node khác trước khi vá):
```powershell
powershell -ExecutionPolicy Bypass -File scripts\Invoke-HyperVPatch.ps1 -Mode Cluster -BackupVerified
```
