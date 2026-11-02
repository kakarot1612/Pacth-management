# TÀI LIỆU KIẾN TRÚC & LUỒNG XỬ LÝ HỆ THỐNG
## VULNERABILITY & PATCH MANAGEMENT AUTOMATION PLATFORM (BPVN SECOPS)

---

## 1. TỔNG QUAN HỆ THỐNG (SYSTEM OVERVIEW)

Hệ thống **Vulnerability & Patch Management Automation** là nền tảng quản trị vòng đời lỗ hổng và kiểm soát bản vá tập trung dành cho hạ tầng **19 máy chủ Windows Server** tại Best Pacific Vietnam (BPVN).

### Mục tiêu cốt lõi:
1. **Giải quyết triệt để độ trễ dữ liệu giữa Scanner và WSUS:** Khắc phục tình trạng Wazuh cảnh báo sai/cảnh báo chậm sau khi máy chủ đã cập nhật bản vá tích lũy (LCU) hoặc đang chờ khởi động lại thông qua **Quy tắc Kiểm toán Rule #4**.
2. **Đối chiếu thời gian thực (Real-time Cross-Validation):** Kết nối đồng thời **Wazuh SIEM/Syscollector**, **Hệ thống cập nhật WSUS**, **Hạ tầng CVE Threat Intel (FastMCP)** và **Trợ lý AI (Google Gemini)**.
3. **Chuẩn hóa quy trình vận hành SecOps:** Quản lý từ khâu rà quét, phê duyệt WSUS, theo dõi cài đặt & reboot, đánh giá SLA, tới lập hồ sơ kiểm toán tuân thủ chuẩn ISO/IEC 27001 & NIST.

---

## 2. MÔ HÌNH KIẾN TRÚC CHỨC NĂNG (FUNCTIONAL ARCHITECTURE)

```mermaid
flowchart TD
    subgraph DATA_SOURCES["1. TẦNG THU THẬP & DỮ LIỆU NGOẠI VI"]
        Wazuh["Wazuh Manager API (10.0.55.249:55000)<br>• 19 Windows Agents<br>• Syscollector: OS Build, Hotfixes, Software Packages<br>• Active Vulnerabilities"]
        WSUS["WSUS Server (10.0.55.240:8530)<br>• Target Computer Groups<br>• KB Approvals & Sync"]
        MCP["FastMCP Server (10.0.55.240:8001)<br>• Tool triage_cve<br>• EPSS Score, CISA KEV, CVSS"]
        Gemini["Google Gemini AI (gemini-3.1-flash-lite)<br>• Live Security Guidance<br>• Hardening Playbooks & Exceptions"]
    end

    subgraph CORE_ENGINE["2. TẦNG XỬ LÝ NGHIỆP VỤ CỐT LÕI (CORE ENGINE)"]
        Mapper["CVE-KB Mapper<br>(core/cve_kb_mapper.py)<br>Ánh xạ CVE sang KB & Min OS Build"]
        Validator["Rule #4 Validator<br>(core/validator.py)<br>Kiểm toán đa tầng: Build, KB, Reboot"]
        RebootMgr["Reboot State Manager<br>(config/reboot_status.json)<br>Theo dõi cờ Pending Restart"]
        ThreatEngine["Threat Intel Engine<br>(core/threat_intel.py)<br>Làm giàu dữ liệu & tính điểm rủi ro"]
        Scheduler["Auto-Scan Scheduler<br>(core/scheduler.py)<br>Quét nền định kỳ mỗi 30 phút"]
        SlaMgr["SLA & Exception Manager<br>(core/sla_tracker.py)<br>P1/P2/P3 Tracking & Ngoại lệ"]
        Reporter["Audit Reporter<br>(core/reporter.py)<br>Tính toán % Tuân thủ & Export CSV/HTML"]
    end

    subgraph PRESENTATION["3. TẦNG TRÌNH DIỄN & GIAO DIỆN QUẢN TRỊ (PORT 8080)"]
        ServerPy["HTTP / REST API Server (server.py)<br>• /api/status, /api/servers, /api/scan<br>• /api/server-reboot-status, /api/approve-kb<br>• /api/ai-advice, /api/export-*"]
        UI_Vulns["Tab 1: Vulnerabilities Dashboard<br>• KPI Cards, Fixable vs Manual"]
        UI_Systems["Tab 2: Systems (19 Hosts)<br>• Chi tiết Build, Hotfixes, Cờ Reboot tương tác"]
        UI_Patches["Tab 3: Patches & Deployment<br>• Trạng thái WSUS Push & Approvals"]
        UI_Intel["Tab 4: Threat Intel & MCP<br>• Ma trận EPSS %, CISA KEV Catalog"]
        UI_Compliance["Tab 5: Compliance & SLA Audit<br>• Báo cáo thanh tra in chuẩn A4"]
    end

    Wazuh -->|Syscollector Live API| CoreEngine
    WSUS <-->|Approvals Config| CoreEngine
    MCP <-->|SSE Stream Tool Call| ThreatEngine
    Gemini <-->|Dynamic Telemetry Prompt| CoreEngine

    CoreEngine --> ServerPy
    ServerPy --> UI_Vulns
    ServerPy --> UI_Systems
    ServerPy --> UI_Patches
    ServerPy --> UI_Intel
    ServerPy --> UI_Compliance
```

---

## 3. CÁC MODULE CHỨC NĂNG CHÍNH (CORE MODULES)

| Module | Tệp mã nguồn | Vai trò chức năng chính |
| :--- | :--- | :--- |
| **Wazuh Connector** | `core/wazuh_client.py` | Kết nối xác thực Bearer Token (AES/HTTPS) với Wazuh Manager. Thu thập danh sách 19 agents, phần mềm đã cài, danh sách Hotfix (KB), và phiên bản Kernel OS Build chi tiết. |
| **CVE-KB Mapper** | `core/cve_kb_mapper.py` | Cơ sở tri thức ánh xạ các mã lỗ hổng CVE của Microsoft sang số hiệu KB tích lũy tương ứng cùng **Số hiệu Kernel Build tối thiểu** (`min_build`) cần đạt được để giải quyết lỗ hổng. |
| **Rule #4 Validator** | `core/validator.py` | Trái tim logic của app: Đối chiếu trạng thái thực tế của máy chủ để phán quyết chính xác xem lỗ hổng còn tồn tại hay đã được khắc phục. |
| **Threat Intel Engine** | `core/threat_intel.py` | Kết nối qua giao thức SSE tới **FastMCP Server** (`10.0.55.240:8001`) để lấy điểm dự đoán khai thác thực tế **EPSS (FIRST.org)**, kiểm tra danh mục vũ khí hóa **CISA KEV**, và tính điểm rủi ro tổng hợp. |
| **Live AI Advisor** | `core/ai_advisor.py` | Tích hợp **Google Gemini API** (`gemini-3.1-flash-lite`). Tiếp nhận thông số live (tên máy chủ, OS, CVE, CVSS, EPSS) để sinh giải pháp cô lập, kịch bản PowerShell thực thi ngay và phiếu đăng ký ngoại lệ (Exception ticket) không dùng mẫu cố định. |
| **Auto-Scan Scheduler** | `core/scheduler.py` | Tiến trình Worker chạy ngầm, tự động kích hoạt chu kỳ kiểm toán và tái đối chiếu toàn bộ 19 máy chủ định kỳ **mỗi 30 phút**. |
| **Audit & Exporter** | `core/reporter.py`<br>`core/audit_exporter.py` | Tính toán tỷ lệ tuân thủ toàn công ty (% Compliance), xuất dữ liệu ma trận máy chủ và chi tiết Rule #4 sang tệp **Excel/CSV (UTF-8 BOM)** và **Hồ sơ HTML thanh tra in chuẩn A4**. |

---

## 4. CHI TIẾT LUỒNG XỬ LÝ (END-TO-END WORKFLOW)

### 4.1. Sơ đồ tuần tự xử lý kiểm toán & quản lý bản vá (Sequence Diagram)

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Quản Trị Viên (SecOps/ITOps)
    participant UI as Web App (localhost:8080)
    participant API as Python API (server.py)
    participant Engine as Rule #4 Validator & Engine
    participant Wazuh as Wazuh Manager (10.0.55.249)
    participant WSUS as WSUS Server (10.0.55.240)
    participant Host as Máy chủ Đích (Target Host)

    Note over Admin, Host: GIAI ĐOẠN 1: QUÉT & PHÁT HIỆN LỖ HỔNG (DISCOVERY)
    alt Tự động 30 phút hoặc Bấm "Làm mới"
        Admin->>UI: Bấm [🔄 Làm mới]
        UI->>API: POST /api/scan
        API->>Wazuh: GET /agents, /syscollector/{id}/os, /hotfixes, /vulnerabilities
        Wazuh-->>API: Trả về OS Build, danh sách Hotfix, gói cài đặt
        API->>Engine: Thực hiện kiểm toán Rule #4 cho 19 Máy chủ
        Engine-->>API: Danh sách lỗ hổng Active, Chờ Rescan, Cần Reboot
        API-->>UI: Cập nhật chỉ số KPI, Bảng ma trận 19 Servers
    end

    Note over Admin, Host: GIAI ĐOẠN 2: PHÊ DUYỆT & ĐẨY BẢN VÁ (WSUS APPROVAL)
    Admin->>UI: Xem máy chủ -> Bấm [⚡ Phê Duyệt & Đẩy WSUS]
    UI->>API: POST /api/approve-kb (KB5122877, Group: BPVN-Server)
    API->>WSUS: Ghi nhận trạng thái Approved cho nhóm máy chủ
    API-->>UI: Trạng thái máy chủ chuyển sang: "⚡ Đã Đẩy WSUS (XX)"

    Note over Admin, Host: GIAI ĐOẠN 3: CÀI ĐẶT & CHỜ KHỞI ĐỘNG LẠI (PENDING RESTART)
    Admin->>Host: Đăng nhập máy chủ -> Bấm "Install Updates" trong Windows Update
    Note over Host: Windows tải gói vào WinSxS<br>Tệp Kernel cũ vẫn chạy<br>Build vẫn là 20348.4052<br>Cờ CBS RebootPending được tạo
    Admin->>UI: Bấm [Không (Gắn cờ Đã Cài)] hoặc [Đã Cài Xong • Chờ Restart]
    UI->>API: POST /api/server-reboot-status (reboot_pending = True)
    API->>Engine: Áp dụng Rule #4 chuyển các CVEs sang "Remediated (Pending Rescan)"
    API-->>UI: Badge đổi thành "🔄 Đã Cài KB • Chờ Restart", Lỗ hổng Active = 0

    Note over Admin, Host: GIAI ĐOẠN 4: RESTART & HOÀN TẤT TUÂN THỦ (CLEAN & COMPLIANT)
    Admin->>Host: Tiến hành Restart máy chủ (Khởi động lại)
    Note over Host: Quá trình Boot: "Working on updates..."<br>Windows tráo đổi file ntoskrnl.exe<br>OS Build nhảy lên 20348.5622
    Admin->>UI: Bấm [🔄 Làm mới] (hoặc chờ Scheduler 30 phút)
    UI->>API: POST /api/scan
    API->>Wazuh: Quét lại Syscollector Host
    Wazuh-->>API: OS Build = 20348.5622 (Đã >= 20348.5622)
    API->>Engine: Rule #4 xác nhận LCU Supersedence thỏa mãn -> Tự động xóa cờ Reboot
    API-->>UI: Trạng thái đổi thành "✅ Sạch (Tuân thủ 100%)"
```

---

## 5. BẢN CHẤT LOGIC KIỂM TOÁN "RULE #4" (THE CORE LOGIC)

Rule #4 là giải thuật giải quyết triệt để vấn đề xung đột giữa hệ thống dò quét an ninh (Wazuh) và trạng thái hệ điều hành Windows:

```mermaid
flowchart TD
    Start([Xét 1 lỗ hổng CVE trên Máy chủ]) --> Q1{Wazuh báo trạng thái<br>Solved?}
    Q1 -- Có --> Solved[Trạng thái: SOLVED<br>Lỗ hổng đã sạch]
    
    Q1 -- Không --> Q2{CVE này có tương ứng<br>với KB nào không?}
    
    Q2 -- Không (Lỗ hổng Ứng dụng/3rd Party) --> AppVuln[Trạng thái: CONFIRMED_VULNERABLE<br>Cần nâng cấp phần mềm hoặc bấm Tư Vấn AI]
    
    Q2 -- Có (Lỗ hổng OS) --> Q3{Mã KB đó đã có trong<br>Get-Hotfix của Host?}
    
    Q3 -- Có --> Q4{OS Build hiện tại >=<br>Min Build yêu cầu?}
    Q4 -- Đạt --> Remediated1[Trạng thái: REMEDIATED_PENDING_RESCAN<br>Bản vá đã có hiệu lực trên nhân OS]
    Q4 -- Chưa đạt --> Q5{Máy chủ có cờ<br>Reboot Pending?}
    Q5 -- Có --> Remediated2[Trạng thái: REMEDIATED_PENDING_RESCAN<br>Đã Cài KB • Chờ Restart máy chủ]
    Q5 -- Không --> Staged[Trạng thái: CONFIRMED_VULNERABLE<br>Gói đã tải về - Cần bấm Install]
    
    Q3 -- Không có mã KB trực tiếp --> Q6{OS Build hiện tại >=<br>Min Build của LCU mới hơn?}
    Q6 -- Đạt --> LCU_Match[Trạng thái: REMEDIATED_PENDING_RESCAN<br>LCU Supersedence: Đã vá qua bản vá tích lũy mới]
    Q6 -- Chưa đạt --> Q7{Máy chủ có cờ<br>Reboot Pending?}
    Q7 -- Có --> Remediated3[Trạng thái: REMEDIATED_PENDING_RESCAN<br>Đã Cài KB • Chờ Restart máy chủ]
    Q7 -- Không --> Vuln[Trạng thái: CONFIRMED_VULNERABLE<br>Máy chủ thực sự thiếu bản vá]
```

### Bảng tóm tắt các trạng thái hiển thị trên giao diện:

| Huy hiệu hiển thị (Status Badge) | Điều kiện kỹ thuật thỏa mãn | Ý nghĩa nghiệp vụ |
| :--- | :--- | :--- |
| **`✅ Sạch (Tuân thủ)`** | OS Build hiện tại $\ge$ `min_build` của bản vá LCU. Không còn lỗ hổng active và không cần reboot. | Máy chủ an toàn 100%, tuân thủ tiêu chuẩn an ninh thông tin. |
| **`🔄 Đã Cài KB • Chờ Restart`** | Đã cài đặt gói bản vá qua WSUS / Windows Update, máy chủ đang có cờ `reboot_pending = True`, chưa khởi động lại. | Quản trị viên đã xử lý xong phần cài đặt, chỉ còn chờ cửa sổ bảo trì để khởi động lại máy chủ. |
| **`⚡ Đã Đẩy WSUS (XX)`** | Máy chủ đang có lỗ hổng active, nhưng **toàn bộ các KB tương ứng đã được APPROVED** trên WSUS cho nhóm máy chủ đó. | Bản vá đã sẵn sàng đẩy về node, kỹ sư hạ tầng chỉ cần đăng nhập bấm Cài đặt (Install). |
| **`⚠️ XX Cần vá`** | Máy chủ có lỗ hổng active nhưng bản vá **chưa được phê duyệt** trên WSUS hoặc chưa có hành động khắc phục. | Cần phê duyệt bản vá trên WSUS hoặc áp dụng giải pháp cô lập. |
| **`🛡️ Sạch OS (Còn X App)`** | Bản vá nhân hệ điều hành đã cập nhật đầy đủ, nhưng máy chủ còn tồn tại lỗ hổng phần mềm bên thứ 3 (ví dụ: Outlook, WinRAR, Chrome). | Sử dụng nút **"🤖 Tư Vấn Khắc Phục AI"** để lấy kịch bản PowerShell cô lập hoặc lập phiếu Ngoại lệ. |

---

## 6. QUY TRÌNH TƯ VẤN THỜI GIAN THỰC CỦA AI & MCP THREAT INTEL

Khi người dùng bấm vào nút **"🤖 Tư Vấn Khắc Phục AI"** của bất kỳ lỗ hổng nào:

1. **Truy vấn FastMCP Server (`10.0.55.240:8001/mcp`):**  
   Hệ thống gọi công cụ `triage_cve` thông qua Server-Sent Events (SSE) để trích xuất:
   - Tỷ lệ khai thác thực tế **EPSS Score** (ví dụ `84.23% - Top 1% nguy hiểm nhất`).
   - Cảnh báo mã độc tống tiền trong danh mục **CISA Known Exploited Vulnerabilities (KEV)**.
   - Điểm đánh giá mức độ nghiêm trọng **CVSS v3.1** và phân loại lỗ hổng (CWE).
2. **Kích hoạt Google Gemini AI (`gemini-3.1-flash-lite`):**  
   Đưa trực tiếp dữ liệu đo đạc thời gian thực (tên máy chủ, phiên bản OS, vai trò, dữ liệu MCP) vào mô hình với yêu cầu đầu ra chuẩn SecOps bằng tiếng Việt:
   - **Đánh giá rủi ro thực tế (Exploitability Assessment)**.
   - **Biện pháp phòng vệ bù đắp (Compensating Controls)** khi chưa thể vá ngay.
   - **Kịch bản PowerShell thực thi ngay (Copy-paste ready)** cấu hình tường lửa, tắt cổng dịch vụ bị ảnh hưởng hoặc bật cơ chế Exploit Guard.
   - **Nội dung Phiếu Ngoại Lệ (Vulnerability Exception Ticket)** kèm hạn mức thời gian khuyến nghị.
3. **Tuyệt đối không sử dụng mẫu (No Mock / Zero Template):** Mọi nội dung tư vấn đều được sinh mới linh hoạt theo từng mã CVE và ngữ cảnh cụ thể của từng máy chủ.

---

## 7. CẤU TRÚC LƯU TRỮ VÀ DỮ LIỆU CỦA APP

- `server.py`: Máy chủ HTTP Web Server & REST API chính (cổng 8080).
- `core/`:
  - `config.py`: Nạp biến môi trường (`.env`), cấu hình Wazuh, WSUS, AI Key, ngưỡng SLA.
  - `wazuh_client.py`: Trình kết nối API Wazuh Manager.
  - `cve_kb_mapper.py`: Từ điển ánh xạ CVE $\leftrightarrow$ KB $\leftrightarrow$ OS Build.
  - `validator.py`: Động cơ kiểm toán Rule #4.
  - `threat_intel.py`: Client tích hợp FastMCP Server & First.org EPSS.
  - `ai_advisor.py`: Client tích hợp Google Gemini AI.
  - `scheduler.py`: Bộ lập lịch tự động quét nền 30 phút.
  - `sla_tracker.py`: Giám sát thời hạn xử lý lỗ hổng theo SLA P1/P2/P3.
  - `reporter.py` & `audit_exporter.py`: Trình xuất dữ liệu CSV/HTML.
- `config/`:
  - `reboot_status.json`: Lưu trữ cờ chờ Reboot theo từng máy chủ (`agent_id`).
  - `wsus_approvals.json`: Lưu trữ lịch sử phê duyệt bản vá trên WSUS.
  - `exceptions.json`: Danh mục phiếu ngoại lệ đã được phê duyệt.
- `reports/`:
  - `latest_report.json`: Kết quả kiểm toán mới nhất của toàn bộ 19 máy chủ.
  - `latest_dashboard.html`: Báo cáo HTML trực quan phục vụ lưu trữ kiểm toán.
- `web/`:
  - `index.html`: Giao diện Dashboard quản trị SecOps.
  - `js/app.js`: Toàn bộ logic tương tác phía Client, biểu đồ Chart.js, quản lý bảng dữ liệu và gọi API.
  - `css/style.css`: Giao diện chuẩn Enterprise SecOps Edition.

