# Quản lý Vulnerability & Patch Management

## 1. Mục tiêu
Thiết lập quy trình thống nhất để phát hiện, đánh giá, lập kế hoạch, kiểm thử, triển khai và xác nhận đóng các lỗ hổng bảo mật (Vulnerabilities) trên hệ thống máy chủ.

* **Hệ thống áp dụng:** Wazuh, WSUS, Active Directory, Windows Server, Hyper-V.
* **Phạm vi:** Windows Server, Hyper-V Host, Windows VM và các endpoint quản lý tập trung.

## 2. Kiến trúc & Vai trò
* **Microsoft Security Update:** Nguồn CVE, KB, và bản vá chính thức.
* **Wazuh (Detection & Verification):** Phát hiện lỗ hổng qua Syscollector và xác nhận trạng thái Remediation (Active/Solved).
* **WSUS (Deployment):** Đồng bộ, quản lý, approve và phân phối cập nhật.
* **Active Directory/GPO:** Quản lý Windows Update policy trên các node.
* **Windows/Hyper-V:** Endpoint thực thi.

## 3. Nguyên tắc Vận hành (Golden Rules)
1. Wazuh là công cụ phát hiện và xác minh, không phải công cụ push patch.
2. WSUS là kênh phân phối độc quyền cho Microsoft Updates.
3. Không patch production chỉ dựa vào CVE ID (Phải map: CVE → Product → Fixed Version → KB).
4. Không coi "Wazuh Active" là bằng chứng duy nhất cho việc patch thất bại (Cần đối chiếu OS Build và Hotfix).
5. Mọi bản vá phải qua bước TEST trước khi lên Production (trừ khẩn cấp).