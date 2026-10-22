# Wazuh Verification & Compliance

## 1. Quy trình Xác minh (Verification)
Sau khi Patch & Reboot:
Agent Online → Syscollector quét Inventory → Hotfix Inventory cập nhật → Module Vulnerability đánh giá lại → Trạng thái CVE chuyển từ `Active` sang `Solved`.

## 2. Xử lý khi Wazuh vẫn báo Active
Không tự động kết luận quá trình patch lỗi. Kiểm tra chéo:
1. Chạy `Get-HotFix` xem KB đã cài chưa.
2. Chạy `Get-ComputerInfo` xem OS Build đã đạt Target Build chưa.
3. Kiểm tra Wazuh CTI/Hotfix Inventory đã cập nhật dữ liệu chưa.

## 3. Metrics & Compliance
Quản lý qua Dashboard:
* Patch compliance: ≥ 95%
* Critical patch compliance: ≥ 98%
* Failed patches: < 2%
* Reboot pending: 0 (trên Critical servers)

## 4. Xác thực Wazuh API & Quản lý Vòng đời Token (15 Phút)
* **Endpoint cấp Token:** `POST /security/user/authenticate` (Basic Auth bằng user/pass).
* **Thời hạn hiệu lực mặc định (Token TTL):** **15 phút (900 giây)**.
* **Định dạng Header bắt buộc cho mọi request:**
  ```http
  Authorization: Bearer <TOKEN>
  Content-Type: application/json
  ```
* **Cơ chế tự động làm mới của Hệ thống:**
  1. *Làm mới chủ động (Proactive Refresh):* Bộ mã nguồn tự động đếm thời gian kể từ khi sinh token; nếu token đã dùng qua **14 phút** (840s), hệ thống tự động gọi authenticate để lấy token mới trước khi gửi request tiếp theo.
  2. *Làm mới phản hồi (Reactive Fallback):* Nếu bất kỳ request nào nhận mã lỗi `HTTP 401 Unauthorized`, hệ thống tự động xóa token cũ, xác thực lại và thực thi lại request ngay lập tức mà không làm gián đoạn tiến trình audit.