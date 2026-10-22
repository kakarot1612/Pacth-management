# Quản lý WSUS & Phân phối Bản vá

## 1. Thiết kế Computer Groups
Không approve trực tiếp update vào toàn bộ hệ thống cùng lúc mà phải chia theo phân kỳ (Phased Rollout).

* **Lưu ý:** Các tên nhóm dưới đây là **mô hình mẫu gợi ý**. Hệ thống hoàn toàn linh hoạt và cho phép bạn áp dụng đúng 100% cấu trúc nhóm thực tế của công ty (qua file `config/groups.json` hoặc tự động đồng bộ từ WSUS qua lệnh `Invoke-WsusPatchFlow.ps1 -Action SyncGroups`):
  * Nhóm Thử nghiệm (Pilot/Test)
  * Nhóm Hạ tầng IT & Ứng dụng nội bộ
  * Nhóm Máy chủ Sản xuất (Production)
  * Nhóm Máy chủ Quan trọng / Hyper-V (Critical Infra)

*(Xem file `config/groups.json` để chỉnh sửa danh sách nhóm thực tế của bạn).*

## 2. Ánh xạ CVE sang KB (Bắt buộc)
Wazuh báo CVE → Kiểm tra Affected Version → Tra cứu Microsoft Update Guide → Lấy mã KB và Target OS Build.

## 3. Quy trình Phê duyệt (Approval Flow)
Microsoft Update → WSUS Sync → Approve to 00-Test → Install & Validate → Approve to Production Groups.