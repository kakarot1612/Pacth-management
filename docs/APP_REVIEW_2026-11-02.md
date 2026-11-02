# Đánh giá ứng dụng ngày 02/11/2026

## Kết luận

Ứng dụng có backend Python, dashboard, kiểm toán Rule #4, báo cáo và các script vận hành. Chưa đủ bằng chứng xác nhận chạy hoàn chỉnh trên 19 máy chủ production. Kiểm tra lần này dùng dữ liệu cô lập, không approve, cài KB, restart agent hay reboot máy chủ thật.

## Đối chiếu tài liệu

| Chức năng | Nhận xét từ mã nguồn và kiểm tra |
|---|---|
| Dashboard, API danh sách máy chủ/nhóm/lịch quét | Các endpoint cơ bản trả HTTP 200 trong kiểm tra cô lập; chưa kiểm tra tương tác trình duyệt |
| Wazuh | Có xác thực và refresh token; có Indexer và file export. Đã sửa thiếu import JSON làm hỏng đọc export. Chưa xác minh dữ liệu live, phân trang vẫn giới hạn 500 ở nhiều truy vấn |
| CVE → Product → KB | Đã bỏ fallback lấy KB/build đầu tiên khi không khớp OS; cache cần được quản trị viên xác minh theo sản phẩm trước rollout |
| Rule #4 | Đã sửa so sánh build khác nhánh Windows; hỗ trợ dạng 10.0.build.revision. Cờ reboot đơn lẻ không còn làm biến mất mọi CVE OS |
| Reboot | KB có mặt nhưng build chưa đạt và chờ reboot vẫn cần xử lý, không tính là đã khắc phục. Không tự xóa cờ reboot khi danh sách CVE trống hoặc không đủ bằng chứng build |
| WSUS approve/unapprove | Trước đây chỉ sửa JSON. Đã bổ sung client và script gọi WSUS API; lỗi WSUS trả 502, UI báo lỗi. Chỉ hiển thị lịch sử có source WSUS; dữ liệu cũ chưa xác minh không còn được dùng làm bằng chứng approve |
| Cài KB | API hiện tạo lệnh để người vận hành chạy; chưa thực thi từ xa |
| Hyper-V | Có script riêng; chưa kiểm chứng drain/migration/backup/reboot/restore trên hạ tầng thật |
| Scheduler | Có singleton chu kỳ mặc định 30 phút; scan lỗi xác thực không còn báo hoàn tất thành công |
| AI/MCP | Có mã tích hợp và fallback. Chưa kiểm tra dịch vụ live; nội dung fallback chưa đáp ứng yêu cầu “No Mock / Zero Template” trong tài liệu kiến trúc |
| GPO/AD | Nút trước đây dùng timer rồi báo đã xếp hàng dù không có backend; đã đổi thành thông báo chưa tích hợp và yêu cầu chạy script có kiểm soát |
| Export/SLA/ngoại lệ | Có module; chưa xác minh toàn bộ quy trình nghiệp vụ, dữ liệu thời hạn và độ chính xác từng mẫu báo cáo |

## Điều chỉnh tài liệu kiến trúc

Luồng trong APP_WORKFLOW_ARCHITECTURE.md coi bật cờ reboot là đã khắc phục và giảm Active về 0 không phải bằng chứng đủ để đóng CVE. Hành vi sửa lại giữ CVE cần xử lý cho đến khi có build phù hợp; cờ thủ công chỉ là thông tin vận hành. Build phải cùng nhánh Windows, không suy ra Server 2022 đã vá chỉ từ baseline của Server 2019.

## Điều kiện sử dụng WSUS mới

Máy chạy backend cần Windows PowerShell và WSUS Administration Console/RSAT. Tài khoản chạy tiến trình app phải có quyền WSUS; client mới sử dụng Windows identity của tiến trình, không impersonate bằng WSUS_USER/WSUS_PASSWORD. Cần cấu hình WSUS_SERVER_FQDN, WSUS_PORT và WSUS_USE_SSL. Phê duyệt chỉ cấp quyền phân phối; không chứng minh máy đích đã tải/cài bản vá. Một KB có thể có nhiều update theo sản phẩm trong WSUS.

## Phần còn cần hoàn thiện trước triển khai rộng

- Kiểm thử live theo nhóm TEST rồi mới production; app chưa cưỡng chế bằng mã điều kiện TEST đã đạt trước khi approve production.
- Xác thực và phân quyền người dùng: HTTP server hiện lắng nghe 0.0.0.0, chưa có đăng nhập cho API thay đổi trạng thái.
- Phân biệt rõ dữ liệu scanner với baseline suy luận và trạng thái thiếu dữ liệu; không dùng scan rỗng làm bằng chứng tuân thủ toàn bộ.
- Phân trang dữ liệu Wazuh/Indexer, đồng bộ trạng thái WSUS định kỳ; lịch sử local không thay thế trạng thái WSUS live khi có thay đổi ngoài app.
- Khóa/ghi nguyên tử cho các JSON và điều phối scan khi nhiều request/scheduler chạy đồng thời.
- Hoàn thiện thực thi từ xa, rollout theo nhóm và kiểm tra ứng dụng sau vá nếu cần tự động hóa đầy đủ.

## Kiểm chứng đã chạy

- `python -m unittest discover -s tests -v`: 8 kiểm tra hồi quy đạt.
- `python -m compileall -q core server.py main.py`: đạt.
- `node --check web/js/app.js`: đạt.
- HTTP server cô lập: `/`, `/api/status`, `/api/servers`, `/api/groups`, `/api/scheduler-status`, `/api/wsus-approvals` trả 200; JSON sai trả 400; WSUS giả lập mất kết nối trả 502 và success=false.

Các kiểm tra trên không chứng minh WSUS/Hyper-V/AI/MCP đã chạy thành công trong môi trường thật.
