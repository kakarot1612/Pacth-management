# Cấu hình bảo mật và độ tin cậy

## Tạo tài khoản đầu tiên

Chạy tại thư mục dự án trên máy chủ:

```powershell
python scripts/manage_users.py admin --role admin
```

Nhập mật khẩu tối thiểu 12 ký tự và xác nhận. Mật khẩu không hiện trên màn hình; app chỉ lưu PBKDF2-SHA256 với salt riêng, 600.000 vòng. Không có tài khoản/mật khẩu mặc định. File `config/auth_users.json` đã được bỏ qua bởi Git; giới hạn NTFS ACL cho tài khoản chạy app và quản trị viên.

Mở http://localhost:8080 và đăng nhập qua hộp thoại của trình duyệt. HTTP Basic phù hợp truy cập loopback hoặc đặt sau reverse proxy HTTPS. Không mở HTTP Basic trực tiếp qua mạng không mã hóa. Trình duyệt có thể cache thông tin đăng nhập; dùng cửa sổ riêng hoặc đóng phiên trình duyệt khi đổi người dùng. Khi chưa cấu hình tài khoản, API trả 503 và không cho thao tác quản trị.

Tạo tài khoản bổ sung bằng cùng lệnh với tên và vai trò khác. Chạy lại để đổi mật khẩu/vai trò. Có thể vô hiệu hóa user bằng `enabled: false` trong file quản trị; app đọc lại file theo request.

| Vai trò | Quyền |
|---|---|
| viewer | Đọc dashboard, báo cáo và dữ liệu |
| analyst | Quyền đọc + yêu cầu tư vấn AI và bulk enrichment |
| operator | Quyền đọc + quét, cập nhật cờ reboot, tạo lệnh cài đặt |
| approver | Quyền đọc + approve/unapprove WSUS, đăng ký ngoại lệ |
| admin | Toàn bộ API |

Đây là phân quyền theo vai trò đơn; chưa có quy trình hai người cùng phê duyệt. Nhật ký thao tác ghi username đã xác thực; trường người duyệt ngoại lệ lấy từ tài khoản thực tế. Cross-origin POST bị chặn, không còn CORS wildcard. Request body giới hạn 1 MB; giới hạn thử sai theo địa chỉ trong bộ nhớ tiến trình.

## Cấu hình AI và độ mới

Trong `.env`:

```dotenv
AI_PROVIDER=gemini
WEB_BIND_HOST=127.0.0.1
DATA_MAX_AGE_MINUTES=60
```

Provider hỗ trợ `gemini`, `openrouter`, `disabled`. Mặc định Gemini; không tự chuyển sang vendor khác khi lỗi. Cấu hình key tương ứng và restart server sau thay đổi `.env`. Gemini trả JSON theo schema rồi backend kiểm tra cấu trúc. Mọi tư vấn đều yêu cầu con người xem xét; app không chạy script AI. Dữ liệu ngoài được đánh dấu không tin cậy trong prompt. Chính sách prompt không phải bảo đảm chống prompt injection hoàn toàn.

Không có provider/key hoặc dịch vụ lỗi: trả trạng thái unavailable; không sinh playbook giả như kết quả AI live. Schema kiểm soát cấu trúc, không xác nhận tính đúng của lời tư vấn. OpenRouter vẫn trả nội dung Markdown kèm bằng chứng và yêu cầu review.

## Nguồn tình báo và chất lượng dữ liệu

- EPSS: truy vấn FIRST, giữ nguyên 0 thực; thiếu dữ liệu dùng null/N/A.
- KEV: tải catalog CISA, không suy ra từ EPSS, tên CVE hay chữ Ransomware. Catalog cache theo giờ; nếu refresh lỗi, cache cũ có nhãn stale.
- PoC: chỉ xác nhận khi có URL HTTPS trong `poc_references` từ MCP. URL là bằng chứng do nguồn cung cấp, chưa được app tải và thẩm định nội dung. Không có URL thì unknown.
- MCP: hỗ trợ JSON hoặc SSE cho kết quả tools/call; chỉ trường JSON đúng kiểu mới được dùng làm telemetry. Văn bản tự do không dùng để suy luận KEV/PoC. Server yêu cầu handshake/session riêng có thể cần adapter bổ sung; khi lỗi sẽ chuyển sang feed trực tiếp với nguồn ghi rõ.
- ATT&CK: mapping dựa từ khóa được ghi heuristic.
- Điểm rủi ro tổng hợp chưa đủ đầu vào trả null, không dùng điểm mặc định.
- Mỗi kết quả có data_status, fetched_at và evidence theo từng nguồn; observed_at chỉ có khi nguồn cung cấp. Cache tình báo hiện trong RAM, không tồn tại qua restart.

Wazuh: dữ liệu live trả fresh, export trả stale, baseline suy luận trả inferred. Snapshot không có trạng thái nguồn hoặc bị cũ không được báo COMPLIANT. Đây là chất lượng thu thập tại app; fresh không bảo đảm agent đã thu thập inventory mới ngay tại endpoint. Indexer trả quá giới hạn truy vấn được đánh dấu partial; chưa triển khai đầy đủ phân trang.

## Tính sẵn sàng và giới hạn còn lại

Full scan có khóa chống chạy trùng trong cùng tiến trình. Báo cáo latest và audit log dùng thay file nguyên tử để tránh đọc JSON dở dang; audit log có khóa cập nhật trong tiến trình. Quét lại một agent không restart dịch vụ Wazuh agent nữa.

Các phần này chưa thay thế database/job queue bền vững. Chưa triển khai migration SQLite/PostgreSQL, nhiều instance, Windows Service, cưỡng chế TEST trước production hoặc đồng bộ WSUS liên tục. Một số file trạng thái nghiệp vụ vẫn sử dụng JSON và cần tiếp tục chuyển sang transaction. Chưa xác nhận TLS/RSAT/WSUS/Hyper-V/AI/MCP trên hạ tầng thật.

## Kiểm tra

```powershell
python -m unittest discover -s tests -v
python -m compileall -q core server.py main.py scripts/manage_users.py
node --check web/js/app.js
```

Các bài kiểm tra dùng dữ liệu tạm và mock dịch vụ ngoài; không phê duyệt WSUS, cài KB hoặc reboot máy chủ thật.
