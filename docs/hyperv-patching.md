# Quy trình Vá Hyper-V Host

## 1. Yêu cầu bắt buộc
* Hyper-V patch thường yêu cầu Reboot.
* Phải có Maintenance Window và Kế hoạch Backup/Rollback (không chỉ tin vào "Backup Job Successful").

## 2. Quy trình Cluster (Nếu có)
1. Chọn Node 1 → Drain / Live Migration VMs sang Node khác.
2. Áp dụng Patch (WSUS) → Reboot Node 1.
3. Validate Node 1 (OS Build, Hyper-V Services).
4. Đưa Node 1 lại Cluster → Tiếp tục Node 2.

## 3. Quy trình Standalone
1. Chốt Maintenance Window → Verify Backup.
2. Shutdown VM an toàn.
3. Cài Patch → Reboot Host.
4. Validate OS Build & HotFix.
5. Start VM & Validate Application Services.

## 4. Scripts Hỗ trợ
**Kiểm tra Build & KB sau vá:**
```powershell
Get-ComputerInfo | Select-Object WindowsProductName, OsBuildNumber
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10