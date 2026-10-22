# Test multiple credential combinations for WSUS 10.0.60.32
$wsusHost = "10.0.60.32"

$credsToTest = @(
    @{ User = ".\vn_batch"; Pass = 'bpvn@123$$' },
    @{ User = "vn_batch"; Pass = 'bpvn@123$$' },
    @{ User = "VN-WSUS01\vn_batch"; Pass = 'bpvn@123$$' },
    @{ User = "BESTPACIFIC\vn_audit_patch"; Pass = 'Bpvn@2026-1' },
    @{ User = "administrator"; Pass = 'bpvn@123$$' },
    @{ User = "Administrator"; Pass = 'Bpvn@2026-1' }
)

foreach ($c in $credsToTest) {
    Write-Host "Testing account: $($c.User)..." -NoNewline
    $res = cmd.exe /c "net use \\$wsusHost\IPC$ /user:$($c.User) $($c.Pass)" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host " [SUCCESS!]" -ForegroundColor Green
        # Try WSUS AdminProxy
        [void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
        try {
            $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($wsusHost, $false, 8530)
            Write-Host "  -> WSUS AdminProxy connected successfully!" -ForegroundColor Green
            $groups = $wsus.GetComputerTargetGroups()
            foreach ($g in $groups) {
                Write-Host "     * Group: $($g.Name)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  -> WSUS AdminProxy: $($_.Exception.Message)" -ForegroundColor Red
        }
        cmd.exe /c "net use \\$wsusHost\IPC$ /delete /y" 2>&1 | Out-Null
        break
    } else {
        Write-Host " [FAILED: $($res -join ' ')]" -ForegroundColor Gray
    }
}
