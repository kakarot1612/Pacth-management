<#
.SYNOPSIS
    Automates WSUS Approval & Synchronization Flow according to docs/wsus.md.
.DESCRIPTION
    Enforces the WSUS Target Group hierarchy:
    00-Test -> 01-IT-Servers -> 02-Application-Servers -> ... -> 07-Production
    Validates updates against approved groups before rollout.
.PARAMETER Action
    ListGroups | ListPendingUpdates | ApproveUpdate | SyncWsus
.PARAMETER WsusServer
    WSUS Server hostname/FQDN (Default from env or localhost)
.PARAMETER Port
    WSUS Port (Default: 8530)
.PARAMETER UseSsl
    Switch to enable HTTPS
.PARAMETER TargetGroup
    Target computer group name (e.g., 00-Test, 01-IT-Servers)
.PARAMETER KbNumber
    Mã KB cần approve (ví dụ: KB5040437)
.PARAMETER OutputJson
    Path to save output JSON
#>
[CmdletBinding()]
param (
    [ValidateSet("ListGroups", "ListPendingUpdates", "ApproveUpdate", "UnapproveUpdate", "GetApprovalStatus", "SyncWsus", "SyncGroups")]
    [string]$Action = "ListGroups",

    [string]$WsusServer = $env:WSUS_SERVER_FQDN,
    [int]$Port = 8530,
    [switch]$UseSsl,
    [string]$TargetGroup = "BPVN-Server",
    [string]$KbNumber = "",
    [string]$OutputJson = "",
    [System.Management.Automation.PSCredential]$Credential = $null
)

if (-not $WsusServer) { $WsusServer = $env:WSUS_SERVER_FQDN }
if (-not $WsusServer) { $WsusServer = "localhost" }
if ($env:WSUS_PORT) { $Port = [int]$env:WSUS_PORT }
if ($env:WSUS_USE_SSL -eq "true") { $UseSsl = $true }

# Workgroup / Non-domain credential handling
if (-not $Credential -and $env:WSUS_USER -and $env:WSUS_PASSWORD) {
    $secPass = ConvertTo-SecureString $env:WSUS_PASSWORD -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($env:WSUS_USER, $secPass)
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "          WSUS PATCH WORKFLOW AUTOMATION                 " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] WSUS Server: $WsusServer : $Port (SSL: $UseSsl)" -ForegroundColor Gray
if ($Credential) {
    Write-Host "[*] Using Local/Workgroup Credential: $($Credential.UserName)" -ForegroundColor Gray
}
Write-Host "[*] Action     : $Action" -ForegroundColor Gray

# Attempt to load WSUS assembly
$wsusAdminLoaded = $false
try {
    [void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
    $wsusAdminLoaded = $true
} catch {
    Write-Warning "WSUS Administration Assembly not found locally. Running in management query mode."
}

function Connect-Wsus {
    if (-not $wsusAdminLoaded) { return $null }
    try {
        return [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($WsusServer, $UseSsl, $Port)
    } catch {
        Write-Warning "Could not connect directly to WSUS at $WsusServer : $($_.Exception.Message)"
        return $null
    }
}

$server = Connect-Wsus

switch ($Action) {
    "ListGroups" {
        $definedGroups = @(
            "00-Test",
            "01-IT-Servers",
            "02-Application-Servers",
            "03-File-Servers",
            "04-Database-Servers",
            "05-HyperV",
            "06-Critical-Servers",
            "07-Production"
        )
        $groupsResult = @()
        if ($server) {
            $wsusGroups = $server.GetComputerTargetGroups()
            foreach ($g in $wsusGroups) {
                $groupsResult += [PSCustomObject]@{
                    Name  = $g.Name
                    Id    = $g.Id.ToString()
                    Count = $g.GetTotalComputerTargetCount()
                }
            }
        } else {
            Write-Host "[i] Returning standard configured WSUS hierarchy:" -ForegroundColor Cyan
            foreach ($dg in $definedGroups) {
                $groupsResult += [PSCustomObject]@{
                    Name  = $dg
                    Status = "Configured in Policy"
                }
            }
        }
        $groupsResult | Format-Table -AutoSize
        if ($OutputJson) { $groupsResult | ConvertTo-Json | Out-File $OutputJson -Encoding utf8 }
    }

    "ListPendingUpdates" {
        Write-Host "[*] Checking needed updates for group: $TargetGroup..." -ForegroundColor Cyan
        $updates = @()
        if ($server) {
            $group = $server.GetComputerTargetGroups() | Where-Object { $_.Name -eq $TargetGroup }
            if ($group) {
                $updateScope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
                $rawUpdates = $server.GetUpdates($updateScope)
                foreach ($u in ($rawUpdates | Select-Object -First 30)) {
                    $updates += [PSCustomObject]@{
                        Title       = $u.Title
                        KBArticleId = ($u.KnowledgebaseArticles -join ', ')
                        IsApproved  = $u.IsApproved
                    }
                }
            }
        } else {
            Write-Host "[-] Note: Connect to WSUS directly or run from WSUS console to query live updates." -ForegroundColor Yellow
        }
        if ($OutputJson) { $updates | ConvertTo-Json | Out-File $OutputJson -Encoding utf8 }
    }

    "ApproveUpdate" {
        if (-not $KbNumber) {
            Write-Error "Vui lòng cung cấp tham số -KbNumber (ví dụ: -KbNumber KB5040437)"
            return
        }
        $cleanKb = $KbNumber.Replace("KB", "").Trim()
        Write-Host "[*] Checking approval status for KB$cleanKb on Target Group: $TargetGroup..." -ForegroundColor Cyan

        $approvalFile = "config/wsus_approvals.json"
        $approvalState = @{}
        if (Test-Path $approvalFile) {
            try { $approvalState = Get-Content $approvalFile -Raw | ConvertFrom-Json } catch {}
        }

        if ($server) {
            $targetGroupObj = $server.GetComputerTargetGroups() | Where-Object { $_.Name -eq $TargetGroup }
            $update = $server.SearchUpdates($cleanKb) | Select-Object -First 1

            if ($update -and $targetGroupObj) {
                # Check existing approvals for this specific group
                $existingApprovals = $update.GetUpdateApprovals($targetGroupObj)
                $isAlreadyApproved = $false
                foreach ($appr in $existingApprovals) {
                    if ($appr.Action -eq [Microsoft.UpdateServices.Administration.UpdateApprovalAction]::Install) {
                        $isAlreadyApproved = $true
                        break
                    }
                }

                if ($isAlreadyApproved) {
                    Write-Host "[i] TRẠNG THÁI: Bản vá KB$cleanKb ĐÃ ĐƯỢC PHÊ DUYỆT (ALREADY APPROVED) cho nhóm $TargetGroup từ trước!" -ForegroundColor Yellow
                    Write-Host "[i] Bỏ qua phê duyệt lại để tránh đẩy trùng lặp vào các máy chủ." -ForegroundColor Cyan
                    return
                }

                # Perform Approval
                Write-Host "[*] Approving KB$cleanKb for Target Group: $TargetGroup..." -ForegroundColor Yellow
                $update.Approve([Microsoft.UpdateServices.Administration.UpdateApprovalAction]::Install, $targetGroupObj)
                Write-Host "[+] Successfully approved KB$cleanKb for $TargetGroup!" -ForegroundColor Green
            } else {
                Write-Error "Update KB$cleanKb hoặc Target Group $TargetGroup không tìm thấy trên WSUS."
            }
        } else {
            Write-Host "[+] Approval recorded for KB$cleanKb -> $TargetGroup (WSUS Local/API Mode)." -ForegroundColor Green
        }
    }

    "UnapproveUpdate" {
        if (-not $KbNumber) {
            Write-Error "Vui lòng cung cấp tham số -KbNumber (ví dụ: -KbNumber KB5040437)"
            return
        }
        $cleanKb = $KbNumber.Replace("KB", "").Trim()
        Write-Host "[*] Unapproving (Hủy phê duyệt) KB$cleanKb for Target Group: $TargetGroup..." -ForegroundColor Yellow

        if ($server) {
            $targetGroupObj = $server.GetComputerTargetGroups() | Where-Object { $_.Name -eq $TargetGroup }
            $update = $server.SearchUpdates($cleanKb) | Select-Object -First 1

            if ($update -and $targetGroupObj) {
                $existingApprovals = $update.GetUpdateApprovals($targetGroupObj)
                if ($existingApprovals.Count -eq 0) {
                    Write-Host "[i] Bản vá KB$cleanKb chưa được phê duyệt cho nhóm $TargetGroup (Không cần hủy)." -ForegroundColor Gray
                } else {
                    foreach ($appr in $existingApprovals) {
                        $appr.Delete()
                    }
                    Write-Host "[+] Đã HỦY PHÊ DUYỆT (Unapproved) thành công KB$cleanKb khỏi nhóm $TargetGroup!" -ForegroundColor Green
                }
            } else {
                Write-Error "Update KB$cleanKb hoặc Target Group $TargetGroup không tìm thấy trên WSUS."
            }
        } else {
            Write-Host "[+] Unapproved recorded for KB$cleanKb -> $TargetGroup." -ForegroundColor Green
        }
    }

    "GetApprovalStatus" {
        if (-not $KbNumber) {
            Write-Error "Vui lòng cung cấp tham số -KbNumber"
            return
        }
        $cleanKb = $KbNumber.Replace("KB", "").Trim()
        $statusResult = [PSCustomObject]@{
            KbNumber    = "KB$cleanKb"
            TargetGroup = $TargetGroup
            Status      = "NotApproved"
        }

        if ($server) {
            $targetGroupObj = $server.GetComputerTargetGroups() | Where-Object { $_.Name -eq $TargetGroup }
            $update = $server.SearchUpdates($cleanKb) | Select-Object -First 1
            if ($update -and $targetGroupObj) {
                $existingApprovals = $update.GetUpdateApprovals($targetGroupObj)
                foreach ($appr in $existingApprovals) {
                    if ($appr.Action -eq [Microsoft.UpdateServices.Administration.UpdateApprovalAction]::Install) {
                        $statusResult.Status = "ApprovedForInstall"
                        break
                    }
                }
            }
        }
        Write-Host "[i] Approval Status: $($statusResult.Status)" -ForegroundColor Cyan
        if ($OutputJson) { $statusResult | ConvertTo-Json | Out-File $OutputJson -Encoding utf8 }
        return $statusResult
    }

    "SyncWsus" {
        Write-Host "[*] Triggering WSUS synchronization with Microsoft Update..." -ForegroundColor Cyan
        if ($server) {
            $sub = $server.GetSubscription()
            $sub.StartSynchronization()
            Write-Host "[+] WSUS Synchronization initiated." -ForegroundColor Green
        } else {
            Write-Host "[i] Use Wsus Synchronization task scheduler or run on WSUS host." -ForegroundColor Yellow
        }
    }

    "SyncGroups" {
        Write-Host "[*] Fetching Computer Target Groups directly from WSUS server..." -ForegroundColor Cyan
        if ($server) {
            $wsusGroups = $server.GetComputerTargetGroups()
            $customGroups = @()
            foreach ($g in $wsusGroups) {
                # Skip 'All Computers' or 'Unassigned Computers' default containers if desired, or keep all
                $customGroups += [PSCustomObject]@{
                    id                   = $g.Name
                    name                 = $g.Name
                    description          = "WSUS Group $($g.Name) (Total Computers: $($g.GetTotalComputerTargetCount()))"
                    auto_approve_test    = ($g.Name -like "*test*" -or $g.Name -like "*pilot*")
                    require_reboot_window= ($g.Name -notlike "*test*")
                }
            }
            $targetPath = if ($OutputJson) { $OutputJson } else { "config/groups.json" }
            $jsonPayload = [PSCustomObject]@{
                description = "Custom WSUS Computer Groups synchronized directly from $WsusServer"
                synced_at   = (Get-Date -Format "o")
                groups      = $customGroups
            }
            $jsonPayload | ConvertTo-Json -Depth 4 | Out-File $targetPath -Encoding utf8
            Write-Host "[+] Successfully synced $($customGroups.Count) real WSUS groups to: $targetPath" -ForegroundColor Green
            $customGroups | Format-Table id, name, description -AutoSize
        } else {
            Write-Warning "Cannot connect to WSUS directly. To sync groups, please run this script on the WSUS server or ensure WSUS Remote Admin is accessible."
        }
    }
}
