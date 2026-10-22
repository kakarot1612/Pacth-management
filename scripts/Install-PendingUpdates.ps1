<#
.SYNOPSIS
    Installs pending updates that have been pushed/downloaded from WSUS to the local server.
.DESCRIPTION
    Complies with Requirement:
    "Server đã được wsus đẩy hotfix về rồi nhưng chưa install cần thao tác install"
    Uses Windows Update Agent (Microsoft.Update.Session COM) to search, download, and install pending updates.
.PARAMETER KbNumber
    Optional KB Number to install (e.g., KB5040430). If omitted, installs all pending approved updates.
.PARAMETER DownloadOnly
    Only download, do not install yet.
.PARAMETER OutputJson
    Path to save execution result JSON.
.EXAMPLE
    .\Install-PendingUpdates.ps1 -KbNumber KB5040430
    .\Install-PendingUpdates.ps1
#>
[CmdletBinding()]
param (
    [string]$KbNumber = "",
    [switch]$DownloadOnly,
    [string]$OutputJson = ""
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       WINDOWS NODE - INSTALL PENDING WSUS UPDATES       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

try {
    Write-Host "[*] Initializing Windows Update Session..." -ForegroundColor Cyan
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $updateSearcher.Online = $false # Query WSUS / local cache first

    Write-Host "[*] Searching for pending uninstalled updates from WSUS..." -ForegroundColor Cyan
    $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")

    $pendingCount = $searchResult.Updates.Count
    Write-Host "[+] Found $pendingCount pending update(s) available on this machine." -ForegroundColor $(if ($pendingCount -gt 0) { "Yellow" } else { "Green" })

    if ($pendingCount -eq 0) {
        Write-Host "[i] No pending updates ready to install on $(hostname)." -ForegroundColor Green
        $resObj = [PSCustomObject]@{
            ComputerName   = $env:COMPUTERNAME
            PendingCount   = 0
            InstalledCount = 0
            RebootRequired = $false
            Status         = "NO_UPDATES_PENDING"
        }
        if ($OutputJson) { $resObj | ConvertTo-Json | Out-File $OutputJson -Encoding utf8 }
        return $resObj
    }

    $updatesToProcess = New-Object -ComObject Microsoft.Update.UpdateColl
    for ($i = 0; $i -lt $searchResult.Updates.Count; $i++) {
        $u = $searchResult.Updates.Item($i)
        $matchesKb = $true
        if ($KbNumber) {
            $cleanKb = $KbNumber.Replace("KB", "").Trim()
            $matchesKb = ($u.Title -like "*$cleanKb*" -or ($u.KBArticleIDs -contains $cleanKb))
        }

        if ($matchesKb) {
            Write-Host "    -> Pending: $($u.Title) (Downloaded: $($u.IsDownloaded))" -ForegroundColor Gray
            $updatesToProcess.Add($u) | Out-Null
        }
    }

    if ($updatesToProcess.Count -eq 0) {
        Write-Host "[!] Specific KB $KbNumber was not found in pending uninstalled updates." -ForegroundColor Yellow
        return
    }

    # 1. Download if not already downloaded
    $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
    for ($i = 0; $i -lt $updatesToProcess.Count; $i++) {
        $u = $updatesToProcess.Item($i)
        if (-not $u.IsDownloaded) {
            $updatesToDownload.Add($u) | Out-Null
        }
    }

    if ($updatesToDownload.Count -gt 0) {
        Write-Host "[*] Downloading $($updatesToDownload.Count) update(s) from WSUS..." -ForegroundColor Cyan
        $downloader = $updateSession.CreateUpdateDownloader()
        $downloader.Updates = $updatesToDownload
        $downloadResult = $downloader.Download()
        Write-Host "[+] Download completed with ResultCode: $($downloadResult.ResultCode)" -ForegroundColor Green
    } else {
        Write-Host "[+] All target updates are already downloaded and cached locally." -ForegroundColor Green
    }

    if ($DownloadOnly) {
        Write-Host "[i] Download completed. Skipping install as -DownloadOnly was specified." -ForegroundColor Yellow
        return
    }

    # 2. Install
    Write-Host "[*] Triggering installation of $($updatesToProcess.Count) update(s)..." -ForegroundColor Yellow
    $installer = $updateSession.CreateUpdateInstaller()
    $installer.Updates = $updatesToProcess
    $installer.ForceQuiet = $true

    $installResult = $installer.Install()
    Write-Host "[+] Installation finished!" -ForegroundColor Green
    Write-Host "    - ResultCode    : $($installResult.ResultCode)" -ForegroundColor Cyan
    Write-Host "    - RebootRequired: $($installResult.RebootRequired)" -ForegroundColor $(if ($installResult.RebootRequired) { "Yellow" } else { "Green" })

    $resultSummary = [PSCustomObject]@{
        ComputerName   = $env:COMPUTERNAME
        TargetKb       = $KbNumber
        ProcessedCount = $updatesToProcess.Count
        ResultCode     = $installResult.ResultCode
        RebootRequired = $installResult.RebootRequired
        Timestamp      = (Get-Date -Format "o")
    }

    if ($OutputJson) {
        $resultSummary | ConvertTo-Json | Out-File $OutputJson -Encoding utf8
    }

    return $resultSummary

} catch {
    Write-Error "Error during Windows Update install: $($_.Exception.Message)"
}
