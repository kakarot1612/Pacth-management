<#
.SYNOPSIS
    Gathers Windows OS Build, Installed Hotfixes, Pending Reboot status, and Wazuh agent state.
.DESCRIPTION
    Complies with docs/wazuh.md & docs/hyperv-patching.md:
    Cross-checks OS build and hotfix state to prevent false positives and verify patch application.
.PARAMETER OutputJson
    If specified, saves the gathered status into a structured JSON file.
.PARAMETER TriggerWazuhScan
    If specified, restarts the Wazuh agent service to trigger immediate Syscollector rescan.
.EXAMPLE
    .\Get-NodePatchStatus.ps1 -OutputJson C:\Temp\node_status.json
#>
[CmdletBinding()]
param (
    [string]$OutputJson = "",
    [switch]$TriggerWazuhScan
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       WINDOWS NODE PATCH & HEALTH STATUS CHECK          " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. OS & Build Information
$compInfo = Get-ComputerInfo -ErrorAction SilentlyContinue
$osName = if ($compInfo.WindowsProductName) { $compInfo.WindowsProductName } else { (Get-CimInstance Win32_OperatingSystem).Caption }
$osBuild = if ($compInfo.OsBuildNumber) { "$($compInfo.OsBuildNumber).$($compInfo.OsHardwareAbstractionLayerBuildNumber)" } else { (Get-CimInstance Win32_OperatingSystem).BuildNumber }

Write-Host "[+] Operating System: $osName" -ForegroundColor Green
Write-Host "[+] OS Build Number : $osBuild" -ForegroundColor Green

# 2. Installed Hotfixes
$hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
$recentHotfixes = $hotfixes | Select-Object -First 15 HotFixID, Description, InstalledOn, InstalledBy

Write-Host "[+] Installed HotFix Count: $($hotfixes.Count)" -ForegroundColor Green
Write-Host "--- Recent 5 Hotfixes ---" -ForegroundColor DarkGray
$recentHotfixes | Select-Object -First 5 | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor DarkGray

# 3. Pending Reboot Check
$rebootPending = $false
$rebootReasons = @()

if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
    $rebootPending = $true
    $rebootReasons += "Component Based Servicing (CBS)"
}
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
    $rebootPending = $true
    $rebootReasons += "Windows Update AutoUpdate"
}
$pfr = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
if ($pfr.PendingFileRenameOperations) {
    $rebootPending = $true
    $rebootReasons += "PendingFileRenameOperations"
}

if ($rebootPending) {
    Write-Host "[!] REBOOT PENDING: YES (Reasons: $($rebootReasons -join ', '))" -ForegroundColor Yellow
} else {
    Write-Host "[+] REBOOT PENDING: NO" -ForegroundColor Green
}

# 4. Wazuh Agent Status
$wazuhService = Get-Service -Name "wazuh-agent" -ErrorAction SilentlyContinue
$wazuhRunning = $false
if ($wazuhService) {
    $wazuhRunning = ($wazuhService.Status -eq "Running")
    Write-Host "[+] Wazuh Agent Service: $($wazuhService.Status)" -ForegroundColor $(if ($wazuhRunning) { "Green" } else { "Yellow" })
} else {
    Write-Host "[-] Wazuh Agent Service not found." -ForegroundColor DarkGray
}

if ($TriggerWazuhScan) {
    if ($wazuhService) {
        Write-Host "[*] Restarting Wazuh Agent to force Syscollector scan..." -ForegroundColor Cyan
        Restart-Service -Name "wazuh-agent" -Force
        Write-Host "[+] Wazuh Agent restarted." -ForegroundColor Green
    }
}

$resultObject = [PSCustomObject]@{
    ComputerName       = $env:COMPUTERNAME
    OSName             = $osName
    OSBuild            = $osBuild
    RebootPending      = $rebootPending
    RebootReasons      = $rebootReasons
    WazuhInstalled     = ($wazuhService -ne $null)
    WazuhStatus        = if ($wazuhService) { $wazuhService.Status.ToString() } else { "NotInstalled" }
    TotalHotfixesCount = $hotfixes.Count
    RecentHotfixes     = ($recentHotfixes | ForEach-Object { @{ HotFixID = $_.HotFixID; InstalledOn = $_.InstalledOn } })
    Timestamp          = (Get-Date -Format "o")
}

if ($OutputJson) {
    $resultObject | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutputJson -Encoding utf8
    Write-Host "[+] Node patch status exported to: $OutputJson" -ForegroundColor Cyan
}

return $resultObject
