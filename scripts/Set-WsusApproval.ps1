[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$WsusServer,
    [int]$Port = 8530,
    [switch]$UseSsl,
    [Parameter(Mandatory=$true)][ValidatePattern('^KB\d{6,8}$')][string]$KbNumber,
    [Parameter(Mandatory=$true)][string]$TargetGroup,
    [ValidateSet('Install', 'NotApproved')][string]$Action = 'Install',
    [string]$Username = '',
    [string]$Password = ''
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Invoke-WsusApprovalCore {
    param($server, $ssl, $p, $kb, $groupName, $act)
    try {
        Add-Type -AssemblyName Microsoft.UpdateServices.Administration -ErrorAction Stop
    } catch {
        $gacDll = "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Microsoft.UpdateServices.Administration\v4.0_4.0.0.0__31bf3856ad364e35\Microsoft.UpdateServices.Administration.dll"
        if (Test-Path $gacDll) {
            Add-Type -Path $gacDll -ErrorAction Stop
        } else {
            throw "Khong tim thay assembly Microsoft.UpdateServices.Administration tren may."
        }
    }
    $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($server, [bool]$ssl, $p)
    $group = @($wsus.GetComputerTargetGroups() | Where-Object { $_.Name -eq $groupName })
    if ($group.Count -ne 1) { throw "Target group '$groupName' not found or ambiguous on WSUS." }
    $article = $kb.Substring(2)
    $updates = @($wsus.SearchUpdates($article) | Where-Object {
        $_.KnowledgebaseArticles -contains $article -and -not $_.IsDeclined
    })
    if ($updates.Count -eq 0) { throw "No matching update found in WSUS catalog for $kb." }
    $approvalAction = [Microsoft.UpdateServices.Administration.UpdateApprovalAction]::$act
    $approvedCount = 0
    foreach ($update in $updates) {
        $approval = $update.Approve($approvalAction, $group[0])
        if ($approval.Action -eq $approvalAction) {
            $approvedCount++
        }
    }
    return @{ success = $true; count = $approvedCount; kb = $kb; group = $groupName; action = $act }
}

$executionResult = $null
$lastError = ''

# Strategy 1: Remote Execution via SMB + WMI (Primary for Workgroup / Non-domain WSUS)
if ($Username -and $Password) {
    try {
        net.exe use "\\$WsusServer\C$" /user:$Username $Password 2>&1 | Out-Null
        $rnd = [guid]::NewGuid().ToString('N').Substring(0,8)
        $scriptName = "wsus_appr_${KbNumber}_$rnd"
        $remotePsPath = "\\$WsusServer\C$\Windows\Temp\$scriptName.ps1"
        $resultFilePath = "\\$WsusServer\C$\Windows\Temp\$scriptName.json"

        $remoteScriptContent = @"
`$ErrorActionPreference = 'Stop'
try {
    Import-Module UpdateServices -ErrorAction SilentlyContinue
    if (-not ([System.Management.Automation.PSTypeName]'Microsoft.UpdateServices.Administration.AdminProxy').Type) {
        `$gac = 'C:\Windows\Microsoft.NETssembly\GAC_MSIL\Microsoft.UpdateServices.Administration4.0_4.0.0.0__31bf3856ad364e35\Microsoft.UpdateServices.Administration.dll'
        if (Test-Path `$gac) { Add-Type -Path `$gac }
    }
    `$wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer()
    `$group = @(`$wsus.GetComputerTargetGroups() | Where-Object { `$_.Name -eq '$TargetGroup' })
    if (`$group.Count -ne 1) { throw "Target group '$TargetGroup' not found or ambiguous on WSUS." }
    `$article = '$KbNumber'.Substring(2)
    `$allMatches = @(`$wsus.SearchUpdates(`$article) | Where-Object { `$_.KnowledgebaseArticles -contains `$article })
    if (`$allMatches.Count -eq 0) { throw "No matching update found in WSUS catalog for $KbNumber." }
    `$activeUpdates = @(`$allMatches | Where-Object { -not `$_.IsDeclined })
    if (`$activeUpdates.Count -eq 0) {
        throw "Bản vá $KbNumber đã bị từ chối (Declined/Superseded) trên WSUS vì đã có bản vá tích lũy mới hơn thay thế."
    }
    `$approvalAction = [Microsoft.UpdateServices.Administration.UpdateApprovalAction]::$Action
    `$approvedCount = 0
    foreach (`$u in `$activeUpdates) {
        `$a = `$u.Approve(`$approvalAction, `$group[0])
        if (`$a.Action -eq `$approvalAction) { `$approvedCount++ }
    }
    @{ success = `$true; count = `$approvedCount; kb = '$KbNumber'; group = '$TargetGroup'; action = '$Action' } | ConvertTo-Json -Compress | Out-File -FilePath 'C:\Windows\Temp\$scriptName.json' -Encoding utf8
} catch {
    @{ success = `$false; error = `$_.Exception.Message; kb = '$KbNumber'; group = '$TargetGroup' } | ConvertTo-Json -Compress | Out-File -FilePath 'C:\Windows\Temp\$scriptName.json' -Encoding utf8
}
"@

        [System.IO.File]::WriteAllText($remotePsPath, $remoteScriptContent, [System.Text.Encoding]::UTF8)

        $sec = ConvertTo-SecureString $Password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($Username, $sec)
        $cmd = "cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\$scriptName.ps1"

        $proc = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $cmd -ComputerName $WsusServer -Credential $cred -ErrorAction Stop
        if ($proc.ReturnValue -eq 0) {
            for ($i = 0; $i -lt 15; $i++) {
                Start-Sleep -Seconds 1
                if (Test-Path $resultFilePath) { break }
            }
            if (Test-Path $resultFilePath) {
                $rawJson = [System.IO.File]::ReadAllText($resultFilePath, [System.Text.Encoding]::UTF8)
                $resObj = $rawJson | ConvertFrom-Json
                if ($resObj.success) {
                    $executionResult = @{ success = $true; count = $resObj.count; kb = $KbNumber; group = $TargetGroup; action = $Action }
                } else {
                    $lastError = "WSUS: $($resObj.error)"
                }
            } else {
                $lastError = "WMI remote execution timed out waiting for WSUS result."
            }
        } else {
            $lastError = "WMI Win32_Process::Create failed with code: $($proc.ReturnValue)"
        }

        Remove-Item $remotePsPath -Force -ErrorAction SilentlyContinue
        Remove-Item $resultFilePath -Force -ErrorAction SilentlyContinue
        net.exe use "\\$WsusServer\C$" /delete /y 2>&1 | Out-Null
    } catch {
        $lastError = "Remote WSUS WMI execution failed: $($_.Exception.Message)"
        net.exe use "\\$WsusServer\C$" /delete /y 2>&1 | Out-Null
    }
}

# Strategy 2: Remote Execution via WinRM / PSSession fallback
if (-not $executionResult -and $Username -and $Password) {
    try {
        $sec = ConvertTo-SecureString $Password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($Username, $sec)
        
        $remoteScript = {
            param($ssl, $p, $kb, $groupName, $act)
            Import-Module UpdateServices -ErrorAction SilentlyContinue
            if (-not ([System.Management.Automation.PSTypeName]'Microsoft.UpdateServices.Administration.AdminProxy').Type) {
                $gac = 'C:\Windows\Microsoft.NETssembly\GAC_MSIL\Microsoft.UpdateServices.Administration4.0_4.0.0.0__31bf3856ad364e35\Microsoft.UpdateServices.Administration.dll'
                if (Test-Path $gac) { Add-Type -Path $gac }
            }
            $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer("localhost", [bool]$ssl, $p)
            $group = @($wsus.GetComputerTargetGroups() | Where-Object { $_.Name -eq $groupName })
            if ($group.Count -ne 1) { throw "Target group '$groupName' not found or ambiguous on WSUS." }
            $article = $kb.Substring(2)
            $updates = @($wsus.SearchUpdates($article) | Where-Object {
                $_.KnowledgebaseArticles -contains $article -and -not $_.IsDeclined
            })
            if ($updates.Count -eq 0) { throw "No matching update found for $kb." }
            $approvalAction = [Microsoft.UpdateServices.Administration.UpdateApprovalAction]::$act
            $approvedCount = 0
            foreach ($u in $updates) {
                $a = $u.Approve($approvalAction, $group[0])
                if ($a.Action -eq $approvalAction) { $approvedCount++ }
            }
            return @{ success = $true; count = $approvedCount; kb = $kb; group = $groupName; action = $act }
        }

        $sessionOpt = New-PSSessionOption -SkipCACheck -SkipCNCheck
        $res = Invoke-Command -ComputerName $WsusServer -Credential $cred -SessionOption $sessionOpt -ScriptBlock $remoteScript -ArgumentList ([bool]$UseSsl, $Port, $KbNumber, $TargetGroup, $Action) -ErrorAction Stop
        if ($res -and $res.success) {
            $executionResult = $res
        }
    } catch {
        $lastError = if ($lastError) { "$lastError | WinRM: $($_.Exception.Message)" } else { "WinRM: $($_.Exception.Message)" }
    }
}

# Strategy 2: Local RSAT / Direct AdminProxy Fallback (current Windows process token)
if (-not $executionResult) {
    try {
        $executionResult = Invoke-WsusApprovalCore -server $WsusServer -ssl $UseSsl -p $Port -kb $KbNumber -groupName $TargetGroup -act $Action
    } catch {
        $localErr = $_.Exception.Message
        $combinedErr = if ($lastError) { "$lastError | Local AdminProxy failed: $localErr" } else { "Local AdminProxy failed: $localErr" }
        @{
            success = $false
            error   = "WSUS_AUTHENTICATION_OR_CONNECTION_ERROR"
            details = $combinedErr
            server  = $WsusServer
            account = $Username
        } | ConvertTo-Json -Compress
        exit 1
    }
}

if ($executionResult) {
    @{
        success = $true
        count   = $executionResult.count
        kb      = $KbNumber
        group   = $TargetGroup
        action  = $Action
    } | ConvertTo-Json -Compress
    exit 0
}
