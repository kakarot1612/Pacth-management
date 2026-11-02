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
    Add-Type -AssemblyName Microsoft.UpdateServices.Administration -ErrorAction Stop
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

# Strategy 1: Remote Execution via WinRM / PSSession if explicit credentials supplied
if ($Username -and $Password) {
    try {
        $sec = ConvertTo-SecureString $Password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($Username, $sec)
        
        $remoteScript = {
            param($ssl, $p, $kb, $groupName, $act)
            Add-Type -AssemblyName Microsoft.UpdateServices.Administration
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
        $lastError = "Remote WSUS WinRM execution failed with account '$Username': $($_.Exception.Message)"
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
