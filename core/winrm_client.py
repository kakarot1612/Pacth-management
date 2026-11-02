"""
WinRM Client: Remote administration and execution engine for client nodes
using Active Directory / Local Service Account (WINRM_USER, WINRM_PASSWORD).
Executes remote verification, reboot key inspection, and patch installation.
"""
import json
import socket
import subprocess
from typing import Dict, Any, List, Optional
from core.config import BASE_DIR, Settings, logger


class WinRMClient:
    """Manages remote Windows Server execution via WinRM / PowerShell Remoting"""

    @classmethod
    def test_node_connectivity(cls, host: str, timeout: float = 2.5) -> Dict[str, Any]:
        """Test whether WinRM port 5985 is open on the target node"""
        s = socket.socket()
        s.settimeout(timeout)
        is_open = False
        err = ""
        try:
            s.connect((host, 5985))
            is_open = True
        except Exception as e:
            err = str(e)
        finally:
            s.close()
        return {
            "host": host,
            "port": 5985,
            "port_open": is_open,
            "error": err
        }

    @classmethod
    def execute_remote_powershell(
        cls,
        host: str,
        script_block: str,
        timeout: int = 180
    ) -> Dict[str, Any]:
        """
        Executes a PowerShell script block on the remote host via Invoke-Command.
        Passes WINRM_USER and WINRM_PASSWORD explicitly.
        """
        user = Settings.WINRM_USER
        password = Settings.WINRM_PASSWORD
        domain = Settings.AD_DOMAIN

        if not user or not password:
            return {
                "success": False,
                "error": "Chưa cấu hình WINRM_USER hoặc WINRM_PASSWORD trong .env.",
                "host": host
            }

        full_user = f"{domain}\\{user}" if domain and "\\" not in user else user

        # PowerShell wrapper that runs Invoke-Command with PSCredential
        ps_wrapper = f"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$sec = ConvertTo-SecureString @'
{password}
'@ -AsPlainText -Force

$cred = New-Object System.Management.Automation.PSCredential ('{full_user}', $sec)
$sessionOpt = New-PSSessionOption -SkipCACheck -SkipCNCheck

try {{
    $script = {{
{script_block}
    }}
    $result = Invoke-Command -ComputerName '{host}' -Credential $cred -SessionOption $sessionOpt -ScriptBlock $script -ErrorAction Stop
    @{{
        success = $true
        host    = '{host}'
        data    = $result
    }} | ConvertTo-Json -Depth 5 -Compress
}} catch {{
    @{{
        success = $false
        host    = '{host}'
        error   = $_.Exception.Message
        details = $_.ToString()
    }} | ConvertTo-Json -Depth 5 -Compress
}}
"""
        try:
            res = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_wrapper],
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
                cwd=BASE_DIR
            )
            stdout = res.stdout.lstrip("\ufeff").strip()
            if stdout:
                try:
                    return json.loads(stdout)
                except Exception:
                    return {"success": res.returncode == 0, "output": stdout, "raw_error": res.stderr}
            return {
                "success": False,
                "error": res.stderr.strip() or "Remote execution produced no output.",
                "host": host
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Lệnh WinRM tới {host} quá thời gian chờ ({timeout}s).", "host": host}
        except Exception as e:
            return {"success": False, "error": f"Lỗi WinRM dispatcher: {str(e)}", "host": host}

    @classmethod
    def check_remote_pending_reboot(cls, host: str) -> Dict[str, Any]:
        """
        Inspects remote registry keys directly on the client machine to confirm
        whether Windows Update or Component-Based Servicing has a pending reboot.
        """
        script = r"""
        $reasons = @()
        $rebootPending = $false

        # 1. Component Based Servicing (CBS)
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
            $rebootPending = $true
            $reasons += 'Component Based Servicing (CBS) RebootPending flag detected'
        }

        # 2. Windows Update Auto Update
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
            $rebootPending = $true
            $reasons += 'Windows Update RebootRequired flag detected'
        }

        # 3. Pending File Rename Operations
        $renameOps = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if ($renameOps) {
            $rebootPending = $true
            $reasons += 'Pending File Rename Operations in Session Manager'
        }

        # Current build from registry
        $currentBuild = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuild' -ErrorAction SilentlyContinue).CurrentBuild
        $ubr = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR' -ErrorAction SilentlyContinue).UBR
        $fullBuild = if ($ubr) { "$currentBuild.$ubr" } else { "$currentBuild" }

        [PSCustomObject]@{
            RebootPending = $rebootPending
            Reasons       = ($reasons -join '; ')
            CurrentBuild  = $fullBuild
            ComputerName  = $env:COMPUTERNAME
        }
        """
        raw_res = cls.execute_remote_powershell(host, script, timeout=30)
        if raw_res.get("success"):
            data = raw_res.get("data", {})
            if isinstance(data, dict):
                return {
                    "success": True,
                    "host": host,
                    "reboot_pending": bool(data.get("RebootPending", False)),
                    "reasons": data.get("Reasons", ""),
                    "remote_build": data.get("CurrentBuild", ""),
                    "verified_via": "WinRM Live Registry Audit"
                }
        return {
            "success": False,
            "host": host,
            "error": raw_res.get("error", "Cannot query remote registry via WinRM."),
            "verified_via": "Failed"
        }

    @classmethod
    def trigger_remote_install(cls, host: str, kb_number: str = "") -> Dict[str, Any]:
        """
        Dispatches Install-PendingUpdates logic directly to the target machine via WinRM,
        initiating search, download, and installation through the Windows Update Agent.
        """
        # Embed the local installation logic to run inside the remote PSSession
        kb_filter = f"$targetKb = '{kb_number}'" if kb_number else "$targetKb = ''"
        script = f"""
        {kb_filter}
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searcher.Online = $false
        $searchResult = $searcher.Search("IsInstalled=0 and Type='Software'")
        
        $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        $matched = @()
        
        foreach ($u in $searchResult.Updates) {{
            $hasKb = $false
            if ($targetKb) {{
                $article = $targetKb -replace 'KB',''
                if ($u.KBArticleIDs -contains $article -or $u.Title -match $targetKb) {{
                    $hasKb = $true
                }}
            }} else {{
                $hasKb = $true
            }}
            if ($hasKb) {{
                if (-not $u.IsDownloaded) {{
                    $dlColl = New-Object -ComObject Microsoft.Update.UpdateColl
                    $dlColl.Add($u) | Out-Null
                    $downloader = $session.CreateUpdateDownloader()
                    $downloader.Updates = $dlColl
                    $downloader.Download() | Out-Null
                }}
                $toInstall.Add($u) | Out-Null
                $matched += $u.Title
            }}
        }}

        if ($toInstall.Count -eq 0) {{
            [PSCustomObject]@{{
                Status        = 'NO_MATCHING_UPDATES'
                Message       = if ($targetKb) {{ "Khong tim thay ban va $targetKb san sang tren may." }} else {{ 'Khong co ban va cho cai dat.' }}
                InstalledCount = 0
                RebootRequired = $false
            }}
        }} else {{
            $installer = $session.CreateUpdateInstaller()
            $installer.Updates = $toInstall
            $installResult = $installer.Install()
            [PSCustomObject]@{{
                Status         = if ($installResult.ResultCode -eq 2) {{ 'SUCCESS' }} else {{ 'INSTALL_RETURN_CODE_' + $installResult.ResultCode }}
                InstalledCount = $toInstall.Count
                RebootRequired = [bool]$installResult.RebootRequired
                Updates        = ($matched -join '; ')
                ResultCode     = $installResult.ResultCode
            }}
        }}
        """
        return cls.execute_remote_powershell(host, script, timeout=300)

