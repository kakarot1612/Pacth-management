"""
WSUS Client: Manages Windows Server Update Services (WSUS) approvals
via PowerShell remoting / RSAT, passing explicit infrastructure credentials.
Never assumes success without confirmation from the WSUS backend.
"""
import json
import re
import socket
import subprocess
from typing import Dict, Any
from core.config import BASE_DIR, Settings, logger


def test_wsus_connectivity() -> Dict[str, Any]:
    """Test TCP port 8530/8531 and WinRM port 5985 to the WSUS server"""
    server = Settings.WSUS_SERVER_FQDN
    port = Settings.WSUS_PORT
    wsus_open = False
    winrm_open = False
    error_msg = ""

    # Test WSUS Service Port
    s = socket.socket()
    s.settimeout(2.5)
    try:
        s.connect((server, port))
        wsus_open = True
    except Exception as e:
        error_msg = f"WSUS port {port} unreachable: {e}"
    finally:
        s.close()

    # Test WinRM Management Port (5985)
    s2 = socket.socket()
    s2.settimeout(2.5)
    try:
        s2.connect((server, 5985))
        winrm_open = True
    except Exception:
        pass
    finally:
        s2.close()

    return {
        "server": server,
        "wsus_port": port,
        "wsus_port_open": wsus_open,
        "winrm_port_open": winrm_open,
        "configured_user": Settings.WSUS_USER,
        "has_password": bool(Settings.WSUS_PASSWORD),
        "error": error_msg
    }


def change_approval(kb: str, group: str, approve: bool = True) -> Dict[str, Any]:
    """Approve or unapprove an update on the remote WSUS server using configured credentials"""
    if not isinstance(kb, str) or not re.fullmatch(r"KB\d{6,8}", kb):
        raise ValueError("Mã KB không hợp lệ (ví dụ đúng: KB5122877).")
    if not isinstance(group, str) or not group.strip() or group.startswith("-"):
        raise ValueError("Tên nhóm WSUS không hợp lệ.")

    script_path = str(BASE_DIR / "scripts" / "Set-WsusApproval.ps1")
    command = [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", script_path,
        "-WsusServer", Settings.WSUS_SERVER_FQDN,
        "-Port", str(Settings.WSUS_PORT),
        "-KbNumber", kb,
        "-TargetGroup", group,
        "-Action", "Install" if approve else "NotApproved"
    ]
    if Settings.WSUS_USE_SSL:
        command.append("-UseSsl")

    # Pass explicit credentials if configured
    if Settings.WSUS_USER and Settings.WSUS_PASSWORD:
        command.extend(["-Username", Settings.WSUS_USER, "-Password", Settings.WSUS_PASSWORD])

    logger.info(f"Executing WSUS approval script for {kb} on group '{group}' via {Settings.WSUS_SERVER_FQDN} (User: {Settings.WSUS_USER or 'Current Process'})")
    
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=120,
        encoding="utf-8",
        errors="replace",
        cwd=BASE_DIR
    )

    stdout_text = result.stdout.lstrip("\ufeff").strip()
    stderr_text = result.stderr.strip()

    # Try parsing JSON output from script
    parsed = {}
    if stdout_text:
        try:
            parsed = json.loads(stdout_text)
        except Exception:
            pass

    if result.returncode != 0 or parsed.get("success") is not True:
        err_detail = parsed.get("details") or stderr_text or stdout_text or "Lỗi không xác định từ WSUS."
        logger.error(f"WSUS approval failed for {kb} (Group: {group}): {err_detail}")
        raise RuntimeError(
            f"WSUS chưa thể phê duyệt bản vá {kb}. Chi tiết kỹ thuật: {err_detail}"
        )

    logger.info(f"WSUS confirmed approval for {kb} (Group: {group}). Count: {parsed.get('count', 1)}")
    return parsed
