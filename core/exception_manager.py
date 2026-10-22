import json
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from core.config import Settings, logger

class ExceptionManager:
    """
    Manages Vulnerability Exceptions according to docs/vulnerability-management.md:
    1. Ticket 'Vulnerability Exception'
    2. CVE, Server, Reason, Compensating Control
    3. Owner, Approved By, Expiration Date
    """

    def __init__(self, filepath: Optional[str] = None):
        self.filepath = filepath or Settings.EXCEPTIONS_FILE
        self.exceptions: List[Dict[str, Any]] = self._load()

    def _load(self) -> List[Dict[str, Any]]:
        if self.filepath.exists():
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("exceptions", [])
            except Exception as e:
                logger.error(f"Error loading exceptions file: {e}")
        return []

    def save(self):
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump({"version": "1.0", "exceptions": self.exceptions}, f, indent=2, ensure_ascii=False)
            logger.info(f"Saved {len(self.exceptions)} exceptions to {self.filepath}")
        except Exception as e:
            logger.error(f"Failed to save exceptions: {e}")

    def is_exempt(self, cve: str, server_name: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Check if CVE on server has an active, non-expired exception"""
        now = datetime.now()
        for item in self.exceptions:
            if item.get("cve", "").upper() == cve.upper() and (
                item.get("server", "").upper() == server_name.upper() or item.get("server") == "*"
            ):
                exp_str = item.get("expiration_date", "")
                try:
                    exp_date = datetime.strptime(exp_str, "%Y-%m-%d")
                    if exp_date >= now:
                        return True, item
                    else:
                        logger.warning(f"Exception for {cve} on {server_name} expired on {exp_str}")
                except Exception:
                    # If date parsing fails, consider active if explicitly approved
                    if item.get("status") == "APPROVED":
                        return True, item
        return False, None

    def add_exception(
        self,
        cve: str,
        server: str,
        reason: str,
        compensating_control: str,
        owner: str,
        approved_by: str,
        expiration_date: str
    ):
        """Register a new formal exception"""
        new_entry = {
            "cve": cve.upper().strip(),
            "server": server.strip(),
            "reason": reason.strip(),
            "compensating_control": compensating_control.strip(),
            "owner": owner.strip(),
            "approved_by": approved_by.strip(),
            "approval_date": datetime.now().strftime("%Y-%m-%d"),
            "expiration_date": expiration_date.strip(),
            "status": "APPROVED"
        }
        self.exceptions.append(new_entry)
        self.save()
        return new_entry
