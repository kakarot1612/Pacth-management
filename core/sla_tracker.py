from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple
from core.config import Settings, logger

class SlaTracker:
    """
    Enforces SLA rules as defined in PLAN.md:
    - P1 (Critical): <= 72 hours
    - P2 (High): <= 14 days
    - P3 (Medium): <= 30 days
    - P4 (Low): <= 90 days
    """

    @classmethod
    def determine_priority(cls, vuln: Dict[str, Any], host_role: str = "") -> str:
        """
        Determines SLA Priority (P1/P2/P3/P4) based on CVSS, severity, and host criticality.
        """
        severity = str(vuln.get("severity", "Medium")).upper()
        cvss = float(vuln.get("cvss", 0.0) or 0.0)
        cisa_kev = vuln.get("cisa_kev", False)
        title = str(vuln.get("title", "")).lower()

        # Critical triggers: CVSS >= 9.0, or CISA KEV / Active exploit, or Critical severity on DC/VPN/Gateway
        is_critical_host = any(k in host_role.lower() for k in ["dc", "domain", "vpn", "gateway", "firewall"])

        if severity == "CRITICAL" or cvss >= 9.0 or cisa_kev or (severity == "HIGH" and is_critical_host):
            return "P1"
        elif severity == "HIGH" or cvss >= 7.0 or "privilege escalation" in title:
            return "P2"
        elif severity == "MEDIUM" or cvss >= 4.0:
            return "P3"
        else:
            return "P4"

    @classmethod
    def calculate_sla_status(cls, priority: str, detected_or_published_time: Any) -> Dict[str, Any]:
        """
        Calculates SLA compliance, deadline, and remaining/overdue duration.
        """
        now = datetime.now(timezone.utc)

        # Parse timestamp
        start_time = None
        if isinstance(detected_or_published_time, (int, float)):
            start_time = datetime.fromtimestamp(detected_or_published_time, tz=timezone.utc)
        elif isinstance(detected_or_published_time, str) and detected_or_published_time:
            for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"):
                try:
                    start_time = datetime.strptime(detected_or_published_time.replace("Z", "+0000"), fmt)
                    if start_time.tzinfo is None:
                        start_time = start_time.replace(tzinfo=timezone.utc)
                    break
                except Exception:
                    pass

        if not start_time:
            # Fallback to current time if no date available
            start_time = now

        # SLA Duration
        if priority == "P1":
            limit_delta = timedelta(hours=Settings.SLA_P1_CRITICAL_HOURS)
            limit_label = f"{Settings.SLA_P1_CRITICAL_HOURS} hours"
        elif priority == "P2":
            limit_delta = timedelta(days=Settings.SLA_P2_HIGH_DAYS)
            limit_label = f"{Settings.SLA_P2_HIGH_DAYS} days"
        elif priority == "P3":
            limit_delta = timedelta(days=Settings.SLA_P3_MEDIUM_DAYS)
            limit_label = f"{Settings.SLA_P3_MEDIUM_DAYS} days"
        else:
            limit_delta = timedelta(days=Settings.SLA_P4_LOW_DAYS)
            limit_label = f"{Settings.SLA_P4_LOW_DAYS} days"

        deadline = start_time + limit_delta
        age = now - start_time
        remaining = deadline - now

        is_breached = now > deadline
        is_warning = (not is_breached) and (remaining.total_seconds() <= 24 * 3600)  # <= 24 hours left

        return {
            "priority": priority,
            "sla_limit": limit_label,
            "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "deadline": deadline.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "age_hours": round(age.total_seconds() / 3600, 1),
            "remaining_hours": round(remaining.total_seconds() / 3600, 1) if not is_breached else 0,
            "overdue_hours": round((now - deadline).total_seconds() / 3600, 1) if is_breached else 0,
            "is_breached": is_breached,
            "is_warning": is_warning,
            "status_label": "BREACHED" if is_breached else ("WARNING" if is_warning else "WITHIN_SLA")
        }
