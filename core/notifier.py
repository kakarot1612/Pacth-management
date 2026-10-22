import requests
import json
from typing import Dict, Any, List
from core.config import Settings, logger

class AlertNotifier:
    """Dispatches patch alerts & emergency notifications via Webhooks (Teams/Slack/Generic)"""

    @classmethod
    def send_emergency_alert(cls, cve_id: str, host_name: str, priority: str, details: Dict[str, Any]) -> bool:
        """Sends immediate alert when a P1 / Emergency CVE is detected"""
        if not Settings.ENABLE_ALERTS or not Settings.ALERT_WEBHOOK_URL:
            logger.info(f"Alert notification skipped (Alerts disabled or no Webhook URL configured): {cve_id} on {host_name}")
            return False

        webhook_url = Settings.ALERT_WEBHOOK_URL
        webhook_type = Settings.ALERT_WEBHOOK_TYPE.lower()

        title = f"🚨 [EMERGENCY PATCH ALERT] {priority} Detected on {host_name}"
        kb_text = details.get("kb") or "Pending KB lookup"
        summary_text = (
            f"**CVE:** {cve_id}\n"
            f"**Server:** {host_name}\n"
            f"**Priority:** {priority} (SLA: ≤ {Settings.SLA_P1_CRITICAL_HOURS}h)\n"
            f"**Remediation KB:** {kb_text}\n"
            f"**Title:** {details.get('title', 'N/A')}\n"
            f"**Golden Rule Notice:** Verify backup before emergency patching."
        )

        try:
            if "teams" in webhook_type:
                payload = {
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "themeColor": "D9383A",
                    "summary": title,
                    "sections": [{
                        "activityTitle": title,
                        "activitySubtitle": f"Patch Management Emergency Notification",
                        "facts": [
                            {"name": "Server", "value": host_name},
                            {"name": "CVE", "value": cve_id},
                            {"name": "Priority", "value": priority},
                            {"name": "Required KB", "value": kb_text},
                            {"name": "SLA", "value": f"<= {Settings.SLA_P1_CRITICAL_HOURS} hours"}
                        ],
                        "markdown": True
                    }]
                }
            elif "slack" in webhook_type:
                payload = {
                    "text": title,
                    "attachments": [{
                        "color": "#D9383A",
                        "text": summary_text
                    }]
                }
            else:
                payload = {
                    "event": "EMERGENCY_PATCH_ALERT",
                    "cve": cve_id,
                    "server": host_name,
                    "priority": priority,
                    "details": details
                }

            resp = requests.post(webhook_url, json=payload, timeout=10)
            if resp.status_code in (200, 204):
                logger.info(f"Successfully sent emergency alert for {cve_id} on {host_name}")
                return True
            else:
                logger.error(f"Failed to send webhook alert: {resp.status_code} {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Error sending webhook notification: {e}")
            return False
