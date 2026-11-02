import os
import json
import logging
from pathlib import Path
from dotenv import load_dotenv

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"
CONFIG_DIR = BASE_DIR / "config"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"

# Ensure output directories exist
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Load .env if present
if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH)

# Configure logging
LOG_FILE = LOGS_DIR / "patch_system.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PatchManager")

class Settings:
    """Central configuration loader for Patch Management System"""
    # Wazuh API (Port 55000 Manager REST API)
    WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://127.0.0.1:55000").rstrip("/")
    WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh")
    WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "")
    WAZUH_VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

    # Wazuh Indexer API (Port 9200 OpenSearch Backend for Vulnerability State Indices in 4.8+/4.14+)
    WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "").rstrip("/")
    WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "")
    WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "")
    WAZUH_VULNS_FILE = Path(os.getenv("WAZUH_VULNS_FILE", str(CONFIG_DIR / "wazuh_vulnerabilities.csv")))

    # WSUS
    WSUS_SERVER_FQDN = os.getenv("WSUS_SERVER_FQDN", "localhost")
    WSUS_PORT = int(os.getenv("WSUS_PORT", "8530"))
    WSUS_USE_SSL = os.getenv("WSUS_USE_SSL", "false").lower() in ("true", "1", "yes")
    WSUS_USER = os.getenv("WSUS_USER", "")
    WSUS_PASSWORD = os.getenv("WSUS_PASSWORD", "")

    # WinRM / AD
    AD_DOMAIN = os.getenv("AD_DOMAIN", "CORP.LOCAL")
    WINRM_USER = os.getenv("WINRM_USER", "")
    WINRM_PASSWORD = os.getenv("WINRM_PASSWORD", "")

    # MSRC API
    MSRC_API_KEY = os.getenv("MSRC_API_KEY", "")

    # OpenRouter AI Advisor (DeepSeek / Any Model)
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
    OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-v4.1-flash:batch")
    OPENROUTER_API_URL = os.getenv("OPENROUTER_API_URL", "https://openrouter.ai/api/v1/chat/completions")
    OPENROUTER_SITE_URL = os.getenv("OPENROUTER_SITE_URL", "http://localhost:8080")
    OPENROUTER_APP_NAME = os.getenv("OPENROUTER_APP_NAME", "Best Pacific Patch Management")

    # Provider is explicit; never silently send telemetry to another vendor.
    AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini").lower()
    WEB_BIND_HOST = os.getenv("WEB_BIND_HOST", "0.0.0.0")
    AUTH_ENABLED = os.getenv("AUTH_ENABLED", "false").lower() in ("true", "1", "yes")
    WAZUH_DASHBOARD_URL = os.getenv("WAZUH_DASHBOARD_URL", "https://10.0.55.249:443").rstrip("/")
    DATA_MAX_AGE_MINUTES = int(os.getenv("DATA_MAX_AGE_MINUTES", "60"))

    # Google Gemini AI Advisor (Alternative)
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")

    # SLA Thresholds (Hours / Days)
    SLA_P1_CRITICAL_HOURS = int(os.getenv("SLA_P1_CRITICAL_HOURS", "72"))
    SLA_P2_HIGH_DAYS = int(os.getenv("SLA_P2_HIGH_DAYS", "14"))
    SLA_P3_MEDIUM_DAYS = int(os.getenv("SLA_P3_MEDIUM_DAYS", "30"))
    SLA_P4_LOW_DAYS = int(os.getenv("SLA_P4_LOW_DAYS", "90"))

    # Compliance targets
    TARGET_COMPLIANCE_RATE = float(os.getenv("TARGET_COMPLIANCE_RATE", "95.0"))
    TARGET_CRITICAL_COMPLIANCE_RATE = float(os.getenv("TARGET_CRITICAL_COMPLIANCE_RATE", "98.0"))
    MAX_FAILED_PATCH_RATE = float(os.getenv("MAX_FAILED_PATCH_RATE", "2.0"))

    # Webhook & Alerts
    ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "")
    ALERT_WEBHOOK_TYPE = os.getenv("ALERT_WEBHOOK_TYPE", "teams").lower()
    ENABLE_ALERTS = os.getenv("ENABLE_ALERTS", "false").lower() in ("true", "1", "yes")

    # Threat Intelligence & CVE MCP Server (mukul975/cve-mcp-server on 10.0.55.240)
    CVE_MCP_URL = os.getenv("CVE_MCP_URL", "http://10.0.55.240:8001/mcp").rstrip("/")
    CVE_MCP_HOST = os.getenv("CVE_MCP_HOST", "sec-mcp.bestpacific.vn")
    CVE_MCP_ENABLED = os.getenv("CVE_MCP_ENABLED", "true").lower() in ("true", "1", "yes")
    CVE_MCP_TIMEOUT = int(os.getenv("CVE_MCP_TIMEOUT", "10"))

    # Files
    EXCEPTIONS_FILE = Path(os.getenv("EXCEPTIONS_FILE", str(CONFIG_DIR / "exceptions.json")))
    GROUPS_FILE = CONFIG_DIR / "groups.json"
    CVE_KB_CACHE_FILE = CONFIG_DIR / "cve_kb_cache.json"

    @classmethod
    def load_groups(cls):
        if cls.GROUPS_FILE.exists():
            try:
                with open(cls.GROUPS_FILE, "r", encoding="utf-8") as f:
                    return json.load(f).get("groups", [])
            except Exception as e:
                logger.error(f"Error loading groups.json: {e}")
        return []

    @classmethod
    def load_cve_kb_cache(cls):
        if cls.CVE_KB_CACHE_FILE.exists():
            try:
                with open(cls.CVE_KB_CACHE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f).get("mappings", {})
            except Exception as e:
                logger.error(f"Error loading cve_kb_cache.json: {e}")
        return {}

    @classmethod
    def is_wazuh_configured(cls):
        return bool(cls.WAZUH_API_USER and cls.WAZUH_API_PASSWORD and cls.WAZUH_API_URL != "https://127.0.0.1:55000")

    @classmethod
    def is_ai_configured(cls):
        return bool((cls.AI_PROVIDER == "gemini" and cls.GEMINI_API_KEY) or
                    (cls.AI_PROVIDER == "openrouter" and cls.OPENROUTER_API_KEY))
