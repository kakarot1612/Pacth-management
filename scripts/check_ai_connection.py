"""Minimal provider health check. Never prints credentials or request URLs."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import requests
from core.config import Settings

try:
    if '--advice' in sys.argv:
        from core.ai_advisor import AiAdvisor
        result = AiAdvisor._query_gemini('VMW-13.0', 'Diagnostic host', 'VMware Tools',
                                      'Product upgrade assessment; no verified CVE supplied', 'Unknown', 0)
        print('Structured advice:', bool(result and result.get('is_live_ai')))
        sys.exit(0 if result else 1)
    response = requests.post(
        'https://generativelanguage.googleapis.com/v1beta/models/' + Settings.GEMINI_MODEL + ':generateContent',
        headers={'x-goog-api-key': Settings.GEMINI_API_KEY},
        json={'contents': [{'parts': [{'text': 'Reply OK'}]}]}, timeout=20)
    print('Gemini HTTP:', response.status_code)
    error = response.json().get('error', {})
    print('API status:', error.get('status', 'OK'))
    print('API message:', str(error.get('message', ''))[:600].replace(Settings.GEMINI_API_KEY, '[REDACTED]'))
except Exception as error:
    print('Connection error type:', type(error).__name__)
    sys.exit(1)
