"""HTTP Basic authentication for a TLS reverse proxy or loopback deployment."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import threading
from pathlib import Path
from core.config import BASE_DIR

USERS_FILE = BASE_DIR / 'config' / 'auth_users.json'
ROLES = {
    'viewer': set(),
    'analyst': {'/api/ai-advice', '/api/gemini-advice', '/api/bulk-cve-intel'},
    'operator': {'/api/scan', '/api/trigger-rescan', '/api/server-reboot-status', '/api/install-kb'},
    'approver': {'/api/approve-kb', '/api/unapprove-kb', '/api/exception'},
}


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 600_000).hex()
    return f'pbkdf2_sha256$600000${salt}${digest}'


def verify_password(password, encoded):
    try:
        algorithm, iterations, salt, expected = encoded.split('$')
        if algorithm != 'pbkdf2_sha256' or int(iterations) != 600_000:
            return False
        actual = password_hash(password, salt).split('$')[-1]
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


class AuthStore:
    def __init__(self, path=None):
        self.path = Path(path or USERS_FILE)
        self._failures = {}
        self._lock = threading.Lock()

    def users(self):
        try:
            return json.loads(self.path.read_text(encoding='utf-8')).get('users', {})
        except (OSError, ValueError):
            return {}

    def authenticate(self, header, address):
        now = time.monotonic()
        with self._lock:
            self._failures = {k: v for k, v in self._failures.items() if now - v[1] < 300}
            attempts, _ = self._failures.get(address, (0, now))
            if attempts >= 10:
                return None
        try:
            scheme, value = (header or '').split(' ', 1)
            if scheme.lower() != 'basic':
                return None
            username, password = base64.b64decode(value, validate=True).decode().split(':', 1)
            user = self.users().get(username, {})
            encoded = user.get('password_hash') or password_hash('dummy-password', '00' * 16)
            if verify_password(password, encoded) and user.get('enabled', True) and user.get('role') in {*ROLES, 'admin'}:
                with self._lock:
                    self._failures.pop(address, None)
                return {'username': username, 'role': user['role']}
        except (ValueError, UnicodeError):
            pass
        with self._lock:
            attempts, started = self._failures.get(address, (0, now))
            self._failures[address] = (attempts + 1, started)
        return None

    @staticmethod
    def allowed(user, path):
        return user['role'] == 'admin' or path in ROLES.get(user['role'], set())


auth_store = AuthStore()
