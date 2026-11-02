"""Run locally: python scripts/manage_users.py admin --role admin"""
import argparse
import getpass
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.security import USERS_FILE, password_hash, ROLES


def main():
    parser = argparse.ArgumentParser(description='Create/update local web account')
    parser.add_argument('username')
    parser.add_argument('--role', choices=[*ROLES, 'admin'], default='viewer')
    args = parser.parse_args()
    if not args.username.strip() or ':' in args.username:
        parser.error('Invalid username')
    password = getpass.getpass('Password (minimum 12 characters): ')
    if len(password) < 12 or password != getpass.getpass('Confirm password: '):
        parser.error('Password too short or confirmation mismatch')
    data = json.loads(USERS_FILE.read_text(encoding='utf-8')) if USERS_FILE.exists() else {'users': {}}
    data['users'][args.username] = {'role': args.role, 'password_hash': password_hash(password), 'enabled': True}
    from core.storage import atomic_write_text
    atomic_write_text(USERS_FILE, json.dumps(data, indent=2))
    print('Account saved. Password is not stored in plaintext.')


if __name__ == '__main__':
    main()
