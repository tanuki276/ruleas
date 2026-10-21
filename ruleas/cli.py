"""Server commands plus the original engine CLI."""
import argparse
import getpass
import os
import sys

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ('serve', 'init-db', 'migrate', 'stamp-initial', 'create-user'):
        from rulea.cli import main as engine_main
        return engine_main()
    parser = argparse.ArgumentParser(prog='ruleas')
    sub = parser.add_subparsers(dest='command', required=True)
    serve = sub.add_parser('serve')
    serve.add_argument('--host', default='127.0.0.1')
    serve.add_argument('--port', type=int, default=8000)
    sub.add_parser('init-db')
    sub.add_parser('migrate')
    sub.add_parser('stamp-initial')
    user = sub.add_parser('create-user')
    user.add_argument('username')
    user.add_argument('--role', choices=['admin', 'viewer'], default='admin')
    args = parser.parse_args()
    if args.command == 'serve':
        import uvicorn
        uvicorn.run('ruleas.server:create_app', factory=True, host=args.host, port=args.port)
        return 0
    from .storage import Base, User, connect
    from .security import hash_password
    url = os.environ.get('RULEAS_DATABASE_URL')
    if not url:
        parser.error('RULEAS_DATABASE_URL is required')
    engine, sessions = connect(url)
    try:
        if args.command in ('init-db', 'migrate', 'stamp-initial'):
            from .migrate import migrate
            migrate(engine, stamp_initial=args.command == 'stamp-initial')
            print('Database migrated to head')
        else:
            password = getpass.getpass('Password (12+ characters): ')
            if password != getpass.getpass('Confirm password: '):
                parser.error('Passwords do not match')
            with sessions() as session:
                session.add(User(username=args.username, role=args.role, password=hash_password(password)))
                session.commit()
            print('User created')
    finally:
        engine.dispose()
    return 0
