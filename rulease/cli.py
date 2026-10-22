"""Platform commands; local policy quality commands never open a database."""
import argparse
import getpass
import json
import sys
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser(prog='rulease')
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('validate', 'lint', 'test', 'diff', 'simulate', 'preview'):
        p = sub.add_parser(command)
        p.add_argument('policy')
        if command in ('test', 'simulate'):
            p.add_argument('cases')
        if command in ('diff', 'simulate'):
            p.add_argument('--against', required=True)
        if command == 'preview':
            p.add_argument('rule')
            p.add_argument('--context', default='{}')
            p.add_argument('--trace', choices=['none', 'summary', 'full'], default='full')
    worker = sub.add_parser('worker')
    worker.add_argument('--once', action='store_true')
    sub.add_parser('migrate')
    sub.add_parser('doctor')
    init = sub.add_parser('init')
    init.add_argument('--workspace', required=True)
    init.add_argument('--project', required=True)
    init.add_argument('--username', required=True)
    serve = sub.add_parser('serve')
    serve.add_argument('--host', default='127.0.0.1')
    serve.add_argument('--port', type=int, default=8000)
    args = parser.parse_args(argv)
    try:
        if args.command in ('validate', 'lint', 'test', 'diff', 'simulate'):
            from rulea.cli import main as engine_main
            command = 'check' if args.command == 'validate' else args.command
            forwarded = [command, args.against, args.policy] if command in ('diff', 'simulate') else [command, args.policy]
            if command in ('test', 'simulate'):
                forwarded.append(args.cases)
            return engine_main(forwarded)
        if args.command == 'preview':
            from .service import preview
            print(json.dumps(preview(Path(args.policy).read_text(encoding='utf-8'), args.rule,
                                     json.loads(args.context), trace=args.trace), indent=2))
            return 0
        from .config import Settings
        settings = Settings()
        if args.command == 'serve':
            import uvicorn
            from .server import create_app
            uvicorn.run(create_app(settings), host=args.host, port=args.port, proxy_headers=False)
            return 0
        from .database import connect, migrate
        engine, sessions = connect(settings.database_url)
        try:
            if args.command == 'worker':
                import signal
                from threading import Event
                from .worker import run, run_once
                if args.once:
                    run_once(sessions, settings)
                else:
                    stop = Event()
                    for signum in (signal.SIGINT, signal.SIGTERM):
                        signal.signal(signum, lambda *_: stop.set())
                    run(sessions, settings, stop)
            elif args.command == 'doctor':
                from sqlalchemy import text
                with engine.connect() as connection:
                    connection.execute(text('SELECT version FROM rulease_migrations LIMIT 1'))
                print('Configuration and PostgreSQL migration table: OK')
            elif args.command == 'migrate':
                migrate(engine)
                print('Database migrated')
            else:
                from .models import Environment, Human, Membership, Project, Workspace
                from .security import hash_password
                from .service import ROLE_PERMISSIONS, valid_key
                password = getpass.getpass('Password (12+ characters): ')
                if password != getpass.getpass('Confirm password: '):
                    raise ValueError('Passwords do not match')
                with sessions.begin() as session:
                    workspace = Workspace(key=valid_key(args.workspace), name=args.workspace)
                    human = Human(username=args.username, password_hash=hash_password(password))
                    session.add_all([workspace, human])
                    session.flush()
                    session.add(Membership(workspace_id=workspace.id, human_id=human.id,
                                           permissions=sorted(ROLE_PERMISSIONS['owner'])))
                    project = Project(workspace_id=workspace.id, key=valid_key(args.project), name=args.project)
                    session.add(project)
                    session.flush()
                    for key, approvals in [('development', 0), ('staging', 1), ('production', 2)]:
                        session.add(Environment(project_id=project.id, key=key, required_approvals=approvals))
                print('Workspace, project and owner created')
        finally:
            engine.dispose()
        return 0
    except (ValueError, OSError) as exc:
        print('rulease: ' + str(exc), file=sys.stderr)
        return 2


def legacy_main():
    print('warning: ruleas is deprecated. Use rulease.', file=sys.stderr)
    return main()
