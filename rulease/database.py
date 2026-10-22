"""PostgreSQL connections and ordered, transactional SQL migrations."""
import hashlib
from importlib.resources import files
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker


def connect(url):
    parsed = make_url(url)
    if parsed.get_backend_name() != 'postgresql':
        raise ValueError('Rulease v2 requires PostgreSQL')
    engine = create_engine(parsed.set(drivername='postgresql+psycopg'), pool_pre_ping=True)
    return engine, sessionmaker(engine, expire_on_commit=False)


def migrate(engine):
    if engine.dialect.name != 'postgresql':
        raise ValueError('Rulease v2 migrations require PostgreSQL')
    with engine.begin() as connection:
        connection.execute(text('SELECT pg_advisory_xact_lock(182736459)'))
        tables = set(inspect(connection).get_table_names())
        if tables and 'rulease_migrations' not in tables:
            raise ValueError('Database is not a managed v2 database; v1 migration requires a separate import')
        connection.execute(text('CREATE TABLE IF NOT EXISTS rulease_migrations (version text PRIMARY KEY, checksum text NOT NULL)'))
        applied = {row[0]: row[1] for row in connection.execute(text('SELECT version, checksum FROM rulease_migrations'))}
        for resource in sorted(files('rulease').joinpath('migrations').iterdir(), key=lambda p: p.name):
            if not resource.name.endswith('.sql'):
                continue
            sql = resource.read_text(encoding='utf-8')
            checksum = hashlib.sha256(sql.encode()).hexdigest()
            if resource.name in applied:
                if applied[resource.name] != checksum:
                    raise ValueError('Applied migration checksum mismatch: ' + resource.name)
                continue
            connection.exec_driver_sql(sql, execution_options={'no_parameters': True})
            connection.execute(text('INSERT INTO rulease_migrations VALUES (:version, :checksum)'),
                               dict(version=resource.name, checksum=checksum))
