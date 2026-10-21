"""Packaged Alembic migrations, including explicit legacy database adoption."""
from pathlib import Path
from alembic import command
from alembic.config import Config
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import MetaData, inspect
from .storage import Base

def migrate(engine, stamp_initial=False):
    config = Config()
    config.set_main_option('script_location', str(Path(__file__).with_name('migrations')))
    with engine.begin() as connection:
        config.attributes['connection'] = connection
        tables = set(inspect(connection).get_table_names())
        if stamp_initial:
            if 'alembic_version' in tables:
                raise ValueError('Database is already managed by Alembic')
            expected = MetaData()
            for table in Base.metadata.sorted_tables:
                if table.name != 'login_buckets':
                    table.to_metadata(expected)
            differences = compare_metadata(MigrationContext.configure(connection), expected)
            if differences:
                raise ValueError('Legacy schema differs from revision 0001; back up and reconcile before stamping')
            command.stamp(config, '0001')
        elif tables and 'alembic_version' not in tables:
            raise ValueError('Legacy database detected. Back up, then run ruleas stamp-initial to verify and adopt revision 0001')
        command.upgrade(config, 'head')
