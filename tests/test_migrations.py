import pytest
from sqlalchemy import create_engine, inspect, text, MetaData
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from ruleas.storage import Base
from ruleas.migrate import migrate


def test_fresh_and_legacy_migrations(tmp_path):
    engine = create_engine('sqlite:///' + str(tmp_path / 'fresh.db'))
    migrate(engine)
    migrate(engine)
    with engine.connect() as c:
        assert c.scalar(text('SELECT version_num FROM alembic_version')) == '0002'
        assert compare_metadata(MigrationContext.configure(c), Base.metadata) == []
    engine.dispose()
    legacy = create_engine('sqlite:///' + str(tmp_path / 'legacy.db'))
    metadata = MetaData()
    for table in Base.metadata.sorted_tables:
        if table.name != 'login_buckets':
            table.to_metadata(metadata)
    metadata.create_all(legacy)
    with legacy.begin() as c:
        c.execute(text("INSERT INTO users (id, username, password, role) VALUES (1, 'kept', 'hash', 'admin')"))
    with pytest.raises(ValueError, match='Legacy database'):
        migrate(legacy)
    migrate(legacy, stamp_initial=True)
    with legacy.connect() as c:
        assert c.scalar(text('SELECT username FROM users WHERE id=1')) == 'kept'
        assert c.scalar(text('SELECT version_num FROM alembic_version')) == '0002'
    legacy.dispose()


def test_refuse_incompatible_legacy(tmp_path):
    engine = create_engine('sqlite:///' + str(tmp_path / 'invalid.db'))
    with engine.begin() as c:
        c.execute(text('CREATE TABLE users (id INTEGER PRIMARY KEY)'))
    with pytest.raises(ValueError, match='differs'):
        migrate(engine, stamp_initial=True)
    assert 'alembic_version' not in inspect(engine).get_table_names()
    engine.dispose()
