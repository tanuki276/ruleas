"""Persistent server records. PostgreSQL is the production backend."""
from datetime import datetime, timezone
from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()
def now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(128), unique=True, nullable=False)
    password = Column(Text, nullable=False)
    role = Column(String(16), nullable=False)

class APIKey(Base):
    __tablename__ = 'api_keys'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    name = Column(String(128), nullable=False)
    digest = Column(String(64), unique=True, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)

class Policy(Base):
    __tablename__ = 'rules'
    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False)
    namespace = Column(String(256), nullable=False)
    version = Column(Integer, nullable=False, default=1)
    enabled = Column(Boolean, nullable=False, default=True)
    tags = Column(JSON, nullable=False)
    source = Column(Text, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=now, nullable=False)
    deleted = Column(Boolean, default=False, nullable=False)

class Revision(Base):
    __tablename__ = 'rule_versions'
    id = Column(Integer, primary_key=True)
    policy_id = Column(Integer, ForeignKey('rules.id'), nullable=False)
    version = Column(Integer, nullable=False)
    snapshot = Column(JSON, nullable=False)
    actor = Column(String(128), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)

class Audit(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True)
    actor = Column(String(128), nullable=False)
    action = Column(String(32), nullable=False)
    policy_id = Column(Integer, nullable=True)
    rule = Column(String(256), nullable=True)
    result = Column(String(32), nullable=False)
    policy_hash = Column(String(64), nullable=True)
    engine_version = Column(String(32), nullable=True)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)

def connect(url):
    kwargs = {'connect_args': {'check_same_thread': False}} if url.startswith('sqlite') else {}
    engine = create_engine(url, pool_pre_ping=True, **kwargs)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)
