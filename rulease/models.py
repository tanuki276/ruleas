"""v2 domain schema. IDs are internal; public APIs resolve workspace/project/policy keys."""
from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import (Boolean, CheckConstraint, Column, DateTime, ForeignKey,
                        ForeignKeyConstraint, Integer, JSON, String, Text, UniqueConstraint)
from sqlalchemy.orm import declarative_base

Base = declarative_base()
def now():
    return datetime.now(timezone.utc)
def identifier():
    return str(uuid4())
def pk():
    return Column(String(36), primary_key=True, default=identifier)
def created():
    return Column(DateTime(timezone=True), nullable=False, default=now)
def ref(target, **kw):
    return Column(String(36), ForeignKey(target, ondelete='RESTRICT'), nullable=False, **kw)


class Workspace(Base):
    __tablename__ = 'workspaces'
    id = pk()
    key = Column(String(128), nullable=False, unique=True)
    name = Column(String(256), nullable=False)
    created_at = created()


class Human(Base):
    __tablename__ = 'humans'
    id = pk()
    username = Column(String(128), nullable=False, unique=True)
    password_hash = Column(Text)
    created_at = created()


class Membership(Base):
    __tablename__ = 'memberships'
    id = pk()
    workspace_id = ref('workspaces.id')
    human_id = ref('humans.id')
    permissions = Column(JSON, nullable=False, default=list)
    __table_args__ = (UniqueConstraint('workspace_id', 'human_id'),)


class Project(Base):
    __tablename__ = 'projects'
    id = pk()
    workspace_id = ref('workspaces.id')
    key = Column(String(128), nullable=False)
    name = Column(String(256), nullable=False)
    __table_args__ = (UniqueConstraint('workspace_id', 'key'),)


class Environment(Base):
    __tablename__ = 'environments'
    id = pk()
    project_id = ref('projects.id')
    key = Column(String(128), nullable=False)
    required_approvals = Column(Integer, nullable=False, default=0)
    version = Column(Integer, nullable=False, default=1)
    __table_args__ = (UniqueConstraint('project_id', 'key'), UniqueConstraint('id', 'project_id'),
                      CheckConstraint('required_approvals >= 0'))


class Policy(Base):
    __tablename__ = 'policies'
    id = pk()
    project_id = ref('projects.id')
    key = Column(String(128), nullable=False)
    name = Column(String(256), nullable=False)
    archived = Column(Boolean, nullable=False, default=False)
    version = Column(Integer, nullable=False, default=1)
    audit_mode = Column(String(32), nullable=False, default='hash-only')
    __table_args__ = (UniqueConstraint('project_id', 'key'), UniqueConstraint('id', 'project_id'),
                      CheckConstraint("audit_mode IN ('none','hash-only','selected-fields','encrypted','full')"))


class Draft(Base):
    __tablename__ = 'drafts'
    id = pk()
    policy_id = ref('policies.id', unique=True)
    source = Column(Text, nullable=False)
    context_schema = Column(JSON, nullable=False, default=dict)
    version = Column(Integer, nullable=False, default=1)
    updated_at = created()


class Revision(Base):
    __tablename__ = 'revisions'
    id = pk()
    policy_id = ref('policies.id')
    number = Column(Integer, nullable=False)
    source = Column(Text, nullable=False)
    context_schema = Column(JSON, nullable=False)
    revision_hash = Column(String(64), nullable=False)
    engine_version = Column(String(32), nullable=False)
    created_by = ref('humans.id')
    created_at = created()
    __table_args__ = (UniqueConstraint('policy_id', 'number'), UniqueConstraint('id', 'policy_id'),
                      CheckConstraint('number > 0'))


class Deployment(Base):
    __tablename__ = 'deployments'
    id = pk()
    project_id = ref('projects.id')
    environment_id = Column(String(36), nullable=False)
    created_by = ref('humans.id')
    status = Column(String(32), nullable=False, default='pending')
    base_version = Column(Integer, nullable=False)
    activate_at = Column(DateTime(timezone=True))
    created_at = created()
    released_at = Column(DateTime(timezone=True))
    __table_args__ = (ForeignKeyConstraint(['environment_id', 'project_id'], ['environments.id', 'environments.project_id']),
                      UniqueConstraint('id', 'project_id'),
                      CheckConstraint("status IN ('pending','released','rejected')"))


class DeploymentItem(Base):
    __tablename__ = 'deployment_items'
    id = pk()
    deployment_id = Column(String(36), nullable=False)
    project_id = Column(String(36), nullable=False)
    policy_id = Column(String(36), nullable=False)
    revision_id = Column(String(36), nullable=False)
    __table_args__ = (UniqueConstraint('deployment_id', 'policy_id'),
        ForeignKeyConstraint(['deployment_id', 'project_id'], ['deployments.id', 'deployments.project_id']),
        ForeignKeyConstraint(['policy_id', 'project_id'], ['policies.id', 'policies.project_id']),
        ForeignKeyConstraint(['revision_id', 'policy_id'], ['revisions.id', 'revisions.policy_id']))


class Release(Base):
    __tablename__ = 'releases'
    id = pk()
    environment_id = ref('environments.id')
    deployment_id = ref('deployments.id')
    policy_id = Column(String(36), nullable=False)
    revision_id = Column(String(36), nullable=False)
    generation = Column(Integer, nullable=False)
    created_at = created()
    __table_args__ = (UniqueConstraint('environment_id', 'policy_id', 'generation'),
        ForeignKeyConstraint(['revision_id', 'policy_id'], ['revisions.id', 'revisions.policy_id']))


class TestSuite(Base):
    __tablename__ = 'test_suites'
    id = pk()
    policy_id = ref('policies.id')
    name = Column(String(256), nullable=False)
    version = Column(Integer, nullable=False, default=1)


class TestCase(Base):
    __tablename__ = 'test_cases'
    id = pk()
    suite_id = ref('test_suites.id')
    name = Column(String(256), nullable=False)
    rule = Column(String(256), nullable=False)
    context = Column(JSON, nullable=False)
    expect = Column(JSON, nullable=False)


class TestRun(Base):
    __tablename__ = 'test_runs'
    id = pk()
    suite_id = ref('test_suites.id')
    revision_id = ref('revisions.id')
    report = Column(JSON, nullable=False)
    created_at = created()


class ApprovalRequest(Base):
    __tablename__ = 'approval_requests'
    id = pk()
    deployment_id = ref('deployments.id')
    reviewer_id = ref('humans.id')
    approved = Column(Boolean, nullable=False)
    created_at = created()
    __table_args__ = (UniqueConstraint('deployment_id', 'reviewer_id'),)


class SimulationJob(Base):
    __tablename__ = 'simulation_jobs'
    id = pk()
    project_id = ref('projects.id')
    baseline_id = ref('revisions.id')
    candidate_id = ref('revisions.id')
    status = Column(String(32), nullable=False, default='queued')
    report = Column(JSON)
    created_at = created()


class ServiceAccount(Base):
    __tablename__ = 'service_accounts'
    id = pk()
    workspace_id = ref('workspaces.id')
    name = Column(String(128), nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    __table_args__ = (UniqueConstraint('workspace_id', 'name'),)


class APIKey(Base):
    __tablename__ = 'api_keys'
    id = pk()
    service_account_id = ref('service_accounts.id')
    digest = Column(String(64), nullable=False, unique=True)
    prefix = Column(String(24), nullable=False)
    permissions = Column(JSON, nullable=False)
    resource_scope = Column(JSON, nullable=False, default=dict)
    created_by = ref('humans.id')
    created_at = created()
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_used_at = Column(DateTime(timezone=True))
    revoked_at = Column(DateTime(timezone=True))


class DecisionEvent(Base):
    __tablename__ = 'decision_events'
    id = Column(String(40), primary_key=True)
    created_at = Column(DateTime(timezone=True), primary_key=True, nullable=False)
    workspace_id = ref('workspaces.id')
    project_id = ref('projects.id')
    policy_id = ref('policies.id')
    revision_id = ref('revisions.id')
    release_id = ref('releases.id')
    service_account_id = ref('service_accounts.id')
    rule = Column(String(256), nullable=False)
    result = Column(String(32), nullable=False)
    reason = Column(Text, nullable=False)
    input_hash = Column(String(64), nullable=False)
    duration_us = Column(Integer, nullable=False)
    evaluated_at = Column(DateTime(timezone=True), nullable=False)
    __table_args__ = {'postgresql_partition_by': 'RANGE (created_at)'}


class AuditEvent(Base):
    __tablename__ = 'audit_events'
    id = pk()
    workspace_id = ref('workspaces.id')
    actor_type = Column(String(32), nullable=False)
    actor_id = Column(String(128), nullable=False)
    actor_name = Column(String(256), nullable=False)
    credential_type = Column(String(32), nullable=False)
    credential_id = Column(String(128))
    request_id = Column(String(128), nullable=False)
    operation = Column(String(128), nullable=False)
    resource = Column(String(256), nullable=False)
    before_hash = Column(String(64))
    after_hash = Column(String(64))
    previous_hash = Column(String(64))
    event_hash = Column(String(64), nullable=False)
    created_at = created()


class Webhook(Base):
    __tablename__ = 'webhooks'
    id = pk()
    workspace_id = ref('workspaces.id')
    url = Column(Text, nullable=False)
    encrypted_secret = Column(Text, nullable=False)
    events = Column(JSON, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)


class WebhookDelivery(Base):
    __tablename__ = 'webhook_deliveries'
    id = pk()
    webhook_id = ref('webhooks.id')
    event = Column(String(128), nullable=False)
    payload = Column(JSON, nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
    state = Column(String(32), nullable=False, default='queued')
    next_attempt_at = created()


class Job(Base):
    __tablename__ = 'jobs'
    id = pk()
    kind = Column(String(64), nullable=False)
    payload = Column(JSON, nullable=False)
    state = Column(String(32), nullable=False, default='queued')
    attempts = Column(Integer, nullable=False, default=0)
    available_at = created()
    locked_until = Column(DateTime(timezone=True))
    lock_token = Column(String(36))
    last_error = Column(Text)


class AuthSession(Base):
    __tablename__ = 'auth_sessions'
    id = pk()
    human_id = ref('humans.id')
    digest = Column(String(64), nullable=False, unique=True)
    created_at = created()
    last_used_at = created()
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True))


class LoginBucket(Base):
    __tablename__ = 'auth_login_buckets'
    key = Column(String(64), primary_key=True)
    count = Column(Integer, nullable=False)
    reset_at = Column(DateTime(timezone=True), nullable=False)
