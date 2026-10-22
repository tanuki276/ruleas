"""Relational tenancy for queued work and staged releases."""
from sqlalchemy import Column, Integer, String, JSON, Text, DateTime, ForeignKeyConstraint, UniqueConstraint, CheckConstraint
from .models import Base, pk, ref, created


class Rollout(Base):
    __tablename__ = 'rollouts'
    id = pk()
    project_id = ref('projects.id')
    environment_id = ref('environments.id')
    policy_id = ref('policies.id')
    deployment_id = ref('deployments.id')
    baseline_release_id = ref('releases.id')
    candidate_revision_id = ref('revisions.id')
    candidate_release_id = Column(String(36))
    mode = Column(String(16), nullable=False)
    state = Column(String(16), nullable=False, default='active')
    basis_points = Column(Integer, nullable=False, default=0)
    stickiness_path = Column(String(256), nullable=False)
    version = Column(Integer, nullable=False, default=1)
    created_at = created()
    __table_args__ = (
        UniqueConstraint('deployment_id', 'policy_id'), UniqueConstraint('id', 'project_id'),
        ForeignKeyConstraint(['environment_id', 'project_id'], ['environments.id', 'environments.project_id']),
        ForeignKeyConstraint(['policy_id', 'project_id'], ['policies.id', 'policies.project_id']),
        ForeignKeyConstraint(['deployment_id', 'project_id'], ['deployments.id', 'deployments.project_id']),
        ForeignKeyConstraint(['candidate_revision_id', 'policy_id'], ['revisions.id', 'revisions.policy_id']),
        ForeignKeyConstraint(['candidate_release_id', 'policy_id', 'candidate_revision_id'], ['releases.id', 'releases.policy_id', 'releases.revision_id']),
        CheckConstraint("mode IN ('shadow','canary')"),
        CheckConstraint("state IN ('active','paused','rolled_back','completed','stopped')"),
        CheckConstraint('basis_points BETWEEN 0 AND 10000'))


class SimulationResult(Base):
    __tablename__ = 'simulation_results'
    id = pk()
    simulation_id = ref('simulation_jobs.id')
    project_id = ref('projects.id')
    position = Column(Integer, nullable=False)
    rule = Column(String(256), nullable=False)
    input_hash = Column(String(64), nullable=False)
    old_result = Column(String(32), nullable=False)
    new_result = Column(String(32), nullable=False)
    changed = Column(Integer, nullable=False)
    encrypted_context = Column(Text, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    __table_args__ = (UniqueConstraint('simulation_id', 'position'),
        ForeignKeyConstraint(['simulation_id', 'project_id'], ['simulation_jobs.id', 'simulation_jobs.project_id']))


class ShadowResult(Base):
    __tablename__ = 'shadow_results'
    id = pk()
    job_id = ref('jobs.id', unique=True)
    rollout_id = ref('rollouts.id')
    project_id = ref('projects.id')
    decision_id = Column(String(40), nullable=False)
    input_hash = Column(String(64), nullable=False)
    primary_result = Column(String(32), nullable=False)
    shadow_result = Column(String(32), nullable=False)
    changed = Column(Integer, nullable=False)
    created_at = created()
    __table_args__ = (ForeignKeyConstraint(['rollout_id', 'project_id'], ['rollouts.id', 'rollouts.project_id']),)
