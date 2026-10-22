-- Frozen initial v2 schema. Changes require a new numbered migration.

CREATE TABLE auth_login_buckets (
	key VARCHAR(64) NOT NULL, 
	count INTEGER NOT NULL, 
	reset_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (key)
)

;

CREATE TABLE humans (
	id VARCHAR(36) NOT NULL, 
	username VARCHAR(128) NOT NULL, 
	password_hash TEXT, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (username)
)

;

CREATE TABLE jobs (
	id VARCHAR(36) NOT NULL, 
	kind VARCHAR(64) NOT NULL, 
	payload JSON NOT NULL, 
	state VARCHAR(32) NOT NULL, 
	attempts INTEGER NOT NULL, 
	available_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	locked_until TIMESTAMP WITH TIME ZONE, 
	lock_token VARCHAR(36), 
	last_error TEXT, 
	PRIMARY KEY (id)
)

;

CREATE TABLE workspaces (
	id VARCHAR(36) NOT NULL, 
	key VARCHAR(128) NOT NULL, 
	name VARCHAR(256) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (key)
)

;

CREATE TABLE audit_events (
	id VARCHAR(36) NOT NULL, 
	workspace_id VARCHAR(36) NOT NULL, 
	actor_type VARCHAR(32) NOT NULL, 
	actor_id VARCHAR(128) NOT NULL, 
	actor_name VARCHAR(256) NOT NULL, 
	credential_type VARCHAR(32) NOT NULL, 
	credential_id VARCHAR(128), 
	request_id VARCHAR(128) NOT NULL, 
	operation VARCHAR(128) NOT NULL, 
	resource VARCHAR(256) NOT NULL, 
	before_hash VARCHAR(64), 
	after_hash VARCHAR(64), 
	previous_hash VARCHAR(64), 
	event_hash VARCHAR(64) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(workspace_id) REFERENCES workspaces (id) ON DELETE RESTRICT
)

;

CREATE TABLE auth_sessions (
	id VARCHAR(36) NOT NULL, 
	human_id VARCHAR(36) NOT NULL, 
	digest VARCHAR(64) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	last_used_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	revoked_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(human_id) REFERENCES humans (id) ON DELETE RESTRICT, 
	UNIQUE (digest)
)

;

CREATE TABLE memberships (
	id VARCHAR(36) NOT NULL, 
	workspace_id VARCHAR(36) NOT NULL, 
	human_id VARCHAR(36) NOT NULL, 
	permissions JSON NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (workspace_id, human_id), 
	FOREIGN KEY(workspace_id) REFERENCES workspaces (id) ON DELETE RESTRICT, 
	FOREIGN KEY(human_id) REFERENCES humans (id) ON DELETE RESTRICT
)

;

CREATE TABLE projects (
	id VARCHAR(36) NOT NULL, 
	workspace_id VARCHAR(36) NOT NULL, 
	key VARCHAR(128) NOT NULL, 
	name VARCHAR(256) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (workspace_id, key), 
	FOREIGN KEY(workspace_id) REFERENCES workspaces (id) ON DELETE RESTRICT
)

;

CREATE TABLE service_accounts (
	id VARCHAR(36) NOT NULL, 
	workspace_id VARCHAR(36) NOT NULL, 
	name VARCHAR(128) NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (workspace_id, name), 
	FOREIGN KEY(workspace_id) REFERENCES workspaces (id) ON DELETE RESTRICT
)

;

CREATE TABLE webhooks (
	id VARCHAR(36) NOT NULL, 
	workspace_id VARCHAR(36) NOT NULL, 
	url TEXT NOT NULL, 
	encrypted_secret TEXT NOT NULL, 
	events JSON NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(workspace_id) REFERENCES workspaces (id) ON DELETE RESTRICT
)

;

CREATE TABLE api_keys (
	id VARCHAR(36) NOT NULL, 
	service_account_id VARCHAR(36) NOT NULL, 
	digest VARCHAR(64) NOT NULL, 
	prefix VARCHAR(24) NOT NULL, 
	permissions JSON NOT NULL, 
	resource_scope JSON NOT NULL, 
	created_by VARCHAR(36) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	last_used_at TIMESTAMP WITH TIME ZONE, 
	revoked_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(service_account_id) REFERENCES service_accounts (id) ON DELETE RESTRICT, 
	UNIQUE (digest), 
	FOREIGN KEY(created_by) REFERENCES humans (id) ON DELETE RESTRICT
)

;

CREATE TABLE environments (
	id VARCHAR(36) NOT NULL, 
	project_id VARCHAR(36) NOT NULL, 
	key VARCHAR(128) NOT NULL, 
	required_approvals INTEGER NOT NULL, 
	version INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (project_id, key), 
	UNIQUE (id, project_id), 
	CHECK (required_approvals >= 0), 
	FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE RESTRICT
)

;

CREATE TABLE policies (
	id VARCHAR(36) NOT NULL, 
	project_id VARCHAR(36) NOT NULL, 
	key VARCHAR(128) NOT NULL, 
	name VARCHAR(256) NOT NULL, 
	archived BOOLEAN NOT NULL, 
	version INTEGER NOT NULL, 
	audit_mode VARCHAR(32) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (project_id, key), 
	UNIQUE (id, project_id), 
	CHECK (audit_mode IN ('none','hash-only','selected-fields','encrypted','full')), 
	FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE RESTRICT
)

;

CREATE TABLE webhook_deliveries (
	id VARCHAR(36) NOT NULL, 
	webhook_id VARCHAR(36) NOT NULL, 
	event VARCHAR(128) NOT NULL, 
	payload JSON NOT NULL, 
	attempts INTEGER NOT NULL, 
	state VARCHAR(32) NOT NULL, 
	next_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(webhook_id) REFERENCES webhooks (id) ON DELETE RESTRICT
)

;

CREATE TABLE deployments (
	id VARCHAR(36) NOT NULL, 
	project_id VARCHAR(36) NOT NULL, 
	environment_id VARCHAR(36) NOT NULL, 
	created_by VARCHAR(36) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	base_version INTEGER NOT NULL, 
	activate_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	released_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(environment_id, project_id) REFERENCES environments (id, project_id), 
	UNIQUE (id, project_id), 
	CHECK (status IN ('pending','released','rejected')), 
	FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE RESTRICT, 
	FOREIGN KEY(created_by) REFERENCES humans (id) ON DELETE RESTRICT
)

;

CREATE TABLE drafts (
	id VARCHAR(36) NOT NULL, 
	policy_id VARCHAR(36) NOT NULL, 
	source TEXT NOT NULL, 
	context_schema JSON NOT NULL, 
	version INTEGER NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (policy_id), 
	FOREIGN KEY(policy_id) REFERENCES policies (id) ON DELETE RESTRICT
)

;

CREATE TABLE revisions (
	id VARCHAR(36) NOT NULL, 
	policy_id VARCHAR(36) NOT NULL, 
	number INTEGER NOT NULL, 
	source TEXT NOT NULL, 
	context_schema JSON NOT NULL, 
	revision_hash VARCHAR(64) NOT NULL, 
	engine_version VARCHAR(32) NOT NULL, 
	created_by VARCHAR(36) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (policy_id, number), 
	UNIQUE (id, policy_id), 
	CHECK (number > 0), 
	FOREIGN KEY(policy_id) REFERENCES policies (id) ON DELETE RESTRICT, 
	FOREIGN KEY(created_by) REFERENCES humans (id) ON DELETE RESTRICT
)

;

CREATE TABLE test_suites (
	id VARCHAR(36) NOT NULL, 
	policy_id VARCHAR(36) NOT NULL, 
	name VARCHAR(256) NOT NULL, 
	version INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(policy_id) REFERENCES policies (id) ON DELETE RESTRICT
)

;

CREATE TABLE approval_requests (
	id VARCHAR(36) NOT NULL, 
	deployment_id VARCHAR(36) NOT NULL, 
	reviewer_id VARCHAR(36) NOT NULL, 
	approved BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (deployment_id, reviewer_id), 
	FOREIGN KEY(deployment_id) REFERENCES deployments (id) ON DELETE RESTRICT, 
	FOREIGN KEY(reviewer_id) REFERENCES humans (id) ON DELETE RESTRICT
)

;

CREATE TABLE deployment_items (
	id VARCHAR(36) NOT NULL, 
	deployment_id VARCHAR(36) NOT NULL, 
	project_id VARCHAR(36) NOT NULL, 
	policy_id VARCHAR(36) NOT NULL, 
	revision_id VARCHAR(36) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (deployment_id, policy_id), 
	FOREIGN KEY(deployment_id, project_id) REFERENCES deployments (id, project_id), 
	FOREIGN KEY(policy_id, project_id) REFERENCES policies (id, project_id), 
	FOREIGN KEY(revision_id, policy_id) REFERENCES revisions (id, policy_id)
)

;

CREATE TABLE releases (
	id VARCHAR(36) NOT NULL, 
	environment_id VARCHAR(36) NOT NULL, 
	deployment_id VARCHAR(36) NOT NULL, 
	policy_id VARCHAR(36) NOT NULL, 
	revision_id VARCHAR(36) NOT NULL, 
	generation INTEGER NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (environment_id, policy_id, generation), 
	FOREIGN KEY(revision_id, policy_id) REFERENCES revisions (id, policy_id), 
	FOREIGN KEY(environment_id) REFERENCES environments (id) ON DELETE RESTRICT, 
	FOREIGN KEY(deployment_id) REFERENCES deployments (id) ON DELETE RESTRICT
)

;

CREATE TABLE simulation_jobs (
	id VARCHAR(36) NOT NULL, 
	project_id VARCHAR(36) NOT NULL, 
	baseline_id VARCHAR(36) NOT NULL, 
	candidate_id VARCHAR(36) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	report JSON, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE RESTRICT, 
	FOREIGN KEY(baseline_id) REFERENCES revisions (id) ON DELETE RESTRICT, 
	FOREIGN KEY(candidate_id) REFERENCES revisions (id) ON DELETE RESTRICT
)

;

CREATE TABLE test_cases (
	id VARCHAR(36) NOT NULL, 
	suite_id VARCHAR(36) NOT NULL, 
	name VARCHAR(256) NOT NULL, 
	rule VARCHAR(256) NOT NULL, 
	context JSON NOT NULL, 
	expect JSON NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(suite_id) REFERENCES test_suites (id) ON DELETE RESTRICT
)

;

CREATE TABLE test_runs (
	id VARCHAR(36) NOT NULL, 
	suite_id VARCHAR(36) NOT NULL, 
	revision_id VARCHAR(36) NOT NULL, 
	report JSON NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(suite_id) REFERENCES test_suites (id) ON DELETE RESTRICT, 
	FOREIGN KEY(revision_id) REFERENCES revisions (id) ON DELETE RESTRICT
)

;

CREATE TABLE decision_events (
	id VARCHAR(40) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	workspace_id VARCHAR(36) NOT NULL, 
	project_id VARCHAR(36) NOT NULL, 
	policy_id VARCHAR(36) NOT NULL, 
	revision_id VARCHAR(36) NOT NULL, 
	release_id VARCHAR(36) NOT NULL, 
	service_account_id VARCHAR(36) NOT NULL, 
	rule VARCHAR(256) NOT NULL, 
	result VARCHAR(32) NOT NULL, 
	reason TEXT NOT NULL, 
	input_hash VARCHAR(64) NOT NULL, 
	duration_us INTEGER NOT NULL, 
	evaluated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id, created_at), 
	FOREIGN KEY(workspace_id) REFERENCES workspaces (id) ON DELETE RESTRICT, 
	FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE RESTRICT, 
	FOREIGN KEY(policy_id) REFERENCES policies (id) ON DELETE RESTRICT, 
	FOREIGN KEY(revision_id) REFERENCES revisions (id) ON DELETE RESTRICT, 
	FOREIGN KEY(release_id) REFERENCES releases (id) ON DELETE RESTRICT, 
	FOREIGN KEY(service_account_id) REFERENCES service_accounts (id) ON DELETE RESTRICT
)
 PARTITION BY RANGE (created_at)

;
CREATE TABLE decision_events_default PARTITION OF decision_events DEFAULT;
CREATE INDEX decision_events_lookup ON decision_events (workspace_id, created_at DESC, id);
CREATE INDEX releases_current ON releases (environment_id, policy_id, generation DESC);
CREATE INDEX jobs_claim ON jobs (state, available_at);

CREATE FUNCTION rulease_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is immutable', TG_TABLE_NAME USING ERRCODE = '23514';
END $$;
CREATE TRIGGER revisions_immutable BEFORE UPDATE OR DELETE ON revisions
  FOR EACH ROW EXECUTE FUNCTION rulease_immutable();
CREATE TRIGGER releases_immutable BEFORE UPDATE OR DELETE ON releases
  FOR EACH ROW EXECUTE FUNCTION rulease_immutable();
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION rulease_immutable();
CREATE TRIGGER deployment_items_immutable BEFORE UPDATE OR DELETE ON deployment_items
  FOR EACH ROW EXECUTE FUNCTION rulease_immutable();
CREATE TRIGGER approvals_immutable BEFORE UPDATE OR DELETE ON approval_requests
  FOR EACH ROW EXECUTE FUNCTION rulease_immutable();

CREATE FUNCTION rulease_stable_policy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.key <> OLD.key OR NEW.project_id <> OLD.project_id THEN
    RAISE EXCEPTION 'Policy key and project are immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER policy_stable BEFORE UPDATE ON policies
  FOR EACH ROW EXECUTE FUNCTION rulease_stable_policy();

CREATE FUNCTION rulease_freeze_deployment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (to_jsonb(NEW) - 'status' - 'released_at') IS DISTINCT FROM
     (to_jsonb(OLD) - 'status' - 'released_at') OR OLD.status <> 'pending' THEN
    RAISE EXCEPTION 'Deployment bundle is frozen' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER deployment_frozen BEFORE UPDATE ON deployments
  FOR EACH ROW EXECUTE FUNCTION rulease_freeze_deployment();

CREATE FUNCTION rulease_check_bundle() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE state text;
BEGIN
  SELECT status INTO state FROM deployments WHERE id = NEW.deployment_id FOR UPDATE;
  IF state <> 'pending' OR EXISTS (SELECT 1 FROM approval_requests WHERE deployment_id = NEW.deployment_id) THEN
    RAISE EXCEPTION 'Deployment is frozen after approval' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER bundle_insert BEFORE INSERT ON deployment_items
  FOR EACH ROW EXECUTE FUNCTION rulease_check_bundle();

CREATE FUNCTION rulease_check_approval() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE creator text; state text;
BEGIN
  SELECT created_by, status INTO creator, state FROM deployments WHERE id = NEW.deployment_id FOR UPDATE;
  IF creator = NEW.reviewer_id OR state <> 'pending' THEN
    RAISE EXCEPTION 'Invalid approval' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER approval_insert BEFORE INSERT ON approval_requests
  FOR EACH ROW EXECUTE FUNCTION rulease_check_approval();

CREATE FUNCTION rulease_check_release() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM deployments d JOIN deployment_items i ON i.deployment_id = d.id
    JOIN environments e ON e.id = d.environment_id
    WHERE d.id = NEW.deployment_id AND d.status = 'released'
      AND d.environment_id = NEW.environment_id AND i.policy_id = NEW.policy_id
      AND i.revision_id = NEW.revision_id AND e.version = NEW.generation
  ) THEN
    RAISE EXCEPTION 'Release must match the released bundle' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER release_insert BEFORE INSERT ON releases
  FOR EACH ROW EXECUTE FUNCTION rulease_check_release();
