-- Tenant-scoped queue and staged rollout records. Earlier migrations remain frozen.
ALTER TABLE simulation_jobs ADD COLUMN request_hash varchar(64);
ALTER TABLE simulation_jobs ADD CONSTRAINT simulation_id_project UNIQUE(id, project_id);
ALTER TABLE jobs ADD COLUMN project_id varchar(36) REFERENCES projects(id);
ALTER TABLE jobs ADD COLUMN simulation_id varchar(36);
ALTER TABLE jobs ADD COLUMN rollout_id varchar(36);
ALTER TABLE jobs ADD COLUMN dedup_key varchar(128) UNIQUE;
ALTER TABLE jobs ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE rollouts (
	id VARCHAR(36) NOT NULL, 
	project_id VARCHAR(36) NOT NULL, 
	environment_id VARCHAR(36) NOT NULL, 
	policy_id VARCHAR(36) NOT NULL, 
	deployment_id VARCHAR(36) NOT NULL, 
	baseline_release_id VARCHAR(36) NOT NULL, 
	candidate_revision_id VARCHAR(36) NOT NULL, 
	candidate_release_id VARCHAR(36), 
	mode VARCHAR(16) NOT NULL, 
	state VARCHAR(16) NOT NULL, 
	basis_points INTEGER NOT NULL, 
	stickiness_path VARCHAR(256) NOT NULL, 
	version INTEGER NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (deployment_id, policy_id), 
	UNIQUE (id, project_id), 
	FOREIGN KEY(environment_id, project_id) REFERENCES environments (id, project_id), 
	FOREIGN KEY(policy_id, project_id) REFERENCES policies (id, project_id), 
	FOREIGN KEY(deployment_id, project_id) REFERENCES deployments (id, project_id), 
	FOREIGN KEY(candidate_revision_id, policy_id) REFERENCES revisions (id, policy_id), 
	FOREIGN KEY(candidate_release_id, policy_id, candidate_revision_id) REFERENCES releases (id, policy_id, revision_id), 
	CHECK (mode IN ('shadow','canary')), 
	CHECK (state IN ('active','paused','rolled_back','completed','stopped')), 
	CHECK (basis_points BETWEEN 0 AND 10000), 
	FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE RESTRICT, 
	FOREIGN KEY(environment_id) REFERENCES environments (id) ON DELETE RESTRICT, 
	FOREIGN KEY(policy_id) REFERENCES policies (id) ON DELETE RESTRICT, 
	FOREIGN KEY(deployment_id) REFERENCES deployments (id) ON DELETE RESTRICT, 
	FOREIGN KEY(baseline_release_id) REFERENCES releases (id) ON DELETE RESTRICT, 
	FOREIGN KEY(candidate_revision_id) REFERENCES revisions (id) ON DELETE RESTRICT
)

;

CREATE TABLE simulation_results (
	id VARCHAR(36) NOT NULL, 
	simulation_id VARCHAR(36) NOT NULL, 
	project_id VARCHAR(36) NOT NULL, 
	position INTEGER NOT NULL, 
	rule VARCHAR(256) NOT NULL, 
	input_hash VARCHAR(64) NOT NULL, 
	old_result VARCHAR(32) NOT NULL, 
	new_result VARCHAR(32) NOT NULL, 
	changed INTEGER NOT NULL, 
	encrypted_context TEXT NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (simulation_id, position), 
	FOREIGN KEY(simulation_id, project_id) REFERENCES simulation_jobs (id, project_id), 
	FOREIGN KEY(simulation_id) REFERENCES simulation_jobs (id) ON DELETE RESTRICT, 
	FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE RESTRICT
)

;

CREATE TABLE shadow_results (
	id VARCHAR(36) NOT NULL, 
	job_id VARCHAR(36) NOT NULL, 
	rollout_id VARCHAR(36) NOT NULL, 
	project_id VARCHAR(36) NOT NULL, 
	decision_id VARCHAR(40) NOT NULL, 
	input_hash VARCHAR(64) NOT NULL, 
	primary_result VARCHAR(32) NOT NULL, 
	shadow_result VARCHAR(32) NOT NULL, 
	changed INTEGER NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(rollout_id, project_id) REFERENCES rollouts (id, project_id), 
	UNIQUE (job_id), 
	FOREIGN KEY(job_id) REFERENCES jobs (id) ON DELETE RESTRICT, 
	FOREIGN KEY(rollout_id) REFERENCES rollouts (id) ON DELETE RESTRICT, 
	FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE RESTRICT
)

;

ALTER TABLE jobs ADD CONSTRAINT jobs_simulation_tenant FOREIGN KEY(simulation_id,project_id) REFERENCES simulation_jobs(id,project_id);
ALTER TABLE jobs ADD CONSTRAINT jobs_rollout_tenant FOREIGN KEY(rollout_id,project_id) REFERENCES rollouts(id,project_id);
ALTER TABLE jobs ADD CONSTRAINT jobs_typed_payload CHECK (
 kind NOT IN ('replay','shadow') OR (project_id IS NOT NULL AND
 ((kind='replay' AND simulation_id IS NOT NULL AND rollout_id IS NULL) OR
  (kind='shadow' AND rollout_id IS NOT NULL AND simulation_id IS NULL))));
ALTER TABLE jobs ADD CONSTRAINT jobs_state CHECK(state IN ('queued','running','completed','failed'));
CREATE INDEX jobs_claim ON jobs(state,available_at,locked_until);
CREATE INDEX simulation_results_filter ON simulation_results(simulation_id,changed,position);
CREATE INDEX shadow_results_rollout ON shadow_results(rollout_id,created_at);
CREATE INDEX rollouts_lookup ON rollouts(environment_id,policy_id,created_at);
CREATE FUNCTION rulease_rollout_links() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM releases WHERE id=NEW.baseline_release_id AND environment_id=NEW.environment_id AND policy_id=NEW.policy_id) OR
 NOT EXISTS (SELECT 1 FROM deployment_items WHERE deployment_id=NEW.deployment_id AND policy_id=NEW.policy_id AND revision_id=NEW.candidate_revision_id) OR
 NOT EXISTS (SELECT 1 FROM deployments WHERE id=NEW.deployment_id AND environment_id=NEW.environment_id) THEN
  RAISE EXCEPTION 'Invalid rollout ancestry' USING ERRCODE='23514';
 END IF;
 IF NEW.mode='canary' AND (NEW.candidate_release_id IS NULL OR NOT EXISTS (
  SELECT 1 FROM releases WHERE id=NEW.candidate_release_id AND deployment_id=NEW.deployment_id AND environment_id=NEW.environment_id)) THEN
  RAISE EXCEPTION 'Canary requires the approved candidate release' USING ERRCODE='23514';
 END IF;
 IF NEW.mode='shadow' AND NEW.candidate_release_id IS NOT NULL THEN
  RAISE EXCEPTION 'Shadow cannot release a candidate' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER rollout_links BEFORE INSERT ON rollouts FOR EACH ROW EXECUTE FUNCTION rulease_rollout_links();
CREATE TRIGGER rollout_stable BEFORE UPDATE ON rollouts FOR EACH ROW EXECUTE FUNCTION rulease_stable_ancestry(
 'project_id','environment_id','policy_id','deployment_id','baseline_release_id','candidate_revision_id','candidate_release_id','mode','stickiness_path');
CREATE TRIGGER job_stable BEFORE UPDATE ON jobs FOR EACH ROW EXECUTE FUNCTION rulease_stable_ancestry('project_id','simulation_id','rollout_id','kind','dedup_key');
CREATE TRIGGER simulation_results_stable BEFORE UPDATE ON simulation_results FOR EACH ROW EXECUTE FUNCTION rulease_immutable();
CREATE TRIGGER shadow_results_stable BEFORE UPDATE ON shadow_results FOR EACH ROW EXECUTE FUNCTION rulease_immutable();
