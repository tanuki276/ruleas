-- Additive upgrade: validate all existing links, never silently reassign tenants.
ALTER TABLE projects ADD CONSTRAINT projects_id_workspace UNIQUE (id, workspace_id);
ALTER TABLE service_accounts ADD CONSTRAINT service_accounts_id_workspace UNIQUE (id, workspace_id);
ALTER TABLE test_suites ADD CONSTRAINT test_suites_id_policy UNIQUE (id, policy_id);
ALTER TABLE releases ADD CONSTRAINT releases_id_policy_revision UNIQUE (id, policy_id, revision_id);

ALTER TABLE decision_events ADD CONSTRAINT decisions_project_workspace
  FOREIGN KEY (project_id, workspace_id) REFERENCES projects (id, workspace_id);
ALTER TABLE decision_events ADD CONSTRAINT decisions_policy_project
  FOREIGN KEY (policy_id, project_id) REFERENCES policies (id, project_id);
ALTER TABLE decision_events ADD CONSTRAINT decisions_revision_policy
  FOREIGN KEY (revision_id, policy_id) REFERENCES revisions (id, policy_id);
ALTER TABLE decision_events ADD CONSTRAINT decisions_release_revision
  FOREIGN KEY (release_id, policy_id, revision_id) REFERENCES releases (id, policy_id, revision_id);
ALTER TABLE decision_events ADD CONSTRAINT decisions_account_workspace
  FOREIGN KEY (service_account_id, workspace_id) REFERENCES service_accounts (id, workspace_id);

ALTER TABLE test_runs ADD COLUMN policy_id varchar(36);
UPDATE test_runs r SET policy_id = s.policy_id FROM test_suites s WHERE r.suite_id = s.id;
ALTER TABLE test_runs ALTER COLUMN policy_id SET NOT NULL;
ALTER TABLE test_runs ADD CONSTRAINT test_runs_suite_policy
  FOREIGN KEY (suite_id, policy_id) REFERENCES test_suites (id, policy_id);
ALTER TABLE test_runs ADD CONSTRAINT test_runs_revision_policy
  FOREIGN KEY (revision_id, policy_id) REFERENCES revisions (id, policy_id);

ALTER TABLE simulation_jobs ADD COLUMN policy_id varchar(36);
UPDATE simulation_jobs j SET policy_id = r.policy_id FROM revisions r WHERE j.baseline_id = r.id;
ALTER TABLE simulation_jobs ALTER COLUMN policy_id SET NOT NULL;
ALTER TABLE simulation_jobs ADD CONSTRAINT simulations_policy_project
  FOREIGN KEY (policy_id, project_id) REFERENCES policies (id, project_id);
ALTER TABLE simulation_jobs ADD CONSTRAINT simulations_baseline_policy
  FOREIGN KEY (baseline_id, policy_id) REFERENCES revisions (id, policy_id);
ALTER TABLE simulation_jobs ADD CONSTRAINT simulations_candidate_policy
  FOREIGN KEY (candidate_id, policy_id) REFERENCES revisions (id, policy_id);

CREATE FUNCTION rulease_stable_ancestry() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE field text;
BEGIN
  FOREACH field IN ARRAY TG_ARGV LOOP
    IF (to_jsonb(NEW) -> field) IS DISTINCT FROM (to_jsonb(OLD) -> field) THEN
      RAISE EXCEPTION 'Resource ancestry is immutable' USING ERRCODE = '23514';
    END IF;
  END LOOP;
  RETURN NEW;
END $$;
CREATE TRIGGER workspace_stable BEFORE UPDATE ON workspaces
  FOR EACH ROW EXECUTE FUNCTION rulease_stable_ancestry('key');
CREATE TRIGGER project_stable BEFORE UPDATE ON projects
  FOR EACH ROW EXECUTE FUNCTION rulease_stable_ancestry('workspace_id', 'key');
CREATE TRIGGER environment_stable BEFORE UPDATE ON environments
  FOR EACH ROW EXECUTE FUNCTION rulease_stable_ancestry('project_id', 'key');
CREATE TRIGGER account_stable BEFORE UPDATE ON service_accounts
  FOR EACH ROW EXECUTE FUNCTION rulease_stable_ancestry('workspace_id');
CREATE TRIGGER draft_stable BEFORE UPDATE ON drafts
  FOR EACH ROW EXECUTE FUNCTION rulease_stable_ancestry('policy_id');
CREATE TRIGGER suite_stable BEFORE UPDATE ON test_suites
  FOR EACH ROW EXECUTE FUNCTION rulease_stable_ancestry('policy_id');
CREATE TRIGGER case_stable BEFORE UPDATE ON test_cases
  FOR EACH ROW EXECUTE FUNCTION rulease_stable_ancestry('suite_id');
CREATE TRIGGER membership_stable BEFORE UPDATE ON memberships
  FOR EACH ROW EXECUTE FUNCTION rulease_stable_ancestry('workspace_id', 'human_id');
CREATE TRIGGER webhook_stable BEFORE UPDATE ON webhooks
  FOR EACH ROW EXECUTE FUNCTION rulease_stable_ancestry('workspace_id');
CREATE TRIGGER delivery_stable BEFORE UPDATE ON webhook_deliveries
  FOR EACH ROW EXECUTE FUNCTION rulease_stable_ancestry('webhook_id');
CREATE TRIGGER key_stable BEFORE UPDATE ON api_keys
  FOR EACH ROW EXECUTE FUNCTION rulease_stable_ancestry('service_account_id', 'created_by');
CREATE TRIGGER simulation_stable BEFORE UPDATE ON simulation_jobs
  FOR EACH ROW EXECUTE FUNCTION rulease_stable_ancestry('project_id', 'policy_id', 'baseline_id', 'candidate_id');
CREATE TRIGGER test_runs_immutable BEFORE UPDATE OR DELETE ON test_runs
  FOR EACH ROW EXECUTE FUNCTION rulease_immutable();
CREATE TRIGGER decisions_immutable BEFORE UPDATE ON decision_events
  FOR EACH ROW EXECUTE FUNCTION rulease_immutable();

-- Historical creators are checked at insertion, not linked to a membership
-- forever: subsequently removing a member must not destroy policy history.
CREATE FUNCTION rulease_check_creator_tenant() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE tenant varchar(36);
BEGIN
  IF TG_TABLE_NAME = 'revisions' THEN
    SELECT p.workspace_id INTO tenant FROM policies r JOIN projects p ON p.id = r.project_id WHERE r.id = NEW.policy_id;
  ELSIF TG_TABLE_NAME = 'deployments' THEN
    SELECT workspace_id INTO tenant FROM projects WHERE id = NEW.project_id;
  ELSE
    SELECT workspace_id INTO tenant FROM service_accounts WHERE id = NEW.service_account_id;
  END IF;
  PERFORM 1 FROM memberships WHERE workspace_id = tenant AND human_id = NEW.created_by FOR KEY SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Creator must belong to the resource workspace' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER revision_creator_tenant BEFORE INSERT ON revisions
  FOR EACH ROW EXECUTE FUNCTION rulease_check_creator_tenant();
CREATE TRIGGER deployment_creator_tenant BEFORE INSERT ON deployments
  FOR EACH ROW EXECUTE FUNCTION rulease_check_creator_tenant();
CREATE TRIGGER key_creator_tenant BEFORE INSERT ON api_keys
  FOR EACH ROW EXECUTE FUNCTION rulease_check_creator_tenant();

CREATE OR REPLACE FUNCTION rulease_check_approval() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE creator text; state text; tenant varchar(36);
BEGIN
  SELECT created_by, status INTO creator, state FROM deployments WHERE id = NEW.deployment_id FOR UPDATE;
  SELECT p.workspace_id INTO tenant FROM deployments d JOIN projects p ON p.id = d.project_id WHERE d.id = NEW.deployment_id;
  PERFORM 1 FROM memberships WHERE workspace_id = tenant AND human_id = NEW.reviewer_id FOR KEY SHARE;
  IF NOT FOUND OR creator = NEW.reviewer_id OR state <> 'pending' THEN
    RAISE EXCEPTION 'Invalid approval' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION rulease_check_key_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE tenant varchar(36); project varchar(36);
BEGIN
  IF jsonb_typeof(NEW.resource_scope::jsonb) <> 'object' THEN
    RAISE EXCEPTION 'Invalid credential resource scope' USING ERRCODE = '23514';
  END IF;
  IF EXISTS (
    SELECT 1 FROM jsonb_each(NEW.resource_scope::jsonb) AS f
    WHERE f.key NOT IN ('project', 'policy', 'environment') OR jsonb_typeof(f.value) <> 'string'
  ) THEN
    RAISE EXCEPTION 'Invalid credential resource scope' USING ERRCODE = '23514';
  END IF;
  SELECT workspace_id INTO tenant FROM service_accounts WHERE id = NEW.service_account_id;
  IF NEW.resource_scope::jsonb ? 'project' THEN
    SELECT id INTO project FROM projects WHERE workspace_id = tenant AND key = NEW.resource_scope ->> 'project';
    IF project IS NULL THEN
      RAISE EXCEPTION 'Project scope must belong to credential workspace' USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.resource_scope::jsonb ?| ARRAY['policy', 'environment'] THEN
    RAISE EXCEPTION 'Policy/environment scopes require a project' USING ERRCODE = '23514';
  END IF;
  IF NEW.resource_scope::jsonb ? 'policy' AND NOT EXISTS (
    SELECT 1 FROM policies WHERE project_id = project AND key = NEW.resource_scope ->> 'policy'
  ) THEN
    RAISE EXCEPTION 'Policy scope must belong to scoped project' USING ERRCODE = '23514';
  END IF;
  IF NEW.resource_scope::jsonb ? 'environment' AND NOT EXISTS (
    SELECT 1 FROM environments WHERE project_id = project AND key = NEW.resource_scope ->> 'environment'
  ) THEN
    RAISE EXCEPTION 'Environment scope must belong to scoped project' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER key_scope_tenant BEFORE INSERT OR UPDATE OF resource_scope ON api_keys
  FOR EACH ROW EXECUTE FUNCTION rulease_check_key_scope();

-- Validate previously issued scopes too; invalid historical links abort the upgrade.
UPDATE api_keys SET resource_scope = resource_scope;
