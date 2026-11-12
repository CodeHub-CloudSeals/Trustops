-- DESIGN DRAFT - NOT APPLIED, NOT TESTED against PostgreSQL. Target schema to replace the snapshot `state` row so that
-- several API tasks can run. Every tenant table carries tenant_id and Row Level Security keyed on a per-request setting.
CREATE TABLE tenant (tenant_id text PRIMARY KEY, name text NOT NULL, residency_profile text, allow_preliminary_report boolean NOT NULL DEFAULT false);
CREATE TABLE app_user (sub text PRIMARY KEY, tenant_id text REFERENCES tenant, roles text[] NOT NULL);
CREATE TABLE assessment (assessment_id uuid PRIMARY KEY, tenant_id text NOT NULL REFERENCES tenant, ai_system_name text NOT NULL,
    industry text NOT NULL, questionnaire_version text NOT NULL, registry_sha256 text NOT NULL, status text NOT NULL,
    snapshot jsonb, created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE answer (assessment_id uuid NOT NULL REFERENCES assessment, scope_id text NOT NULL, question_id text NOT NULL,
    tenant_id text NOT NULL, value jsonb, answer_status text NOT NULL, comment text, evidence_refs text[], revision int NOT NULL,
    updated_by text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (assessment_id, scope_id, question_id));
CREATE TABLE answer_revision (LIKE answer, revision_id bigserial PRIMARY KEY);
CREATE TABLE evidence (evidence_id uuid PRIMARY KEY, assessment_id uuid NOT NULL REFERENCES assessment, tenant_id text NOT NULL,
    filename text NOT NULL, content_type text NOT NULL, size bigint NOT NULL, sha256 text NOT NULL, state text NOT NULL, injection_flagged boolean);
CREATE TABLE finding (assessment_id uuid NOT NULL REFERENCES assessment, rule_id text NOT NULL, tenant_id text NOT NULL, body jsonb NOT NULL,
    PRIMARY KEY (assessment_id, rule_id));
CREATE TABLE report (report_id uuid PRIMARY KEY, assessment_id uuid NOT NULL REFERENCES assessment, tenant_id text NOT NULL, status text NOT NULL,
    version int NOT NULL, findings_snapshot jsonb, published_digest text, review jsonb);
CREATE TABLE audit_log (id bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), sub text, tenant_id text, action text NOT NULL, ref text);
CREATE TABLE idempotency (sub text, op text, key text, response jsonb, PRIMARY KEY (sub, op, key));
CREATE TABLE outbox_event (event_id uuid PRIMARY KEY, tenant_id text NOT NULL, type text NOT NULL, envelope jsonb NOT NULL, published_at timestamptz);
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['assessment','answer','answer_revision','evidence','finding','report'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''taad.tenant_id'', true))', t);
  END LOOP;
END $$;
