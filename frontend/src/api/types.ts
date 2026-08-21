// Mirrors app/schemas/*.py exactly — field names/optionality kept 1:1
// with the Pydantic response models so the API client needs no mapping
// layer.

export const BASELINE_ROLES = ['org_admin', 'project_lead', 'analyst', 'viewer'] as const
export type Role = (typeof BASELINE_ROLES)[number]

export interface UserOut {
  id: string
  org_id: string
  email: string
  role: Role
  is_active: boolean
}

export interface TokenResponse {
  access_token: string
  token_type: string
}

export interface OrganizationOut {
  id: string
  name: string
  created_at: string
}

export interface ProjectOut {
  id: string
  org_id: string
  name: string
  created_at: string
}

export interface VersionOut {
  id: string
  project_id: string
  name: string
  created_at: string
  is_authorized: boolean
}

export interface ScopeEntryOut {
  id: string
  version_id: string
  host: string
  port: number | null
  path_pattern: string | null
  in_scope: boolean
}

export interface AuthorizationRecordOut {
  id: string
  version_id: string
  approver_name: string
  attestation_text: string | null
  letter_object_key: string | null
  attested_by: string
  attested_at: string
}

export interface TargetOut {
  id: string
  version_id: string
  host: string
  port: number | null
  base_url: string | null
}

export interface CredentialSetOut {
  id: string
  version_id: string
  label: string
  credential_type: string
  masked_reference: string
  login_endpoint: string | null
  login_method: string | null
  token_response_path: string | null
}

export const BUSINESS_RULE_TYPES = [
  'resource_isolation',
  'workflow_order',
  'price_or_quantity_tampering',
  'race_condition_limited_use',
] as const
export type BusinessRuleType = (typeof BUSINESS_RULE_TYPES)[number]

export interface BusinessRuleOut {
  id: string
  version_id: string
  rule_type: BusinessRuleType
  title: string
  config: Record<string, unknown>
}

// Mirrors app/schemas/business_rule.py's per-rule-type config shapes
// exactly — one bespoke form per type in pages/version/business-rules/
// builds these directly instead of asking the analyst to hand-write JSON.
export interface HttpCallConfig {
  method: string
  url: string
  body?: string | null
  content_type?: string | null
}

export interface ResourceIsolationConfig {
  url: string
  method: string
}

export interface WorkflowOrderConfig {
  precondition: HttpCallConfig
  guarded_action: HttpCallConfig
  credential_set_id?: string | null
}

export interface PriceOrQuantityTamperingConfig {
  method: string
  url: string
  body_template: string
  content_type: string
  baseline_value: string
  tamper_values?: string[] | null
  credential_set_id?: string | null
}

export interface RaceConditionConfig {
  method: string
  url: string
  body?: string | null
  content_type: string
  concurrency: number
  max_allowed_successes: number
  credential_set_id?: string | null
}

export type ScanRunStatus = 'running' | 'completed' | 'failed'

export interface ScanRunOut {
  id: string
  version_id: string
  status: ScanRunStatus
  started_at: string | null
  completed_at: string | null
  error: string | null
  ai_provider_config_id: string | null
}

export interface AgentJobOut {
  id: string
  agent_type: string
  status: string
  started_at: string | null
  completed_at: string | null
  error: string | null
  stats: Record<string, unknown> | null
}

export interface ScanRunDetail extends ScanRunOut {
  agent_jobs: AgentJobOut[]
  finding_counts_by_severity: Record<string, number>
  tech_stack_fingerprint: Record<string, unknown> | null
}

export interface EvidenceOut {
  request_raw: string
  response_raw: string
  screenshot_refs: string[]
  additional_notes: string | null
}

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

export interface FindingOut {
  id: string
  check_id: string
  title: string
  severity: Severity
  owasp_2025_category: string
  cwe_id: string
  portswigger_reference_url: string | null
  cvss_vector: string
  cvss_score: number
  affected_endpoints: string[]
  plain_language_summary: string
  technical_description: string
  steps_to_reproduce: string[]
  remediation: string
  references: string[]
  confirmation_status: string
  retest_status: string
  evidence: EvidenceOut | null
}

export type ReviewCandidateStatus = 'pending' | 'promoted' | 'dismissed'

export interface ReviewCandidateOut {
  id: string
  scan_run_id: string
  agent_job_id: string
  check_type: string
  title: string
  severity_guess: string
  affected_endpoint: string
  request_raw: string
  response_raw: string
  llm_reasoning: string
  llm_confidence: string
  status: ReviewCandidateStatus
}

export interface ApiKeyCreated {
  id: string
  label: string
  api_key: string
  key_prefix: string
}

export interface ApiKeyOut {
  id: string
  label: string
  key_prefix: string
  last_used_at: string | null
  revoked_at: string | null
}

export const AI_PROVIDER_TYPES = ['claude', 'openai', 'custom'] as const
export type AiProviderType = (typeof AI_PROVIDER_TYPES)[number]

export interface AIProviderConfigOut {
  id: string
  org_id: string
  label: string
  provider: AiProviderType
  model: string
  base_url: string | null
  masked_reference: string
}

export interface OidcProviderConfigOut {
  id: string
  org_id: string
  label: string
  issuer: string
  client_id: string
  redirect_uri: string
  default_role: Role
}
