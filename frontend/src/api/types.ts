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
  invited_at: string | null
  invite_accepted_at: string | null
}

export interface UserInviteOut {
  id: string
  email: string
  role: Role
  invite_token: string
  invited_at: string
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
  archived_at: string | null
}

export interface VersionOut {
  id: string
  project_id: string
  name: string
  created_at: string
}

export interface ScopeEntryOut {
  id: string
  version_id: string
  host: string
  port: number | null
  path_pattern: string | null
  in_scope: boolean
  // "target" (a real scan target) or "login_only" (auto-added only so a
  // login POST could reach a third-party IdP — never sent fuzzing
  // payloads even though it's technically in scope).
  purpose: string
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
  extra_cookies: Record<string, string> | null
  extra_headers: Record<string, string> | null
  privilege_rank: number | null
}

export interface TestLoginResult {
  session_established: boolean
  test_request_url: string | null
  test_request_status: number | null
  ok: boolean
  message: string
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
  source: 'analyst' | 'ai_generated'
}

// Mirrors app/schemas/chatbot_target.py's ChatbotTargetOut — a
// conversational endpoint for chatbot/LLM prompt-injection testing
// (app.agents.chatbot_injection). No auto-discovery is possible, so this
// is always hand-authored, the same reason CredentialSet is.
export interface ChatbotTargetOut {
  id: string
  version_id: string
  label: string
  endpoint_url: string
  http_method: string
  content_type: string
  response_text_path: string
  auth_header_name: string | null
  masked_reference: string | null
}

// Mirrors app/schemas/chatbot_agency_probe.py's ChatbotAgencyProbeOut —
// an analyst's plain-language description of an action one specific
// ChatbotTarget should never agree to/perform (LLM03 Excessive Agency).
export interface ChatbotAgencyProbeOut {
  id: string
  chatbot_target_id: string
  forbidden_action: string
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

export type ScanRunStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'

export interface ScanRunOut {
  id: string
  version_id: string
  status: ScanRunStatus
  started_at: string | null
  completed_at: string | null
  error: string | null
  warning: string | null
  ai_provider_config_id: string | null
  llm_cost_usd: string
  llm_input_tokens: number
  llm_output_tokens: number
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

export interface ScanRunDiffOut {
  earlier_scan_run_id: string
  later_scan_run_id: string
  new_findings: FindingOut[]
  fixed_findings: FindingOut[]
  still_open_findings: FindingOut[]
}

export interface DashboardScanRunSummary {
  id: string
  version_id: string
  project_name: string
  version_name: string
  status: string
  started_at: string | null
  completed_at: string | null
  finding_counts_by_severity: Record<string, number>
}

export interface DashboardOut {
  total_projects: number
  total_versions: number
  total_scan_runs: number
  open_findings_by_severity: Record<string, number>
  recent_scan_runs: DashboardScanRunSummary[]
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
  // The exact substring (payload, marker, etc.) proving the finding
  // within request_raw/response_raw — highlight occurrences of this in
  // the UI the same way the downloadable HTML/PDF/DOCX reports already
  // do. Null for findings with no single distinguishing substring (most
  // header/config-only checks).
  payload: string | null
}

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

export type FindingRetestStatus = 'open' | 'fixed' | 'risk_accepted' | 'false_positive_after_review'

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
  retest_status: FindingRetestStatus
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

export const AI_PROVIDER_TYPES = ['claude', 'openai', 'gemini', 'grok', 'custom'] as const
export type AiProviderType = (typeof AI_PROVIDER_TYPES)[number]
export const AI_PROVIDER_AUTH_TYPES = ['api_key', 'bearer_token'] as const
export type AiProviderAuthType = (typeof AI_PROVIDER_AUTH_TYPES)[number]

export interface AIProviderConfigOut {
  id: string
  org_id: string
  label: string
  provider: AiProviderType
  model: string
  base_url: string | null
  auth_type: AiProviderAuthType
  masked_reference: string
  is_default: boolean
  // When the secret was last created/rotated, shown so an analyst can
  // see at a glance how stale a stored key/token is.
  secret_rotated_at: string | null
}

export const TRAFFIC_SOURCES = [
  'manual',
  'burp_live',
  'har',
  'burp_file',
  'zst_traffic',
  'webinspect_macro',
  'agent',
] as const
export type TrafficSource = (typeof TRAFFIC_SOURCES)[number]

export interface HttpRequest {
  method: string
  url: string
  headers: Record<string, string>
  query_params: Record<string, string>
  body: string | null
}

export interface HttpResponse {
  status: number | null
  headers: Record<string, string> | null
  body: string | null
  timing_ms: number | null
}

export interface TrafficInteractionOut {
  id: string
  version_id: string
  source: TrafficSource
  timestamp: string
  request: HttpRequest
  response: HttpResponse
  credential_set_id: string | null
}

export interface TrafficImportResult {
  imported_count: number
  interaction_ids: string[]
}

export type RetestResult = 'still_vulnerable' | 'fixed' | 'not_supported' | 'error'

export interface RetestJobOut {
  id: string
  finding_id: string
  status: string
  result: RetestResult | null
  created_at: string
  completed_at: string | null
  request_raw: string | null
  response_raw: string | null
  error: string | null
}

export interface LoginMacroOut {
  id: string
  version_id: string
  credential_set_id: string
  step_count: number
  created_at: string
}

export interface RecordingStartedOut {
  recording_id: string
}

export interface BurpScanCreated {
  scan_run_id: string
  agent_job_id: string
  task_id: string
}

export interface BurpImportResult {
  scan_status: string
  imported_count: number
  finding_ids: string[]
}

export const NOTIFICATION_PROVIDER_TYPES = ['slack', 'teams', 'outlook'] as const
export type NotificationProviderType = (typeof NOTIFICATION_PROVIDER_TYPES)[number]

export interface NotificationConfigOut {
  id: string
  org_id: string
  label: string
  provider: NotificationProviderType
  masked_reference: string
  notify_on_scan_completed: boolean
}

export interface NotificationConfigCreate {
  label: string
  provider: NotificationProviderType
  webhook_url?: string | null
  smtp_host?: string | null
  smtp_port?: number | null
  smtp_username?: string | null
  smtp_password?: string | null
  from_address?: string | null
  to_address?: string | null
  notify_on_scan_completed?: boolean
}

export const TICKETING_PROVIDER_TYPES = ['jira'] as const
export type TicketingProviderType = (typeof TICKETING_PROVIDER_TYPES)[number]

export interface TicketingConfigOut {
  id: string
  org_id: string
  label: string
  provider: TicketingProviderType
  base_url: string
  email: string
  masked_reference: string
  project_key: string
  issue_type: string
}

export interface FindingTicketOut {
  id: string
  finding_id: string
  ticketing_config_id: string
  external_key: string
  external_url: string
}

export const CMDB_PROVIDER_TYPES = ['generic_rest'] as const
export type CMDBProviderType = (typeof CMDB_PROVIDER_TYPES)[number]

export interface CMDBConfigOut {
  id: string
  org_id: string
  label: string
  provider: CMDBProviderType
  lookup_url_template: string
  auth_header_name: string
  masked_reference: string
  owner_json_path: string
  criticality_json_path: string
}

export interface AssetMetadataOut {
  identifier: string
  owner: string | null
  criticality: string | null
  raw: Record<string, unknown>
}

export const VGS_AUTH_TYPES = ['api_key', 'bearer_token', 'basic'] as const
export type VgsAuthType = (typeof VGS_AUTH_TYPES)[number]

export interface VGSConfigOut {
  id: string
  org_id: string
  label: string
  masked_reference: string
  push_on_scan_completed: boolean
  auth_type: VgsAuthType | null
  masked_auth_reference: string | null
}

export interface VGSConfigCreate {
  label: string
  webhook_url: string
  push_on_scan_completed?: boolean
  auth_type?: VgsAuthType | null
  auth_value?: string | null
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

export interface SamlConfigOut {
  id: string
  org_id: string
  label: string
  idp_sso_url: string | null
  idp_entity_id: string | null
  has_idp_metadata: boolean
}

export interface SamlIdpMetadataUpload {
  idp_metadata_xml?: string | null
  idp_sso_url?: string | null
  idp_entity_id?: string | null
  idp_x509_cert?: string | null
}

export interface OrgBrandingOut {
  org_id: string
  logo_object_key: string | null
  company_name: string | null
  primary_color_hex: string | null
}

export interface AttackChainEvidenceOut {
  request_raw: string
  response_raw: string
  screenshot_refs: string[]
  additional_notes: string | null
}

export interface AttackChainOut {
  id: string
  scan_run_id: string
  title: string
  severity: Severity
  finding_ids: string[]
  plain_language_summary: string
  narrative: string
  steps_to_reproduce: string[]
  references: string[]
  confirmation_status: string
  created_at: string
  evidence: AttackChainEvidenceOut | null
}
