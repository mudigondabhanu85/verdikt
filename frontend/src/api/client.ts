import type {
  AgentJobOut,
  AIProviderConfigOut,
  ApiKeyCreated,
  ApiKeyOut,
  AssetMetadataOut,
  AttackChainOut,
  BurpImportResult,
  BurpScanCreated,
  BusinessRuleOut,
  ChatbotAgencyProbeOut,
  ChatbotTargetOut,
  CMDBConfigOut,
  CredentialSetOut,
  DashboardOut,
  FindingTicketOut,
  LoginMacroOut,
  MacroReplayTestResult,
  RecordingStartedOut,
  NotificationConfigOut,
  FindingOut,
  FindingRetestStatus,
  HttpRequest,
  HttpResponse,
  OidcProviderConfigOut,
  OrgBrandingOut,
  OrganizationOut,
  ProjectOut,
  RetestJobOut,
  ReviewCandidateOut,
  SamlConfigOut,
  SamlIdpMetadataUpload,
  ConfirmationPhraseOut,
  PentestCommandOut,
  ScanRunDetail,
  ScanRunDiffOut,
  ScanRunOut,
  ScopeEntryOut,
  TargetOut,
  TestLoginResult,
  TicketingConfigOut,
  TokenResponse,
  TrafficImportResult,
  TrafficInteractionOut,
  UserInviteOut,
  UserOut,
  VersionOut,
  VGSConfigOut,
} from './types'

export const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'
// noVNC/websockify — see docker-compose.yml's backend.ports and
// start-display.sh. Used by MacroSection to stream the login-macro
// recorder's headed browser into an <iframe>, no extension needed.
export const VNC_BASE_URL = import.meta.env.VITE_VNC_BASE_URL ?? 'http://localhost:6080'
const TOKEN_KEY = 'verdikt_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
}

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

// A 401 means the token is gone/expired — no refresh flow exists
// server-side (see plan), so the only correct client behavior is to
// drop the stale token and bounce to /login rather than looping on a
// request that will never succeed.
function handleUnauthorized(): void {
  clearToken()
  if (window.location.pathname !== '/login') {
    window.location.href = '/login'
  }
}

async function request<T>(
  path: string,
  options: { method?: string; body?: unknown; formData?: FormData } = {},
): Promise<T> {
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`

  let body: BodyInit | undefined
  if (options.formData) {
    body = options.formData
  } else if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(options.body)
  }

  const response = await fetch(`${BASE_URL}${path}`, {
    method: options.method ?? 'GET',
    headers,
    body,
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new ApiError(401, 'Unauthorized')
  }

  if (!response.ok) {
    let detail = response.statusText
    try {
      const data = await response.json()
      detail = data.detail ?? detail
    } catch {
      // non-JSON error body — fall back to statusText
    }
    throw new ApiError(response.status, typeof detail === 'string' ? detail : JSON.stringify(detail))
  }

  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

// Same reasoning as downloadReport below — GET /objects/{key} requires
// the bearer token (app.api.routes.objects), so a plain <img src=...>
// gets a 401 on every request (a browser never attaches Authorization
// headers to image-tag fetches). Fetch the bytes ourselves and hand the
// caller an object: URL to put in an <img src>; caller must revoke it
// (e.g. on unmount) once done.
export async function fetchObjectBlobUrl(objectKey: string): Promise<string | null> {
  const token = getToken()
  const response = await fetch(`${BASE_URL}/objects/${objectKey}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!response.ok) return null
  const blob = await response.blob()
  return URL.createObjectURL(blob)
}

// Blob download for the four report formats — needs the bearer token
// on the request, so a plain <a href> won't work (no way to attach an
// Authorization header to a browser-navigated download).
export async function downloadReport(
  scanRunId: string,
  format: 'json' | 'html' | 'pdf' | 'docx' | 'csv' | 'vgs.docx',
): Promise<void> {
  const token = getToken()
  const response = await fetch(`${BASE_URL}/scan-runs/${scanRunId}/report.${format}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (response.status === 401) {
    handleUnauthorized()
    return
  }
  if (!response.ok) throw new ApiError(response.status, response.statusText)
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `scan-run-${scanRunId}-report.${format}`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

// Same reasoning as downloadReport above — this endpoint requires the
// bearer token, so a plain <a href> can't be used for it either.
export async function downloadSamlMetadata(configId: string): Promise<void> {
  const token = getToken()
  const response = await fetch(`${BASE_URL}/saml-configs/${configId}/metadata.xml`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (response.status === 401) {
    handleUnauthorized()
    return
  }
  if (!response.ok) throw new ApiError(response.status, response.statusText)
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `verdikt-sp-metadata-${configId}.xml`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

// Same reasoning as downloadReport/downloadSamlMetadata above — this
// endpoint requires the bearer token too, so a plain <a href> can't be
// used for it either.
export async function downloadBrowserExtension(): Promise<void> {
  const token = getToken()
  const response = await fetch(`${BASE_URL}/browser-extension/download`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (response.status === 401) {
    handleUnauthorized()
    return
  }
  if (!response.ok) throw new ApiError(response.status, response.statusText)
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'verdikt-login-macro-recorder.zip'
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export const api = {
  auth: {
    register: (body: { org_name: string; email: string; password: string }) =>
      request<TokenResponse>('/auth/register', { method: 'POST', body }),
    login: (body: { email: string; password: string }) =>
      request<TokenResponse>('/auth/login', { method: 'POST', body }),
    me: () => request<UserOut>('/auth/me'),
    changePassword: (body: { current_password: string; new_password: string }) =>
      request<void>('/auth/change-password', { method: 'POST', body }),
  },

  organizations: {
    me: () => request<OrganizationOut>('/organizations/me'),
    dashboard: () => request<DashboardOut>('/organizations/me/dashboard'),
  },

  projects: {
    list: (includeArchived = false) =>
      request<ProjectOut[]>(`/projects${includeArchived ? '?include_archived=true' : ''}`),
    get: (projectId: string) => request<ProjectOut>(`/projects/${projectId}`),
    create: (body: { name: string }) => request<ProjectOut>('/projects', { method: 'POST', body }),
    archive: (projectId: string) => request<void>(`/projects/${projectId}/archive`, { method: 'POST' }),
    unarchive: (projectId: string) => request<void>(`/projects/${projectId}/unarchive`, { method: 'POST' }),
    delete: (projectId: string) => request<void>(`/projects/${projectId}`, { method: 'DELETE' }),
  },

  users: {
    list: () => request<UserOut[]>('/users'),
    invite: (body: { email: string; role: string }) =>
      request<UserInviteOut>('/users/invite', { method: 'POST', body }),
    acceptInvite: (body: { invite_token: string; password: string }) =>
      request<TokenResponse>('/users/accept-invite', { method: 'POST', body }),
    deactivate: (userId: string) => request<void>(`/users/${userId}/deactivate`, { method: 'POST' }),
    reactivate: (userId: string) => request<void>(`/users/${userId}/reactivate`, { method: 'POST' }),
  },

  versions: {
    list: (projectId: string) => request<VersionOut[]>(`/projects/${projectId}/versions`),
    get: (versionId: string) => request<VersionOut>(`/versions/${versionId}`),
    create: (projectId: string, body: { name: string }) =>
      request<VersionOut>(`/projects/${projectId}/versions`, { method: 'POST', body }),

    listScopeEntries: (versionId: string) => request<ScopeEntryOut[]>(`/versions/${versionId}/scope-entries`),
    createScopeEntry: (
      versionId: string,
      body: { host: string; port?: number | null; path_pattern?: string | null; in_scope?: boolean },
    ) => request<ScopeEntryOut>(`/versions/${versionId}/scope-entries`, { method: 'POST', body }),
    updateScopeEntry: (
      versionId: string,
      scopeEntryId: string,
      body: Partial<{ host: string; port: number | null; path_pattern: string | null; in_scope: boolean }>,
    ) =>
      request<ScopeEntryOut>(`/versions/${versionId}/scope-entries/${scopeEntryId}`, {
        method: 'PATCH',
        body,
      }),
    deleteScopeEntry: (versionId: string, scopeEntryId: string) =>
      request<void>(`/versions/${versionId}/scope-entries/${scopeEntryId}`, { method: 'DELETE' }),
  },

  targets: {
    list: (versionId: string) => request<TargetOut[]>(`/versions/${versionId}/targets`),
    create: (versionId: string, body: { host: string; port?: number | null; base_url?: string | null }) =>
      request<TargetOut>(`/versions/${versionId}/targets`, { method: 'POST', body }),
    delete: (versionId: string, targetId: string) =>
      request<void>(`/versions/${versionId}/targets/${targetId}`, { method: 'DELETE' }),
  },

  credentials: {
    list: (versionId: string) => request<CredentialSetOut[]>(`/versions/${versionId}/credentials`),
    create: (
      versionId: string,
      body: {
        label: string
        credential_type?: string
        username: string
        secret: string
        login_endpoint?: string | null
        login_method?: string | null
        login_body_template?: string | null
        login_content_type?: string | null
        token_response_path?: string | null
        extra_cookies?: Record<string, string> | null
        extra_headers?: Record<string, string> | null
        privilege_rank?: number | null
      },
    ) => request<CredentialSetOut>(`/versions/${versionId}/credentials`, { method: 'POST', body }),
    update: (
      versionId: string,
      credentialId: string,
      body: {
        label?: string
        credential_type?: string
        username?: string
        secret?: string
        login_endpoint?: string | null
        login_method?: string | null
        login_body_template?: string | null
        login_content_type?: string | null
        token_response_path?: string | null
        extra_cookies?: Record<string, string> | null
        extra_headers?: Record<string, string> | null
        privilege_rank?: number | null
      },
    ) =>
      request<CredentialSetOut>(`/versions/${versionId}/credentials/${credentialId}`, {
        method: 'PATCH',
        body,
      }),
    delete: (versionId: string, credentialId: string) =>
      request<void>(`/versions/${versionId}/credentials/${credentialId}`, { method: 'DELETE' }),
    uploadMacro: (versionId: string, credentialId: string, body: { steps: Record<string, unknown>[] }) =>
      request<LoginMacroOut>(`/versions/${versionId}/credentials/${credentialId}/macros/upload`, {
        method: 'POST',
        body,
      }),
    // Split into start/finish (not one blocking call) — see
    // MacroSection.tsx and app/api/routes/credentials.py's
    // start_recording_macro docstring for why: relying on the analyst
    // finding and clicking the *remote*, VNC-streamed browser window's
    // own close button turned out to silently lose recordings. The
    // Verdikt UI itself now streams that browser live and has its own
    // "Finish recording" button, which calls finishRecordingMacro.
    startRecordingMacro: (versionId: string, credentialId: string, body: { start_url: string }) =>
      request<RecordingStartedOut>(`/versions/${versionId}/credentials/${credentialId}/record-macro/start`, {
        method: 'POST',
        body,
      }),
    finishRecordingMacro: (versionId: string, credentialId: string, recordingId: string) =>
      request<LoginMacroOut>(
        `/versions/${versionId}/credentials/${credentialId}/record-macro/${recordingId}/finish`,
        { method: 'POST' },
      ),
    cancelRecordingMacro: (versionId: string, credentialId: string, recordingId: string) =>
      request<void>(`/versions/${versionId}/credentials/${credentialId}/record-macro/${recordingId}/cancel`, {
        method: 'POST',
      }),
    listMacros: (versionId: string, credentialId: string) =>
      request<LoginMacroOut[]>(`/versions/${versionId}/credentials/${credentialId}/macros`),
    deleteMacro: (versionId: string, credentialId: string, macroId: string) =>
      request<void>(`/versions/${versionId}/credentials/${credentialId}/macros/${macroId}`, {
        method: 'DELETE',
      }),
    replayMacro: (versionId: string, credentialId: string, macroId: string) =>
      request<MacroReplayTestResult>(
        `/versions/${versionId}/credentials/${credentialId}/macros/${macroId}/replay`,
        { method: 'POST' },
      ),
    testLogin: (versionId: string, credentialId: string) =>
      request<TestLoginResult>(`/versions/${versionId}/credentials/${credentialId}/test-login`, {
        method: 'POST',
      }),
  },

  businessRules: {
    list: (versionId: string) => request<BusinessRuleOut[]>(`/versions/${versionId}/business-rules`),
    create: (versionId: string, body: { rule_type: string; title: string; config: Record<string, unknown> }) =>
      request<BusinessRuleOut>(`/versions/${versionId}/business-rules`, { method: 'POST', body }),
    delete: (versionId: string, ruleId: string) =>
      request<void>(`/versions/${versionId}/business-rules/${ruleId}`, { method: 'DELETE' }),
  },

  chatbotTargets: {
    list: (versionId: string) => request<ChatbotTargetOut[]>(`/versions/${versionId}/chatbot-targets`),
    create: (
      versionId: string,
      body: {
        label: string
        endpoint_url: string
        http_method: string
        request_body_template: string
        content_type: string
        response_text_path: string
        auth_header_name?: string | null
        auth_header_value?: string | null
      },
    ) => request<ChatbotTargetOut>(`/versions/${versionId}/chatbot-targets`, { method: 'POST', body }),
    delete: (versionId: string, targetId: string) =>
      request<void>(`/versions/${versionId}/chatbot-targets/${targetId}`, { method: 'DELETE' }),
  },

  chatbotAgencyProbes: {
    list: (versionId: string, targetId: string) =>
      request<ChatbotAgencyProbeOut[]>(`/versions/${versionId}/chatbot-targets/${targetId}/agency-probes`),
    create: (versionId: string, targetId: string, body: { forbidden_action: string }) =>
      request<ChatbotAgencyProbeOut>(`/versions/${versionId}/chatbot-targets/${targetId}/agency-probes`, {
        method: 'POST',
        body,
      }),
    delete: (versionId: string, targetId: string, probeId: string) =>
      request<void>(`/versions/${versionId}/chatbot-targets/${targetId}/agency-probes/${probeId}`, {
        method: 'DELETE',
      }),
  },

  scanRuns: {
    list: (versionId: string) => request<ScanRunOut[]>(`/versions/${versionId}/scan-runs`),
    get: (scanRunId: string) => request<ScanRunDetail>(`/scan-runs/${scanRunId}`),
    create: (versionId: string, body?: { ai_provider_config_id?: string | null }) =>
      request<ScanRunOut>(`/versions/${versionId}/scan-runs`, { method: 'POST', body: body ?? {} }),
    retest: (versionId: string, priorScanRunId: string) =>
      request<ScanRunOut>(`/versions/${versionId}/scan-runs/${priorScanRunId}/retest`, { method: 'POST' }),
    findings: (scanRunId: string) => request<FindingOut[]>(`/scan-runs/${scanRunId}/findings`),
    diff: (laterScanRunId: string, earlierScanRunId: string) =>
      request<ScanRunDiffOut>(`/scan-runs/${laterScanRunId}/diff/${earlierScanRunId}`),
    cancel: (scanRunId: string) => request<ScanRunOut>(`/scan-runs/${scanRunId}/cancel`, { method: 'POST' }),
    delete: (scanRunId: string) => request<void>(`/scan-runs/${scanRunId}`, { method: 'DELETE' }),
  },

  // The AI-driven autonomous pentest mode (mode="autonomous_ai" on the
  // same ScanRun/AgentJob shape scanRuns above already uses) — a real
  // shell/CLI tool-use loop against a network-isolated sandbox, not the
  // deterministic per-check agents. See backend/app/api/routes/
  // autonomous_pentest.py.
  autonomousPentest: {
    confirmationPhrase: (versionId: string) =>
      request<ConfirmationPhraseOut>(`/versions/${versionId}/autonomous-pentest-sessions/confirmation-phrase`),
    create: (
      versionId: string,
      body: { confirmation_text: string; objective: string; credential_id?: string | null },
    ) => request<ScanRunOut>(`/versions/${versionId}/autonomous-pentest-sessions`, { method: 'POST', body }),
    commands: (scanRunId: string) => request<PentestCommandOut[]>(`/scan-runs/${scanRunId}/pentest-commands`),
  },

  findings: {
    // An analyst's own disposition after reviewing a Finding — mark it
    // a false positive or an accepted risk (both "analyst-locked": a
    // later rescan won't silently reopen them just because the same
    // signal reproduced), or reopen one. See
    // app/api/routes/findings.py.
    updateStatus: (findingId: string, retest_status: FindingRetestStatus) =>
      request<FindingOut>(`/findings/${findingId}`, { method: 'PATCH', body: { retest_status } }),
    delete: (findingId: string) => request<void>(`/findings/${findingId}`, { method: 'DELETE' }),
  },

  retestJobs: {
    // Synchronous — the response IS the completed (or failed/
    // not_supported) job, not a "started" placeholder to poll. See
    // app/api/routes/retest_jobs.py: every registered check is one
    // HTTP request or one real-browser page load, not a full scan.
    trigger: (findingId: string) => request<RetestJobOut>(`/findings/${findingId}/retest`, { method: 'POST' }),
    list: (findingId: string) => request<RetestJobOut[]>(`/findings/${findingId}/retest-jobs`),
  },

  reviewCandidates: {
    list: (scanRunId: string) => request<ReviewCandidateOut[]>(`/scan-runs/${scanRunId}/review-candidates`),
    promote: (candidateId: string) =>
      request<FindingOut>(`/review-candidates/${candidateId}/promote`, { method: 'POST' }),
    dismiss: (candidateId: string) =>
      request<ReviewCandidateOut>(`/review-candidates/${candidateId}/dismiss`, { method: 'POST' }),
  },

  apiKeys: {
    list: () => request<ApiKeyOut[]>('/api-keys'),
    create: (body: { label: string }) => request<ApiKeyCreated>('/api-keys', { method: 'POST', body }),
    revoke: (id: string) => request<ApiKeyOut>(`/api-keys/${id}/revoke`, { method: 'POST' }),
  },

  aiProviderConfigs: {
    list: () => request<AIProviderConfigOut[]>('/ai-provider-configs'),
    create: (body: {
      label: string
      provider: string
      model: string
      api_key: string
      base_url?: string
      auth_type?: string
    }) => request<AIProviderConfigOut>('/ai-provider-configs', { method: 'POST', body }),
    setDefault: (id: string) =>
      request<AIProviderConfigOut>(`/ai-provider-configs/${id}/set-default`, { method: 'POST' }),
    rotateSecret: (id: string, body: { api_key?: string }) =>
      request<AIProviderConfigOut>(`/ai-provider-configs/${id}/rotate-secret`, { method: 'POST', body }),
    delete: (id: string) => request<void>(`/ai-provider-configs/${id}`, { method: 'DELETE' }),
  },

  traffic: {
    list: (versionId: string) => request<TrafficInteractionOut[]>(`/versions/${versionId}/traffic`),
    importFile: (versionId: string, file: File) => {
      const formData = new FormData()
      formData.set('file', file)
      return request<TrafficImportResult>(`/versions/${versionId}/traffic/import`, { method: 'POST', formData })
    },
    addManual: (
      versionId: string,
      body: {
        request: HttpRequest
        response: HttpResponse
        credential_set_id?: string | null
        timestamp?: string | null
      },
    ) => request<TrafficInteractionOut>(`/versions/${versionId}/traffic/manual`, { method: 'POST', body }),
    deleteInteraction: (versionId: string, interactionId: string) =>
      request<void>(`/versions/${versionId}/traffic/${interactionId}`, { method: 'DELETE' }),
    // `source` clears just one import type (e.g. "har") without
    // touching manually-added entries or other imports — there's no
    // import-batch id (each imported exchange is its own row), so this
    // is the practical "delete what I just uploaded" action. Omit it
    // to clear everything for this version.
    clearAll: (versionId: string, source?: string) =>
      request<void>(
        `/versions/${versionId}/traffic${source ? `?source=${encodeURIComponent(source)}` : ''}`,
        { method: 'DELETE' },
      ),
  },

  burp: {
    // startScan returns fast (just triggers the scan on Burp's side).
    // importResults does NOT — app/api/routes/burp.py's import route
    // blocks the whole HTTP request until Burp's scan reaches a
    // terminal state (poll_interval/timeout are passed straight
    // through to that server-side polling loop). There's no separate
    // status-check endpoint to poll instead — see BurpTab's warning
    // copy for why the UI just shows a spinner for however long that
    // takes.
    startScan: (
      versionId: string,
      body: { burp_base_url: string; burp_api_key?: string; urls: string[]; scan_configurations?: string[] },
    ) => request<BurpScanCreated>(`/versions/${versionId}/burp/scans`, { method: 'POST', body }),
    importResults: (
      versionId: string,
      taskId: string,
      body: {
        burp_base_url: string
        burp_api_key?: string
        scan_run_id: string
        poll_interval?: number
        timeout?: number
      },
    ) => request<BurpImportResult>(`/versions/${versionId}/burp/scans/${taskId}/import`, { method: 'POST', body }),
  },

  notificationConfigs: {
    list: () => request<NotificationConfigOut[]>('/notification-configs'),
    create: (body: {
      label: string
      provider: string
      webhook_url?: string
      smtp_host?: string
      smtp_port?: number
      smtp_username?: string
      smtp_password?: string
      from_address?: string
      to_address?: string
      notify_on_scan_completed?: boolean
    }) => request<NotificationConfigOut>('/notification-configs', { method: 'POST', body }),
    delete: (id: string) => request<void>(`/notification-configs/${id}`, { method: 'DELETE' }),
    test: (id: string) => request<void>(`/notification-configs/${id}/test`, { method: 'POST' }),
  },

  ticketingConfigs: {
    list: () => request<TicketingConfigOut[]>('/ticketing-configs'),
    create: (body: {
      label: string
      provider: string
      base_url: string
      email: string
      api_token: string
      project_key: string
      issue_type?: string
    }) => request<TicketingConfigOut>('/ticketing-configs', { method: 'POST', body }),
    delete: (id: string) => request<void>(`/ticketing-configs/${id}`, { method: 'DELETE' }),
  },

  findingTickets: {
    list: (findingId: string) => request<FindingTicketOut[]>(`/findings/${findingId}/tickets`),
    create: (findingId: string, ticketingConfigId: string) =>
      request<FindingTicketOut>(`/findings/${findingId}/tickets`, {
        method: 'POST',
        body: { ticketing_config_id: ticketingConfigId },
      }),
  },

  cmdbConfigs: {
    list: () => request<CMDBConfigOut[]>('/cmdb-configs'),
    create: (body: {
      label: string
      provider: string
      lookup_url_template: string
      auth_header_name?: string
      auth_header_value: string
      owner_json_path: string
      criticality_json_path: string
    }) => request<CMDBConfigOut>('/cmdb-configs', { method: 'POST', body }),
    delete: (id: string) => request<void>(`/cmdb-configs/${id}`, { method: 'DELETE' }),
    lookup: (id: string, identifier: string) =>
      request<AssetMetadataOut>(`/cmdb-configs/${id}/lookup`, { method: 'POST', body: { identifier } }),
  },

  vgsConfigs: {
    list: () => request<VGSConfigOut[]>('/vgs-configs'),
    create: (body: {
      label: string
      webhook_url: string
      push_on_scan_completed?: boolean
      auth_type?: string | null
      auth_value?: string | null
    }) => request<VGSConfigOut>('/vgs-configs', { method: 'POST', body }),
    delete: (id: string) => request<void>(`/vgs-configs/${id}`, { method: 'DELETE' }),
    test: (id: string) => request<void>(`/vgs-configs/${id}/test`, { method: 'POST' }),
  },

  samlConfigs: {
    list: () => request<SamlConfigOut[]>('/saml-configs'),
    create: (body: { label: string }) => request<SamlConfigOut>('/saml-configs', { method: 'POST', body }),
    delete: (id: string) => request<void>(`/saml-configs/${id}`, { method: 'DELETE' }),
    uploadIdpMetadata: (id: string, body: SamlIdpMetadataUpload) =>
      request<SamlConfigOut>(`/saml-configs/${id}/idp-metadata`, { method: 'POST', body }),
  },

  orgBranding: {
    get: () => request<OrgBrandingOut>('/org-branding'),
    update: (body: { company_name?: string | null; primary_color_hex?: string | null }) =>
      request<OrgBrandingOut>('/org-branding', { method: 'PUT', body }),
    uploadLogo: (file: File) => {
      const formData = new FormData()
      formData.set('logo', file)
      return request<OrgBrandingOut>('/org-branding/logo', { method: 'POST', formData })
    },
    deleteLogo: () => request<OrgBrandingOut>('/org-branding/logo', { method: 'DELETE' }),
  },

  attackChains: {
    list: (scanRunId: string) => request<AttackChainOut[]>(`/scan-runs/${scanRunId}/attack-chains`),
  },

  oidcProviderConfigs: {
    // Authenticated, org-scoped (see app/api/routes/oidc.py) — an
    // org_admin manages these from AccountPage. There's no public
    // "list SSO providers for org X" endpoint, so the login page can't
    // discover configs on its own; an admin shares each config's
    // sign-in link (built client-side as /login?sso={id}) with their
    // users instead. See LoginPage.tsx.
    list: () => request<OidcProviderConfigOut[]>('/oidc-provider-configs'),
    create: (body: {
      label: string
      issuer: string
      client_id: string
      client_secret: string
      redirect_uri: string
      default_role?: string
    }) => request<OidcProviderConfigOut>('/oidc-provider-configs', { method: 'POST', body }),
    delete: (id: string) => request<void>(`/oidc-provider-configs/${id}`, { method: 'DELETE' }),
  },
}

// The OIDC login redirect is a full top-level browser navigation, not
// a fetch — the browser has to actually leave the SPA to visit the
// IdP. See OidcCallbackPage for the other half of this flow (reading
// the token back out of the redirect fragment).
export function oidcLoginUrl(configId: string): string {
  return `${BASE_URL}/auth/oidc/${configId}/login`
}

export type { AgentJobOut }
