import type {
  AgentJobOut,
  AIProviderConfigOut,
  ApiKeyCreated,
  ApiKeyOut,
  AuthorizationRecordOut,
  BusinessRuleOut,
  CredentialSetOut,
  FindingOut,
  HttpRequest,
  HttpResponse,
  OidcProviderConfigOut,
  OrganizationOut,
  ProjectOut,
  ReviewCandidateOut,
  ScanRunDetail,
  ScanRunOut,
  ScopeEntryOut,
  TargetOut,
  TokenResponse,
  TrafficImportResult,
  TrafficInteractionOut,
  UserOut,
  VersionOut,
} from './types'

export const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'
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

// Blob download for the four report formats — needs the bearer token
// on the request, so a plain <a href> won't work (no way to attach an
// Authorization header to a browser-navigated download).
export async function downloadReport(scanRunId: string, format: 'json' | 'html' | 'pdf' | 'docx'): Promise<void> {
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

export const api = {
  auth: {
    register: (body: { org_name: string; email: string; password: string }) =>
      request<TokenResponse>('/auth/register', { method: 'POST', body }),
    login: (body: { email: string; password: string }) =>
      request<TokenResponse>('/auth/login', { method: 'POST', body }),
    me: () => request<UserOut>('/auth/me'),
  },

  organizations: {
    me: () => request<OrganizationOut>('/organizations/me'),
  },

  projects: {
    list: () => request<ProjectOut[]>('/projects'),
    get: (projectId: string) => request<ProjectOut>(`/projects/${projectId}`),
    create: (body: { name: string }) => request<ProjectOut>('/projects', { method: 'POST', body }),
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

    listAuthorizationRecords: (versionId: string) =>
      request<AuthorizationRecordOut[]>(`/versions/${versionId}/authorization`),
    addAuthorizationRecord: (
      versionId: string,
      body: { approver_name: string; attestation_text?: string; letter?: File },
    ) => {
      const formData = new FormData()
      formData.set('approver_name', body.approver_name)
      if (body.attestation_text) formData.set('attestation_text', body.attestation_text)
      if (body.letter) formData.set('letter', body.letter)
      return request<AuthorizationRecordOut>(`/versions/${versionId}/authorization`, {
        method: 'POST',
        formData,
      })
    },
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
      },
    ) => request<CredentialSetOut>(`/versions/${versionId}/credentials`, { method: 'POST', body }),
    delete: (versionId: string, credentialId: string) =>
      request<void>(`/versions/${versionId}/credentials/${credentialId}`, { method: 'DELETE' }),
  },

  businessRules: {
    list: (versionId: string) => request<BusinessRuleOut[]>(`/versions/${versionId}/business-rules`),
    create: (versionId: string, body: { rule_type: string; title: string; config: Record<string, unknown> }) =>
      request<BusinessRuleOut>(`/versions/${versionId}/business-rules`, { method: 'POST', body }),
    delete: (versionId: string, ruleId: string) =>
      request<void>(`/versions/${versionId}/business-rules/${ruleId}`, { method: 'DELETE' }),
  },

  scanRuns: {
    list: (versionId: string) => request<ScanRunOut[]>(`/versions/${versionId}/scan-runs`),
    get: (scanRunId: string) => request<ScanRunDetail>(`/scan-runs/${scanRunId}`),
    create: (versionId: string, body?: { ai_provider_config_id?: string | null }) =>
      request<ScanRunOut>(`/versions/${versionId}/scan-runs`, { method: 'POST', body: body ?? {} }),
    retest: (versionId: string, priorScanRunId: string) =>
      request<ScanRunOut>(`/versions/${versionId}/scan-runs/${priorScanRunId}/retest`, { method: 'POST' }),
    findings: (scanRunId: string) => request<FindingOut[]>(`/scan-runs/${scanRunId}/findings`),
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
    create: (body: { label: string; provider: string; model: string; api_key: string; base_url?: string }) =>
      request<AIProviderConfigOut>('/ai-provider-configs', { method: 'POST', body }),
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
