// Local API surface for the VGS report-builder tabs (native port of the
// user's standalone VGS tool's manual-report-builder workflow). Mirrors
// ../../../api/client.ts's exact request/download conventions, but lives
// here rather than in the shared client.ts/types.ts since another
// concurrent work stream owns those files this round — safe to promote
// into the shared files later.

import { ApiError, BASE_URL, getToken } from '../../../api/client'

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

export interface VgsVulnerabilityLibraryEntryOut {
  id: string
  org_id: string
  title: string
  severity: Severity
  cvss_score: string
  cvss_vector: string
  description: string
  recommendation: string
  reference: string
}

export interface VgsVulnerabilityLibraryEntryInput {
  title: string
  severity: Severity
  cvss_score?: string
  cvss_vector?: string
  description?: string
  recommendation?: string
  reference?: string
}

export interface VgsReportDraftOut {
  id: string
  version_id: string
  app_title: string
  scope: string
  urls: string
  analyst_name: string
  requester_name: string
}

export interface VgsReportVulnerabilityOut {
  id: string
  report_draft_id: string
  library_entry_id: string | null
  source_finding_id: string | null
  order_index: number
  title: string
  severity: Severity
  cvss_score: string
  cvss_vector: string
  description: string
  recommendation: string
  reference: string
}

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
}

export interface AvailableFindingOut {
  finding: FindingOut
  scan_run_id: string
  already_added: boolean
}

export interface VgsEvidenceStepOut {
  id: string
  report_vulnerability_id: string
  step_order: number
  comment: string
  screenshot_object_keys: string[]
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

  if (!response.ok) {
    let detail = response.statusText
    try {
      const data = await response.json()
      detail = data.detail ?? detail
    } catch {
      // non-JSON error body
    }
    throw new ApiError(response.status, typeof detail === 'string' ? detail : JSON.stringify(detail))
  }

  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

export const vgsApi = {
  library: {
    list: () => request<VgsVulnerabilityLibraryEntryOut[]>('/vgs-vulnerability-library'),
    create: (body: VgsVulnerabilityLibraryEntryInput) =>
      request<VgsVulnerabilityLibraryEntryOut>('/vgs-vulnerability-library', { method: 'POST', body }),
    update: (id: string, body: VgsVulnerabilityLibraryEntryInput) =>
      request<VgsVulnerabilityLibraryEntryOut>(`/vgs-vulnerability-library/${id}`, {
        method: 'PATCH',
        body,
      }),
    delete: (id: string) => request<void>(`/vgs-vulnerability-library/${id}`, { method: 'DELETE' }),
  },

  draft: {
    get: (versionId: string) => request<VgsReportDraftOut>(`/versions/${versionId}/vgs-report-draft`),
    update: (
      versionId: string,
      body: Partial<Pick<VgsReportDraftOut, 'app_title' | 'scope' | 'urls' | 'analyst_name' | 'requester_name'>>,
    ) => request<VgsReportDraftOut>(`/versions/${versionId}/vgs-report-draft`, { method: 'PATCH', body }),
  },

  availableFindings: {
    list: (versionId: string) =>
      request<AvailableFindingOut[]>(`/versions/${versionId}/vgs-report-draft/available-findings`),
  },

  vulnerabilities: {
    list: (versionId: string) =>
      request<VgsReportVulnerabilityOut[]>(`/versions/${versionId}/vgs-report-draft/vulnerabilities`),
    addFromLibrary: (versionId: string, libraryEntryId: string) =>
      request<VgsReportVulnerabilityOut>(`/versions/${versionId}/vgs-report-draft/vulnerabilities`, {
        method: 'POST',
        body: { library_entry_id: libraryEntryId },
      }),
    addFromFinding: (versionId: string, findingId: string) =>
      request<VgsReportVulnerabilityOut>(
        `/versions/${versionId}/vgs-report-draft/vulnerabilities/from-finding/${findingId}`,
        { method: 'POST' },
      ),
    addAdHoc: (
      versionId: string,
      body: { title: string; severity: Severity; cvss_score?: string; cvss_vector?: string; description?: string; recommendation?: string; reference?: string },
    ) =>
      request<VgsReportVulnerabilityOut>(`/versions/${versionId}/vgs-report-draft/vulnerabilities`, {
        method: 'POST',
        body,
      }),
    update: (versionId: string, vulnId: string, body: Partial<VgsReportVulnerabilityOut>) =>
      request<VgsReportVulnerabilityOut>(
        `/versions/${versionId}/vgs-report-draft/vulnerabilities/${vulnId}`,
        { method: 'PATCH', body },
      ),
    delete: (versionId: string, vulnId: string) =>
      request<void>(`/versions/${versionId}/vgs-report-draft/vulnerabilities/${vulnId}`, {
        method: 'DELETE',
      }),
  },

  evidenceSteps: {
    list: (versionId: string, vulnId: string) =>
      request<VgsEvidenceStepOut[]>(
        `/versions/${versionId}/vgs-report-draft/vulnerabilities/${vulnId}/evidence-steps`,
      ),
    add: (versionId: string, vulnId: string, comment: string, screenshot?: File) => {
      const formData = new FormData()
      formData.set('comment', comment)
      if (screenshot) formData.set('screenshot', screenshot)
      return request<VgsEvidenceStepOut>(
        `/versions/${versionId}/vgs-report-draft/vulnerabilities/${vulnId}/evidence-steps`,
        { method: 'POST', formData },
      )
    },
    update: (versionId: string, vulnId: string, stepId: string, body: { comment?: string }) =>
      request<VgsEvidenceStepOut>(
        `/versions/${versionId}/vgs-report-draft/vulnerabilities/${vulnId}/evidence-steps/${stepId}`,
        { method: 'PATCH', body },
      ),
    delete: (versionId: string, vulnId: string, stepId: string) =>
      request<void>(
        `/versions/${versionId}/vgs-report-draft/vulnerabilities/${vulnId}/evidence-steps/${stepId}`,
        { method: 'DELETE' },
      ),
  },

  // Same blob-download-with-auth-header pattern as ../../../api/client.ts's
  // downloadReport — a plain <a href> can't attach an Authorization header.
  downloadReportDocx: async (versionId: string, appTitle: string): Promise<void> => {
    const token = getToken()
    const response = await fetch(`${BASE_URL}/versions/${versionId}/vgs-report-draft/report.docx`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!response.ok) throw new ApiError(response.status, response.statusText)
    const blob = await response.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${appTitle || 'DVA-Report'}.docx`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  },
}

export function calculateCvss(values: {
  AV?: string
  AC?: string
  PR?: string
  UI?: string
  S?: string
  C?: string
  I?: string
  A?: string
}): { score: number; vector: string } | null {
  const { AV, AC, PR, UI, S, C, I, A } = values
  if (!(AV && AC && PR && UI && S && C && I && A)) return null

  // Real CVSS v3.1 base-score formula, ported from the VGS tool's own
  // CVSSCalculator.jsx (same metric-value tables and impact/
  // exploitability math, not reinvented).
  const avVals: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
  const acVals: Record<string, number> = { L: 0.77, H: 0.44 }
  const prVals: Record<string, Record<string, number>> = {
    U: { N: 0.85, L: 0.62, H: 0.27 },
    C: { N: 0.85, L: 0.68, H: 0.5 },
  }
  const uiVals: Record<string, number> = { N: 0.85, R: 0.62 }
  const ciaVals: Record<string, number> = { H: 0.56, L: 0.22, N: 0.0 }

  const iss = 1 - (1 - ciaVals[C]) * (1 - ciaVals[I]) * (1 - ciaVals[A])
  const impact = S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
  const exploitability = 8.22 * avVals[AV] * acVals[AC] * prVals[S][PR] * uiVals[UI]
  let score = impact <= 0 ? 0 : S === 'U' ? impact + exploitability : 1.08 * (impact + exploitability)
  score = Math.ceil(Math.min(score, 10) * 10) / 10

  const vector = `CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`
  return { score, vector }
}

export function severityFromScore(score: number): Severity {
  if (score >= 9.0) return 'Critical'
  if (score >= 7.0) return 'High'
  if (score >= 4.0) return 'Medium'
  return 'Low'
}
