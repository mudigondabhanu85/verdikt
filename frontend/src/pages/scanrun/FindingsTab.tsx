import { useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../../api/client'
import { AuthenticatedImage } from '../../components/AuthenticatedImage'
import { SeverityBadge, StatusBadge } from '../../components/Badges'
import { TicketSection } from './TicketSection'
import type { FindingOut, FindingRetestStatus } from '../../api/types'
import { useAuth, canReview, canWrite } from '../../auth/AuthContext'

// Same substring-highlight behavior as the downloadable HTML/PDF/DOCX
// reports (app/reporting/html_report.py's highlight_payload Jinja
// filter — keep these two in sync) — every literal occurrence of the
// first matching highlight candidate (see highlightCandidates) inside
// the raw request/response text gets wrapped for visual emphasis, so a
// reader can see at a glance exactly what payload was sent and where it
// landed in the response, without hunting through a wall of raw HTTP
// text. Built as separate React children (never dangerouslySetInnerHTML)
// so the surrounding — possibly attacker-controlled — text stays safely
// auto-escaped by React exactly as it already was before this existed.

// x-www-form-urlencoded encodes a space as "+", not "%20" —
// encodeURIComponent alone (which produces "%20") never matches a real
// form-encoded request body/query string built by Python's own
// urlencode() (e.g. DVWA's command-injection field arriving as
// "%3B+echo+VERDIKT...").
function quotePlus(s: string): string {
  return encodeURIComponent(s).replace(/%20/g, '+')
}

// Every marker-based check in this codebase embeds a recognizable
// "VERDIKT<hex>" / "verdikt_<...>" token inside its full payload (e.g.
// command-injection's "; echo VERDIKT7228dae9") — but what actually
// proves the finding in the *response* is often only that marker (a
// shell echoes its output, not the command that produced it), so a
// literal full-payload match finds nothing there even though the
// finding is completely real.
const MARKER_RE = /VERDIKT[0-9a-f]{6,}|verdikt_[A-Za-z0-9]{6,}|verdikt[0-9]{4,}/

function highlightCandidates(payload: string): string[] {
  const candidates = [payload]
  const encoded = quotePlus(payload)
  if (!candidates.includes(encoded)) candidates.push(encoded)
  const markerMatch = payload.match(MARKER_RE)
  if (markerMatch && !candidates.includes(markerMatch[0])) candidates.push(markerMatch[0])
  return candidates
}

function highlightPayload(text: string, payload: string | null): ReactNode {
  if (!payload) return text
  for (const candidate of highlightCandidates(payload)) {
    if (!candidate) continue
    const parts = text.split(candidate)
    if (parts.length === 1) continue
    const nodes: ReactNode[] = []
    parts.forEach((part, i) => {
      if (part) nodes.push(part)
      if (i < parts.length - 1) {
        nodes.push(
          <mark key={i} className="rounded bg-yellow-200 px-0.5 text-gray-900">
            {candidate}
          </mark>,
        )
      }
    })
    return nodes
  }
  return text
}

// The direct answer to "I need to delete/false-positive a finding": mark
// it false_positive_after_review/risk_accepted (both "analyst-locked" —
// a later rescan diff won't silently reopen them just because the same
// signal reproduced) if you want the record kept for audit history, or
// delete it outright if you don't. See backend/app/api/routes/findings.py.
function FindingStatusControl({ scanRunId, finding }: { scanRunId: string; finding: FindingOut }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [confirmingDelete, setConfirmingDelete] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['scan-runs', scanRunId, 'findings'] })

  const statusMutation = useMutation({
    mutationFn: (retest_status: FindingRetestStatus) => api.findings.updateStatus(finding.id, retest_status),
    onSuccess: () => {
      setError(null)
      invalidate()
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Update failed'),
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.findings.delete(finding.id),
    onSuccess: invalidate,
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Delete failed'),
  })

  if (!canReview(user?.role)) return null

  return (
    <div className="flex flex-wrap items-center gap-2 border-t border-gray-100 pt-2">
      {finding.retest_status !== 'false_positive_after_review' && (
        <button
          onClick={() => statusMutation.mutate('false_positive_after_review')}
          disabled={statusMutation.isPending}
          className="rounded border border-gray-300 bg-white px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
        >
          Mark false positive
        </button>
      )}
      {finding.retest_status !== 'risk_accepted' && (
        <button
          onClick={() => statusMutation.mutate('risk_accepted')}
          disabled={statusMutation.isPending}
          className="rounded border border-gray-300 bg-white px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
        >
          Accept risk
        </button>
      )}
      {finding.retest_status !== 'open' && (
        <button
          onClick={() => statusMutation.mutate('open')}
          disabled={statusMutation.isPending}
          className="rounded border border-gray-300 bg-white px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
        >
          Reopen
        </button>
      )}
      {canWrite(user?.role) &&
        (confirmingDelete ? (
          <span className="flex items-center gap-1 text-xs">
            <span className="text-gray-500">Delete permanently?</span>
            <button
              onClick={() => deleteMutation.mutate()}
              disabled={deleteMutation.isPending}
              className="rounded border border-red-300 bg-red-50 px-2 py-0.5 text-red-700 hover:bg-red-100 disabled:opacity-50"
            >
              {deleteMutation.isPending ? 'Deleting…' : 'Confirm delete'}
            </button>
            <button onClick={() => setConfirmingDelete(false)} className="text-gray-400 hover:underline">
              cancel
            </button>
          </span>
        ) : (
          <button
            onClick={() => setConfirmingDelete(true)}
            className="rounded border border-red-300 bg-white px-2 py-0.5 text-xs text-red-600 hover:bg-red-50"
          >
            Delete
          </button>
        ))}
      {error && <span className="text-xs text-red-600">{error}</span>}
    </div>
  )
}

const RETEST_RESULT_LABELS: Record<string, string> = {
  still_vulnerable: 'Still vulnerable',
  fixed: 'Fixed',
  not_supported: 'Not supported',
  error: 'Error',
}

// AI-pentest findings (check_id "ai-pentest-finding" — every autonomous
// session uses this one check_id regardless of the actual vulnerability
// type, see app.agents.autonomous_pentest.runner._persist_confirmed_finding)
// were never in app.agents.retest_registry.RETEST_HANDLERS at all: they
// were confirmed by an open-ended LLM investigation, not one fixed
// deterministic HTTP probe, so there's no single request to "replay."
// POST .../retest for one of these always came back "not_supported" —
// real, but the fix isn't a synchronous handler, it's a real (if
// smaller and narrower) AI-driven re-investigation, reusing the exact
// same engine and consent flow the original finding came from rather
// than inventing a second one.
function AiRetestSection({ versionId, finding }: { versionId: string; finding: FindingOut }) {
  const [showConfirm, setShowConfirm] = useState(false)
  const [confirmationText, setConfirmationText] = useState('')
  const [credentialId, setCredentialId] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [lastScanRunId, setLastScanRunId] = useState<string | null>(null)

  const { data: credentials } = useQuery({
    queryKey: ['versions', versionId, 'credentials'],
    queryFn: () => api.credentials.list(versionId),
  })

  const phraseQuery = useQuery({
    queryKey: ['versions', versionId, 'autonomous-pentest-confirmation-phrase'],
    queryFn: () => api.autonomousPentest.confirmationPhrase(versionId),
    enabled: showConfirm,
  })

  const objective = [
    `Confirm whether this previously-confirmed vulnerability is still present: "${finding.title}"`,
    `at ${finding.affected_endpoints[0] ?? '(endpoint not recorded)'}.`,
    finding.evidence?.payload ? `It was originally proven with this payload: ${finding.evidence.payload}.` : '',
    'Re-verify using the same or an equivalent technique and report using the same JSON finding schema if it still reproduces.',
  ]
    .filter(Boolean)
    .join(' ')

  const startMutation = useMutation({
    mutationFn: () =>
      api.autonomousPentest.create(versionId, {
        confirmation_text: confirmationText,
        objective,
        credential_id: credentialId || null,
      }),
    onSuccess: (scanRun) => {
      setError(null)
      setLastScanRunId(scanRun.id)
      setShowConfirm(false)
      setConfirmationText('')
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Could not start the retest'),
  })

  const phrase = phraseQuery.data?.confirmation_phrase

  return (
    <div>
      <h4 className="mb-1 font-medium text-gray-700">Retest</h4>
      <p className="mb-2 text-xs text-gray-500">
        This finding came from an open-ended AI investigation, not one fixed check — re-verifying it means
        running a fresh, focused AI session against the same target rather than a single instant replay.
      </p>

      {!showConfirm && !lastScanRunId && (
        <button
          onClick={() => setShowConfirm(true)}
          className="rounded border border-gray-300 bg-white px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50"
        >
          Re-verify with AI
        </button>
      )}

      {showConfirm && (
        <div className="rounded border border-purple-200 bg-purple-50 p-2 text-xs">
          {credentials && credentials.length > 1 && (
            <>
              <label className="mb-1 block font-medium text-purple-900">Pre-authenticate as</label>
              <select
                value={credentialId}
                onChange={(e) => setCredentialId(e.target.value)}
                className="mb-2 w-full rounded border border-gray-300 px-2 py-1 focus:border-purple-500 focus:outline-none"
              >
                <option value="">Don't pre-authenticate — let the AI log in itself</option>
                {credentials.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.label} ({c.masked_reference})
                  </option>
                ))}
              </select>
            </>
          )}
          <p className="mb-2 text-purple-900">
            This runs real exploitation tooling in an isolated sandbox again. To confirm, type the phrase below
            exactly.
          </p>
          {phraseQuery.isLoading && <p className="text-gray-500">Loading…</p>}
          {phrase && (
            <>
              <p className="mb-2 rounded bg-white px-2 py-1 font-mono">{phrase}</p>
              <input
                value={confirmationText}
                onChange={(e) => setConfirmationText(e.target.value)}
                placeholder="Type the phrase above"
                className="mb-2 w-full rounded border border-gray-300 px-2 py-1 focus:border-purple-500 focus:outline-none"
              />
            </>
          )}
          <div className="flex items-center gap-2">
            <button
              onClick={() => startMutation.mutate()}
              disabled={!phrase || confirmationText !== phrase || startMutation.isPending}
              className="rounded bg-purple-700 px-3 py-1 font-medium text-white hover:bg-purple-800 disabled:opacity-50"
            >
              {startMutation.isPending ? 'Starting…' : 'Start retest'}
            </button>
            <button onClick={() => setShowConfirm(false)} className="text-gray-500 hover:underline">
              cancel
            </button>
          </div>
        </div>
      )}

      {error && <p className="mt-1 text-xs text-red-600">{error}</p>}

      {lastScanRunId && (
        <p className="text-xs text-gray-600">
          Retest session started —{' '}
          <Link to={`/scan-runs/${lastScanRunId}`} className="text-purple-700 hover:underline">
            view its live transcript and findings →
          </Link>
          . This original finding's status isn't updated automatically; review the new session's result and
          mark this one Fixed/Reopened yourself once you've seen it.
        </p>
      )}
    </div>
  )
}

function RetestSection({ scanRunId, finding }: { scanRunId: string; finding: FindingOut }) {
  const queryClient = useQueryClient()

  const { data: jobs } = useQuery({
    queryKey: ['findings', finding.id, 'retest-jobs'],
    queryFn: () => api.retestJobs.list(finding.id),
  })

  const retestMutation = useMutation({
    mutationFn: () => api.retestJobs.trigger(finding.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings', finding.id, 'retest-jobs'] })
      queryClient.invalidateQueries({ queryKey: ['scan-runs', scanRunId, 'findings'] })
    },
  })

  const latest = jobs && jobs.length > 0 ? jobs[jobs.length - 1] : null

  return (
    <div>
      <div className="mb-1 flex items-center gap-2">
        <h4 className="font-medium text-gray-700">Retest</h4>
        <button
          onClick={() => retestMutation.mutate()}
          disabled={retestMutation.isPending}
          className="rounded border border-gray-300 bg-white px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
        >
          {retestMutation.isPending ? 'Retesting…' : 'Retest this finding'}
        </button>
      </div>
      {retestMutation.isError && (
        <p className="text-xs text-red-600">
          {retestMutation.error instanceof ApiError ? retestMutation.error.message : 'Retest failed'}
        </p>
      )}
      {latest && (
        <p className="text-xs text-gray-500">
          Last checked {new Date(latest.created_at).toLocaleString()} —{' '}
          <span className="font-medium">{RETEST_RESULT_LABELS[latest.result ?? ''] ?? latest.result}</span>
          {latest.error && <span className="ml-1 text-gray-400">({latest.error})</span>}
        </p>
      )}
      {jobs && jobs.length > 1 && (
        <details className="mt-1 text-xs text-gray-400">
          <summary className="cursor-pointer">{jobs.length} retest attempts</summary>
          <ul className="mt-1 space-y-0.5">
            {jobs.map((job) => (
              <li key={job.id}>
                {new Date(job.created_at).toLocaleString()} — {RETEST_RESULT_LABELS[job.result ?? ''] ?? job.result}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  )
}

function FindingDetail({
  scanRunId,
  versionId,
  finding,
}: {
  scanRunId: string
  versionId: string
  finding: FindingOut
}) {
  return (
    <div className="space-y-3 border-t border-gray-100 bg-gray-50 px-4 py-4 text-sm">
      <p className="text-gray-700">{finding.plain_language_summary}</p>
      <p className="text-gray-600">{finding.technical_description}</p>

      <div>
        <h4 className="mb-1 font-medium text-gray-700">Steps to reproduce</h4>
        <ol className="list-inside list-decimal space-y-1 text-gray-600">
          {finding.steps_to_reproduce.map((step, i) => (
            <li key={i}>{step}</li>
          ))}
        </ol>
      </div>

      <div>
        <h4 className="mb-1 font-medium text-gray-700">Affected endpoints</h4>
        <ul className="list-inside list-disc font-mono text-xs text-gray-600">
          {finding.affected_endpoints.map((ep) => (
            <li key={ep}>{ep}</li>
          ))}
        </ul>
      </div>

      <div>
        <h4 className="mb-1 font-medium text-gray-700">Remediation</h4>
        <p className="text-gray-600">{finding.remediation}</p>
      </div>

      <div className="flex gap-4 text-xs text-gray-500">
        <span>CWE: {finding.cwe_id}</span>
        <span>CVSS: {finding.cvss_score} ({finding.cvss_vector})</span>
        <span>{finding.owasp_2025_category}</span>
      </div>

      <FindingStatusControl scanRunId={scanRunId} finding={finding} />
      {finding.check_id === 'ai-pentest-finding' ? (
        <AiRetestSection versionId={versionId} finding={finding} />
      ) : (
        <RetestSection scanRunId={scanRunId} finding={finding} />
      )}
      <TicketSection findingId={finding.id} />

      {finding.evidence && (
        <div>
          <h4 className="mb-1 font-medium text-gray-700">Evidence</h4>
          {finding.evidence.payload && (
            <p className="mb-1 text-xs text-gray-500">
              Payload: <code className="rounded bg-yellow-100 px-1 py-0.5 text-gray-900">{finding.evidence.payload}</code>
            </p>
          )}
          <pre className="mb-2 overflow-x-auto rounded bg-white p-2 text-xs text-gray-700">
            {highlightPayload(finding.evidence.request_raw, finding.evidence.payload)}
          </pre>
          <pre className="overflow-x-auto rounded bg-white p-2 text-xs text-gray-700">
            {highlightPayload(finding.evidence.response_raw, finding.evidence.payload)}
          </pre>
          {finding.evidence.screenshot_refs.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-2">
              {finding.evidence.screenshot_refs.map((ref) => (
                <AuthenticatedImage key={ref} objectKey={ref} alt="evidence screenshot" className="max-w-xs rounded border" />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

const SEVERITY_RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 }

interface FindingGroup {
  key: string
  checkId: string
  title: string
  severity: string
  instances: FindingOut[]
}

function groupFindings(findings: FindingOut[]): FindingGroup[] {
  const byKey = new Map<string, FindingGroup>()
  for (const finding of findings) {
    const key = `${finding.check_id}::${finding.title}`
    const existing = byKey.get(key)
    if (existing) {
      existing.instances.push(finding)
      if (SEVERITY_RANK[finding.severity] < SEVERITY_RANK[existing.severity]) {
        existing.severity = finding.severity
      }
    } else {
      byKey.set(key, { key, checkId: finding.check_id, title: finding.title, severity: finding.severity, instances: [finding] })
    }
  }
  return Array.from(byKey.values()).sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
}

function FindingGroupRow({
  scanRunId,
  versionId,
  group,
}: {
  scanRunId: string
  versionId: string
  group: FindingGroup
}) {
  const [groupOpen, setGroupOpen] = useState(false)
  const [expandedInstance, setExpandedInstance] = useState<string | null>(null)
  const shared = group.instances[0]

  return (
    <li>
      <button
        onClick={() => setGroupOpen(!groupOpen)}
        className="flex w-full items-center justify-between px-4 py-3 text-left hover:bg-gray-50"
      >
        <span className="flex items-center gap-3">
          <SeverityBadge severity={group.severity} />
          <span className="font-medium">{group.title}</span>
          <span className="rounded-full bg-gray-100 px-2 py-0.5 text-xs text-gray-600">
            × {group.instances.length} {group.instances.length === 1 ? 'instance' : 'instances'}
          </span>
        </span>
        <span className="text-xs text-gray-400">{groupOpen ? 'Hide' : 'Show'} instances</span>
      </button>

      {groupOpen && (
        <div className="border-t border-gray-100 bg-gray-50 px-4 py-4 text-sm">
          <p className="mb-2 text-gray-700">{shared.plain_language_summary}</p>
          <p className="mb-3 text-gray-600">{shared.remediation}</p>
          <div className="mb-3 flex gap-4 text-xs text-gray-500">
            <span>CWE: {shared.cwe_id}</span>
            <span>{shared.owasp_2025_category}</span>
          </div>

          <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
            {group.instances.map((finding) => (
              <li key={finding.id}>
                <button
                  onClick={() => setExpandedInstance(expandedInstance === finding.id ? null : finding.id)}
                  className="flex w-full items-center justify-between px-4 py-2 text-left hover:bg-gray-50"
                >
                  <span className="truncate font-mono text-xs text-gray-700">
                    {finding.affected_endpoints[0] ?? '(no endpoint recorded)'}
                  </span>
                  <span className="flex shrink-0 items-center gap-2">
                    <StatusBadge status={finding.confirmation_status} />
                    <StatusBadge status={finding.retest_status} />
                  </span>
                </button>
                {expandedInstance === finding.id && (
                  <FindingDetail scanRunId={scanRunId} versionId={versionId} finding={finding} />
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </li>
  )
}

export function FindingsTab({ scanRunId, versionId }: { scanRunId: string; versionId: string }) {
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  const { data: findings, isLoading } = useQuery({
    queryKey: ['scan-runs', scanRunId, 'findings'],
    queryFn: () => api.scanRuns.findings(scanRunId),
  })

  const visible = findings?.filter((f) => severityFilter === 'all' || f.severity === severityFilter) ?? []
  const groups = groupFindings(visible)

  return (
    <div>
      <div className="mb-4 flex gap-2">
        {['all', 'Critical', 'High', 'Medium', 'Low'].map((sev) => (
          <button
            key={sev}
            onClick={() => setSeverityFilter(sev)}
            className={`rounded-full border px-3 py-1 text-xs ${
              severityFilter === sev ? 'border-purple-700 bg-purple-100 text-purple-800' : 'border-gray-300 text-gray-600'
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      {isLoading && <p className="text-gray-500">Loading…</p>}
      {findings && findings.length === 0 && <p className="text-gray-500">No findings.</p>}
      {findings && findings.length > 0 && (
        <p className="mb-2 text-xs text-gray-500">
          {findings.length} finding{findings.length === 1 ? '' : 's'} across {groupFindings(findings).length} vulnerability
          type{groupFindings(findings).length === 1 ? '' : 's'}
        </p>
      )}

      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {groups.map((group) => (
          <FindingGroupRow key={group.key} scanRunId={scanRunId} versionId={versionId} group={group} />
        ))}
      </ul>
    </div>
  )
}
