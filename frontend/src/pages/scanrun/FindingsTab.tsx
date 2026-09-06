import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../../api/client'
import { AuthenticatedImage } from '../../components/AuthenticatedImage'
import { SeverityBadge, StatusBadge } from '../../components/Badges'
import { TicketSection } from './TicketSection'
import type { FindingOut } from '../../api/types'

const RETEST_RESULT_LABELS: Record<string, string> = {
  still_vulnerable: 'Still vulnerable',
  fixed: 'Fixed',
  not_supported: 'Not supported',
  error: 'Error',
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

function FindingDetail({ scanRunId, finding }: { scanRunId: string; finding: FindingOut }) {
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

      <RetestSection scanRunId={scanRunId} finding={finding} />
      <TicketSection findingId={finding.id} />

      {finding.evidence && (
        <div>
          <h4 className="mb-1 font-medium text-gray-700">Evidence</h4>
          <pre className="mb-2 overflow-x-auto rounded bg-white p-2 text-xs text-gray-700">{finding.evidence.request_raw}</pre>
          <pre className="overflow-x-auto rounded bg-white p-2 text-xs text-gray-700">{finding.evidence.response_raw}</pre>
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

function FindingGroupRow({ scanRunId, group }: { scanRunId: string; group: FindingGroup }) {
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
                {expandedInstance === finding.id && <FindingDetail scanRunId={scanRunId} finding={finding} />}
              </li>
            ))}
          </ul>
        </div>
      )}
    </li>
  )
}

export function FindingsTab({ scanRunId }: { scanRunId: string }) {
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
          <FindingGroupRow key={group.key} scanRunId={scanRunId} group={group} />
        ))}
      </ul>
    </div>
  )
}
