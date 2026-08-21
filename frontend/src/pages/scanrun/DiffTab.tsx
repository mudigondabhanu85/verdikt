import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import { SeverityBadge } from '../../components/Badges'
import type { FindingOut } from '../../api/types'

function FindingRow({ finding }: { finding: FindingOut }) {
  return (
    <li className="flex items-center gap-3 px-3 py-2 text-sm">
      <SeverityBadge severity={finding.severity} />
      <span>{finding.title}</span>
      <span className="truncate font-mono text-xs text-gray-400">{finding.affected_endpoints[0]}</span>
    </li>
  )
}

function DiffColumn({ title, findings, tone }: { title: string; findings: FindingOut[]; tone: string }) {
  return (
    <div className="flex-1">
      <h3 className={`mb-2 text-sm font-medium ${tone}`}>
        {title} ({findings.length})
      </h3>
      {findings.length === 0 ? (
        <p className="text-xs text-gray-400">None</p>
      ) : (
        <ul className="divide-y divide-gray-100 rounded border border-gray-200 bg-white">
          {findings.map((f) => (
            <FindingRow key={f.id} finding={f} />
          ))}
        </ul>
      )}
    </div>
  )
}

export function DiffTab({ scanRunId, versionId }: { scanRunId: string; versionId: string }) {
  const [compareTo, setCompareTo] = useState('')

  const { data: scanRuns } = useQuery({
    queryKey: ['versions', versionId, 'scan-runs'],
    queryFn: () => api.scanRuns.list(versionId),
  })

  const otherRuns = scanRuns?.filter((r) => r.id !== scanRunId && r.status !== 'running') ?? []

  const { data: diff, isLoading } = useQuery({
    queryKey: ['scan-runs', scanRunId, 'diff', compareTo],
    queryFn: () => api.scanRuns.diff(scanRunId, compareTo),
    enabled: !!compareTo,
  })

  return (
    <div>
      <p className="mb-4 text-sm text-gray-500">
        Compare this scan run against an earlier one on the same version — findings matched by check type and
        affected endpoint, the same way a retest reconciles retest_status.
      </p>

      <div className="mb-6 flex items-center gap-2">
        <span className="text-sm text-gray-600">Compare against:</span>
        <select
          value={compareTo}
          onChange={(e) => setCompareTo(e.target.value)}
          className="rounded border border-gray-300 px-3 py-2 text-sm"
        >
          <option value="">Select an earlier scan run…</option>
          {otherRuns.map((run) => (
            <option key={run.id} value={run.id}>
              {run.id.slice(0, 8)} — {run.started_at ? new Date(run.started_at).toLocaleString() : run.status}
            </option>
          ))}
        </select>
      </div>

      {isLoading && <p className="text-gray-500">Loading…</p>}

      {diff && (
        <div className="flex gap-6">
          <DiffColumn title="New" findings={diff.new_findings} tone="text-red-700" />
          <DiffColumn title="Fixed" findings={diff.fixed_findings} tone="text-green-700" />
          <DiffColumn title="Still open" findings={diff.still_open_findings} tone="text-gray-700" />
        </div>
      )}
    </div>
  )
}
