import type { AgentJobOut, ScanRunDetail } from '../../api/types'
import { StatusBadge, SeverityBadge } from '../../components/Badges'

export function AgentJobsTab({ scanRun }: { scanRun: ScanRunDetail }) {
  return (
    <div>
      <div className="mb-4 flex flex-wrap gap-2">
        {Object.entries(scanRun.finding_counts_by_severity).map(([severity, count]) => (
          <span key={severity} className="flex items-center gap-1 rounded border border-gray-200 bg-white px-3 py-1 text-sm">
            <SeverityBadge severity={severity} /> {count}
          </span>
        ))}
      </div>

      {scanRun.error && (
        <p className="mb-4 rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{scanRun.error}</p>
      )}

      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-gray-200 text-gray-500">
            <th className="py-2">Agent</th>
            <th className="py-2">Status</th>
            <th className="py-2">Stats</th>
            <th className="py-2">Error</th>
          </tr>
        </thead>
        <tbody>
          {scanRun.agent_jobs.map((job: AgentJobOut) => (
            <tr key={job.id} className="border-b border-gray-100 align-top">
              <td className="py-2 font-medium">{job.agent_type}</td>
              <td className="py-2">
                <StatusBadge status={job.status} />
              </td>
              <td className="py-2 font-mono text-xs text-gray-500">{job.stats ? JSON.stringify(job.stats) : '—'}</td>
              <td className="py-2 text-xs text-red-600">{job.error ?? ''}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {scanRun.tech_stack_fingerprint && Object.keys(scanRun.tech_stack_fingerprint).length > 0 && (
        <div className="mt-6">
          <h3 className="mb-2 text-sm font-medium text-gray-700">Tech stack fingerprint</h3>
          <pre className="overflow-x-auto rounded bg-gray-50 p-3 text-xs text-gray-600">
            {JSON.stringify(scanRun.tech_stack_fingerprint, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}
