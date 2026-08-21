import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { SeverityBadge, StatusBadge } from '../components/Badges'

export function DashboardPage() {
  const { data, isLoading } = useQuery({
    queryKey: ['organizations', 'me', 'dashboard'],
    queryFn: api.organizations.dashboard,
  })

  if (isLoading || !data) return <p className="text-gray-500">Loading…</p>

  return (
    <div>
      <h1 className="mb-6 text-2xl font-semibold">Dashboard</h1>

      <div className="mb-8 grid grid-cols-3 gap-4">
        <div className="rounded border border-gray-200 bg-white p-4">
          <div className="text-2xl font-semibold">{data.total_projects}</div>
          <div className="text-sm text-gray-500">Projects</div>
        </div>
        <div className="rounded border border-gray-200 bg-white p-4">
          <div className="text-2xl font-semibold">{data.total_versions}</div>
          <div className="text-sm text-gray-500">Versions</div>
        </div>
        <div className="rounded border border-gray-200 bg-white p-4">
          <div className="text-2xl font-semibold">{data.total_scan_runs}</div>
          <div className="text-sm text-gray-500">Scan runs</div>
        </div>
      </div>

      <h2 className="mb-3 text-lg font-medium text-gray-800">Open findings, org-wide</h2>
      <p className="mb-3 text-sm text-gray-500">
        Excludes anything marked "fixed" by a rescan or retest — includes findings still open as well as ones an
        analyst risk-accepted or dismissed after review.
      </p>
      <div className="mb-8 flex flex-wrap gap-3">
        {Object.entries(data.open_findings_by_severity).map(([severity, count]) => (
          <span key={severity} className="flex items-center gap-2 rounded border border-gray-200 bg-white px-4 py-2">
            <SeverityBadge severity={severity} />
            <span className="text-lg font-semibold">{count}</span>
          </span>
        ))}
      </div>

      <h2 className="mb-3 text-lg font-medium text-gray-800">Recent scan runs</h2>
      {data.recent_scan_runs.length === 0 && <p className="text-gray-500">No scan runs yet.</p>}
      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {data.recent_scan_runs.map((run) => (
          <li key={run.id}>
            <Link to={`/scan-runs/${run.id}`} className="flex items-center justify-between px-4 py-3 hover:bg-gray-50">
              <span className="flex items-center gap-2">
                <span className="font-medium">{run.project_name}</span>
                <span className="text-gray-400">/</span>
                <span className="text-gray-600">{run.version_name}</span>
                <StatusBadge status={run.status} />
              </span>
              <span className="flex items-center gap-2 text-xs text-gray-500">
                {Object.entries(run.finding_counts_by_severity)
                  .filter(([, count]) => count > 0)
                  .map(([severity, count]) => (
                    <span key={severity} className="flex items-center gap-1">
                      <SeverityBadge severity={severity} /> {count}
                    </span>
                  ))}
                {run.started_at && <span>{new Date(run.started_at).toLocaleString()}</span>}
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  )
}
