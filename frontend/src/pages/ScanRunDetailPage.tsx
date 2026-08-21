import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { Tabs } from '../components/Tabs'
import { StatusBadge } from '../components/Badges'
import { AgentJobsTab } from './scanrun/AgentJobsTab'
import { FindingsTab } from './scanrun/FindingsTab'
import { ReviewCandidatesTab } from './scanrun/ReviewCandidatesTab'
import { ReportsTab } from './scanrun/ReportsTab'

export function ScanRunDetailPage() {
  const { scanRunId } = useParams<{ scanRunId: string }>()

  const { data: scanRun, isLoading } = useQuery({
    queryKey: ['scan-runs', scanRunId],
    queryFn: () => api.scanRuns.get(scanRunId!),
    enabled: !!scanRunId,
    refetchInterval: (query) => (query.state.data?.status === 'running' ? 3000 : false),
  })

  if (!scanRunId) return null
  if (isLoading || !scanRun) return <p className="text-gray-500">Loading…</p>

  return (
    <div>
      <Link to={`/versions/${scanRun.version_id}`} className="mb-2 inline-block text-sm text-purple-700 hover:underline">
        ← Version
      </Link>
      <div className="mb-6 flex items-center gap-3">
        <h1 className="text-2xl font-semibold">Scan Run</h1>
        <StatusBadge status={scanRun.status} testId="scan-run-status" />
        <span className="font-mono text-xs text-gray-400">{scanRun.id}</span>
      </div>

      <Tabs
        tabs={[
          { key: 'agent-jobs', label: 'Agent Jobs', content: <AgentJobsTab scanRun={scanRun} /> },
          { key: 'findings', label: 'Findings', content: <FindingsTab scanRunId={scanRunId} /> },
          { key: 'review-candidates', label: 'Review Candidates', content: <ReviewCandidatesTab scanRunId={scanRunId} /> },
          { key: 'reports', label: 'Reports', content: <ReportsTab scanRunId={scanRunId} /> },
        ]}
      />
    </div>
  )
}
