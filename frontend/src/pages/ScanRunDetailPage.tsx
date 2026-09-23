import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { Tabs } from '../components/Tabs'
import { StatusBadge } from '../components/Badges'
import { AgentJobsTab } from './scanrun/AgentJobsTab'
import { SiteMapTab } from './scanrun/SiteMapTab'
import { FindingsTab } from './scanrun/FindingsTab'
import { ReviewCandidatesTab } from './scanrun/ReviewCandidatesTab'
import { ReportsTab } from './scanrun/ReportsTab'
import { DiffTab } from './scanrun/DiffTab'
import { PentestTranscriptTab } from './scanrun/PentestTranscriptTab'

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
      <div className="mb-1 flex items-center gap-3">
        <h1 className="text-2xl font-semibold">Scan Run</h1>
        {scanRun.mode === 'autonomous_ai' && (
          <span className="rounded bg-purple-100 px-2 py-0.5 text-xs font-medium text-purple-800">
            AI-driven pentest
          </span>
        )}
        <StatusBadge status={scanRun.status} testId="scan-run-status" />
        <span className="font-mono text-xs text-gray-400">{scanRun.id}</span>
      </div>
      <p className="mb-6 text-xs text-gray-500">
        LLM usage: {(scanRun.llm_input_tokens + scanRun.llm_output_tokens).toLocaleString()} tokens (
        {scanRun.llm_input_tokens.toLocaleString()} in / {scanRun.llm_output_tokens.toLocaleString()} out) · $
        {Number(scanRun.llm_cost_usd).toFixed(4)} estimated
      </p>

      <Tabs
        tabs={
          scanRun.mode === 'autonomous_ai'
            ? [
                // The AI-driven mode's own tool-use transcript replaces
                // Site Map/Diff/Review Candidates here — those are all
                // specific to the deterministic agents' own crawl/XSS-
                // proof pipeline, which this mode never runs.
                { key: 'transcript', label: 'Pentest Transcript', content: <PentestTranscriptTab scanRun={scanRun} /> },
                { key: 'agent-jobs', label: 'Agent Jobs', content: <AgentJobsTab scanRun={scanRun} /> },
                { key: 'findings', label: 'Findings', content: <FindingsTab scanRunId={scanRunId} /> },
                { key: 'reports', label: 'Reports', content: <ReportsTab scanRunId={scanRunId} /> },
              ]
            : [
                { key: 'agent-jobs', label: 'Agent Jobs', content: <AgentJobsTab scanRun={scanRun} /> },
                { key: 'site-map', label: 'Site Map', content: <SiteMapTab scanRun={scanRun} /> },
                { key: 'findings', label: 'Findings', content: <FindingsTab scanRunId={scanRunId} /> },
                { key: 'review-candidates', label: 'Review Candidates', content: <ReviewCandidatesTab scanRunId={scanRunId} /> },
                { key: 'reports', label: 'Reports', content: <ReportsTab scanRunId={scanRunId} /> },
                { key: 'diff', label: 'Diff', content: <DiffTab scanRunId={scanRunId} versionId={scanRun.version_id} /> },
              ]
        }
      />
    </div>
  )
}
