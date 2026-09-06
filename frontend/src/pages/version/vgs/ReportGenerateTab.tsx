import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../../api/client'
import { vgsApi } from './api'

export function ReportGenerateTab({ versionId }: { versionId: string }) {
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const { data: draft } = useQuery({
    queryKey: ['vgs-report-draft', versionId],
    queryFn: () => vgsApi.draft.get(versionId),
  })
  const { data: vulnerabilities } = useQuery({
    queryKey: ['vgs-report-vulnerabilities', versionId],
    queryFn: () => vgsApi.vulnerabilities.list(versionId),
  })
  const { data: branding } = useQuery({
    queryKey: ['org-branding'],
    queryFn: api.orgBranding.get,
  })

  const severityCounts = (vulnerabilities ?? []).reduce<Record<string, number>>((acc, v) => {
    acc[v.severity] = (acc[v.severity] ?? 0) + 1
    return acc
  }, {})

  async function handleGenerate() {
    setError(null)
    setGenerating(true)
    try {
      await vgsApi.downloadReportDocx(versionId, draft?.app_title ?? 'DVA-Report')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate report')
    } finally {
      setGenerating(false)
    }
  }

  return (
    <div className="mx-auto max-w-xl space-y-4">
      <h2 className="text-center text-lg font-semibold text-gray-800">Summary &amp; Generate Report</h2>

      <div className="rounded border border-gray-200 bg-white p-4 text-sm">
        <p>
          <span className="font-medium">Application:</span> {draft?.app_title || '(not set)'}
        </p>
        <p>
          <span className="font-medium">Requested by:</span> {draft?.requester_name || '(not set)'}
        </p>
        <p>
          <span className="font-medium">Analyst:</span> {draft?.analyst_name || '(not set)'}
        </p>
      </div>

      <div className="rounded border border-gray-200 bg-white p-4 text-sm">
        <p className="mb-2 font-medium">Selected vulnerabilities: {vulnerabilities?.length ?? 0}</p>
        {(['Critical', 'High', 'Medium', 'Low'] as const).map((sev) =>
          severityCounts[sev] ? (
            <p key={sev} className="text-gray-600">
              {sev}: {severityCounts[sev]}
            </p>
          ) : null,
        )}
      </div>

      <div className="rounded border border-gray-200 bg-white p-4 text-sm">
        <p className="mb-1 font-medium">Report logo</p>
        {branding?.logo_object_key ? (
          <p className="text-gray-600">Using your org's branding logo (set in Account settings).</p>
        ) : (
          <p className="text-gray-400">
            No logo set — configure one under Account → Report branding to include it on the cover page.
          </p>
        )}
      </div>

      {error && <p className="text-sm text-red-600">{error}</p>}

      <button
        onClick={handleGenerate}
        disabled={generating || !vulnerabilities || vulnerabilities.length === 0}
        className="w-full rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
      >
        {generating ? 'Generating…' : 'Generate Report (DOCX)'}
      </button>
    </div>
  )
}
