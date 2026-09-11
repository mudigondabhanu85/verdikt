import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  calculateCvss,
  vgsApi,
  type AvailableFindingOut,
  type Severity,
  type VgsReportVulnerabilityOut,
  type VgsVulnerabilityLibraryEntryOut,
} from './api'

const CVSS_METRICS: Record<string, { label: string; options: Record<string, string> }> = {
  AV: { label: 'Attack Vector', options: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' } },
  AC: { label: 'Attack Complexity', options: { L: 'Low', H: 'High' } },
  PR: { label: 'Privileges Required', options: { N: 'None', L: 'Low', H: 'High' } },
  UI: { label: 'User Interaction', options: { N: 'None', R: 'Required' } },
  S: { label: 'Scope', options: { U: 'Unchanged', C: 'Changed' } },
  C: { label: 'Confidentiality', options: { H: 'High', L: 'Low', N: 'None' } },
  I: { label: 'Integrity', options: { H: 'High', L: 'Low', N: 'None' } },
  A: { label: 'Availability', options: { H: 'High', L: 'Low', N: 'None' } },
}

function LibraryEntryRow({
  entry,
  versionId,
}: {
  entry: VgsVulnerabilityLibraryEntryOut
  versionId: string
}) {
  const queryClient = useQueryClient()
  const [expanded, setExpanded] = useState(false)
  const [cvss, setCvss] = useState<Record<string, string>>({})

  const addMutation = useMutation({
    mutationFn: () => vgsApi.vulnerabilities.addFromLibrary(versionId, entry.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['vgs-report-vulnerabilities', versionId] }),
  })

  const result = calculateCvss(cvss)

  return (
    <li className="rounded border border-gray-200 bg-white p-3 shadow-sm">
      <div className="flex items-center justify-between">
        <span className="font-medium">{entry.title}</span>
        <span className="flex gap-2">
          <button onClick={() => setExpanded(!expanded)} className="text-xs text-purple-700 hover:underline">
            {expanded ? 'Hide CVSS' : 'Show CVSS'}
          </button>
          <button
            onClick={() => addMutation.mutate()}
            disabled={addMutation.isPending}
            className="rounded bg-purple-700 px-2 py-1 text-xs font-medium text-white hover:bg-purple-800 disabled:opacity-50"
          >
            Add
          </button>
        </span>
      </div>
      {expanded && (
        <div className="mt-3 grid grid-cols-2 gap-2">
          {Object.entries(CVSS_METRICS).map(([key, meta]) => (
            <label key={key} className="text-xs">
              <span className="mb-0.5 block text-gray-600">{meta.label}</span>
              <select
                value={cvss[key] ?? ''}
                onChange={(e) => setCvss((prev) => ({ ...prev, [key]: e.target.value }))}
                className="w-full rounded border border-gray-300 px-2 py-1 text-xs"
              >
                <option value="">Select</option>
                {Object.entries(meta.options).map(([abbr, label]) => (
                  <option key={abbr} value={abbr}>
                    {label} ({abbr})
                  </option>
                ))}
              </select>
            </label>
          ))}
          {result && (
            <p className="col-span-2 mt-1 text-xs text-gray-600">
              Score: <strong>{result.score}</strong> — {result.vector}
            </p>
          )}
        </div>
      )}
    </li>
  )
}

function FindingRow({ item, versionId }: { item: AvailableFindingOut; versionId: string }) {
  const queryClient = useQueryClient()
  const [expanded, setExpanded] = useState(false)
  const { finding } = item

  const addMutation = useMutation({
    mutationFn: () => vgsApi.vulnerabilities.addFromFinding(versionId, finding.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vgs-report-vulnerabilities', versionId] })
      queryClient.invalidateQueries({ queryKey: ['vgs-available-findings', versionId] })
    },
  })

  return (
    <li className="rounded border border-gray-200 bg-white p-3 shadow-sm">
      <div className="flex items-center justify-between">
        <span className="font-medium">{finding.title}</span>
        <span className="flex items-center gap-2">
          <button onClick={() => setExpanded(!expanded)} className="text-xs text-purple-700 hover:underline">
            {expanded ? 'Hide details' : 'Details'}
          </button>
          {item.already_added ? (
            <span className="rounded bg-gray-100 px-2 py-1 text-xs font-medium text-gray-500">Added</span>
          ) : (
            <button
              onClick={() => addMutation.mutate()}
              disabled={addMutation.isPending}
              className="rounded bg-purple-700 px-2 py-1 text-xs font-medium text-white hover:bg-purple-800 disabled:opacity-50"
            >
              Add
            </button>
          )}
        </span>
      </div>
      <p className="mt-1 text-xs text-gray-600">
        {finding.severity} · CVSS {finding.cvss_score} · {finding.owasp_2025_category}
      </p>
      {expanded && (
        <div className="mt-2 space-y-1 text-xs text-gray-600">
          <p>{finding.plain_language_summary}</p>
          {finding.affected_endpoints.length > 0 && (
            <p className="text-gray-500">Endpoints: {finding.affected_endpoints.join(', ')}</p>
          )}
        </div>
      )}
    </li>
  )
}

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low']

function SelectedVulnerabilityRow({
  vuln,
  versionId,
}: {
  vuln: VgsReportVulnerabilityOut
  versionId: string
}) {
  const queryClient = useQueryClient()
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['vgs-report-vulnerabilities', versionId] })

  const severityMutation = useMutation({
    mutationFn: (severity: Severity) => vgsApi.vulnerabilities.update(versionId, vuln.id, { severity }),
    onSuccess: invalidate,
  })
  const removeMutation = useMutation({
    mutationFn: () => vgsApi.vulnerabilities.delete(versionId, vuln.id),
    onSuccess: invalidate,
  })

  return (
    <li className="rounded border border-gray-200 bg-purple-50 p-3">
      <div className="flex items-center justify-between">
        <span className="font-medium">{vuln.title}</span>
        <button onClick={() => removeMutation.mutate()} className="text-xs text-red-600 hover:underline">
          Remove
        </button>
      </div>
      <div className="mt-1 flex items-center gap-2 text-xs text-gray-600">
        <select
          value={vuln.severity}
          onChange={(e) => severityMutation.mutate(e.target.value as Severity)}
          disabled={severityMutation.isPending}
          className="rounded border border-gray-300 bg-white px-1.5 py-0.5 text-xs disabled:opacity-50"
        >
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <span>· CVSS {vuln.cvss_score}</span>
        {vuln.source_finding_id && (
          <span className="text-gray-400" title="Severity as originally identified by the scan; editable here for this report only">
            (from scan)
          </span>
        )}
      </div>
    </li>
  )
}

export function ReportVulnerabilitiesTab({ versionId }: { versionId: string }) {
  const queryClient = useQueryClient()
  const [searchTerm, setSearchTerm] = useState('')
  const [source, setSource] = useState<'findings' | 'library'>('findings')

  const { data: availableFindings } = useQuery({
    queryKey: ['vgs-available-findings', versionId],
    queryFn: () => vgsApi.availableFindings.list(versionId),
  })
  const { data: library } = useQuery({
    queryKey: ['vgs-vulnerability-library'],
    queryFn: vgsApi.library.list,
  })
  const { data: selected } = useQuery({
    queryKey: ['vgs-report-vulnerabilities', versionId],
    queryFn: () => vgsApi.vulnerabilities.list(versionId),
  })

  const [customTitle, setCustomTitle] = useState('')
  const [customSeverity, setCustomSeverity] = useState<Severity>('Medium')
  const [customDescription, setCustomDescription] = useState('')

  const addCustomMutation = useMutation({
    mutationFn: () =>
      vgsApi.vulnerabilities.addAdHoc(versionId, {
        title: customTitle,
        severity: customSeverity,
        description: customDescription,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vgs-report-vulnerabilities', versionId] })
      setCustomTitle('')
      setCustomDescription('')
    },
  })

  const filteredLibrary = (library ?? []).filter((v) => v.title.toLowerCase().includes(searchTerm.toLowerCase()))
  const filteredFindings = (availableFindings ?? []).filter((v) =>
    v.finding.title.toLowerCase().includes(searchTerm.toLowerCase()),
  )

  return (
    <div className="flex gap-6">
      <div className="w-1/2 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-gray-800">
            {source === 'findings' ? 'Scan Findings' : 'Vulnerability Library'}
          </h3>
          <div className="flex rounded border border-gray-300 text-xs">
            <button
              onClick={() => setSource('findings')}
              className={`px-2 py-1 ${source === 'findings' ? 'bg-purple-700 text-white' : 'text-gray-600'}`}
            >
              From scans ({availableFindings?.length ?? 0})
            </button>
            <button
              onClick={() => setSource('library')}
              className={`px-2 py-1 ${source === 'library' ? 'bg-purple-700 text-white' : 'text-gray-600'}`}
            >
              Library
            </button>
          </div>
        </div>
        <input
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search…"
          className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        {source === 'findings' ? (
          <ul className="max-h-[500px] space-y-2 overflow-y-auto">
            {filteredFindings.map((item) => (
              <FindingRow key={item.finding.id} item={item} versionId={versionId} />
            ))}
            {filteredFindings.length === 0 && (
              <p className="text-sm text-gray-400">
                No scan-confirmed findings yet — run a scan on this version first.
              </p>
            )}
          </ul>
        ) : (
          <ul className="max-h-[500px] space-y-2 overflow-y-auto">
            {filteredLibrary.map((entry) => (
              <LibraryEntryRow key={entry.id} entry={entry} versionId={versionId} />
            ))}
            {filteredLibrary.length === 0 && <p className="text-sm text-gray-400">No library entries yet.</p>}
          </ul>
        )}

        <details className="rounded border border-gray-200 bg-white p-3">
          <summary className="cursor-pointer text-sm font-medium text-gray-700">+ Add custom vulnerability</summary>
          <div className="mt-3 space-y-2">
            <input
              value={customTitle}
              onChange={(e) => setCustomTitle(e.target.value)}
              placeholder="Title"
              className="w-full rounded border border-gray-300 px-3 py-2 text-sm"
            />
            <select
              value={customSeverity}
              onChange={(e) => setCustomSeverity(e.target.value as Severity)}
              className="w-full rounded border border-gray-300 px-3 py-2 text-sm"
            >
              {(['Critical', 'High', 'Medium', 'Low'] as Severity[]).map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <textarea
              value={customDescription}
              onChange={(e) => setCustomDescription(e.target.value)}
              placeholder="Description"
              rows={2}
              className="w-full rounded border border-gray-300 px-3 py-2 text-sm"
            />
            <button
              onClick={() => addCustomMutation.mutate()}
              disabled={!customTitle.trim() || addCustomMutation.isPending}
              className="rounded bg-purple-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-purple-800 disabled:opacity-50"
            >
              Add custom
            </button>
          </div>
        </details>
      </div>

      <div className="w-1/2 space-y-3">
        <h3 className="font-semibold text-gray-800">Selected for this report ({selected?.length ?? 0})</h3>
        <ul className="max-h-[600px] space-y-2 overflow-y-auto">
          {(selected ?? []).map((v) => (
            <SelectedVulnerabilityRow key={v.id} vuln={v} versionId={versionId} />
          ))}
          {(selected ?? []).length === 0 && <p className="text-sm text-gray-400">Nothing selected yet.</p>}
        </ul>
      </div>
    </div>
  )
}
