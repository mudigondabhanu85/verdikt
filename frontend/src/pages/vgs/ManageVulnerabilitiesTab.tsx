import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { vgsApi, type Severity, type VgsVulnerabilityLibraryEntryInput, type VgsVulnerabilityLibraryEntryOut } from '../version/vgs/api'

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low']

const EMPTY_FORM: VgsVulnerabilityLibraryEntryInput = {
  title: '',
  severity: 'Medium',
  cvss_score: '',
  cvss_vector: '',
  description: '',
  recommendation: '',
  reference: '',
}

function EntryForm({
  initial,
  onSubmit,
  onCancel,
  submitLabel,
}: {
  initial: VgsVulnerabilityLibraryEntryInput
  onSubmit: (body: VgsVulnerabilityLibraryEntryInput) => void
  onCancel?: () => void
  submitLabel: string
}) {
  const [form, setForm] = useState(initial)

  return (
    <div className="space-y-2">
      <input
        value={form.title}
        onChange={(e) => setForm({ ...form, title: e.target.value })}
        placeholder="Title"
        className="w-full rounded border border-gray-300 px-3 py-2 text-sm"
      />
      <div className="flex gap-2">
        <select
          value={form.severity}
          onChange={(e) => setForm({ ...form, severity: e.target.value as Severity })}
          className="rounded border border-gray-300 px-3 py-2 text-sm"
        >
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <input
          value={form.cvss_score ?? ''}
          onChange={(e) => setForm({ ...form, cvss_score: e.target.value })}
          placeholder="CVSS score"
          className="w-32 rounded border border-gray-300 px-3 py-2 text-sm"
        />
        <input
          value={form.cvss_vector ?? ''}
          onChange={(e) => setForm({ ...form, cvss_vector: e.target.value })}
          placeholder="CVSS vector"
          className="flex-1 rounded border border-gray-300 px-3 py-2 text-sm"
        />
      </div>
      <textarea
        value={form.description ?? ''}
        onChange={(e) => setForm({ ...form, description: e.target.value })}
        placeholder="Description"
        rows={3}
        className="w-full rounded border border-gray-300 px-3 py-2 text-sm"
      />
      <textarea
        value={form.recommendation ?? ''}
        onChange={(e) => setForm({ ...form, recommendation: e.target.value })}
        placeholder="Recommendation / remediation"
        rows={2}
        className="w-full rounded border border-gray-300 px-3 py-2 text-sm"
      />
      <input
        value={form.reference ?? ''}
        onChange={(e) => setForm({ ...form, reference: e.target.value })}
        placeholder="Reference URL"
        className="w-full rounded border border-gray-300 px-3 py-2 text-sm"
      />
      <div className="flex gap-2">
        <button
          onClick={() => onSubmit(form)}
          disabled={!form.title.trim()}
          className="rounded bg-purple-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-purple-800 disabled:opacity-50"
        >
          {submitLabel}
        </button>
        {onCancel && (
          <button onClick={onCancel} className="rounded border border-gray-300 px-3 py-1.5 text-xs text-gray-600 hover:bg-gray-50">
            Cancel
          </button>
        )}
      </div>
    </div>
  )
}

function LibraryEntryCard({ entry }: { entry: VgsVulnerabilityLibraryEntryOut }) {
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState(false)

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['vgs-vulnerability-library'] })

  const updateMutation = useMutation({
    mutationFn: (body: VgsVulnerabilityLibraryEntryInput) => vgsApi.library.update(entry.id, body),
    onSuccess: () => {
      invalidate()
      setEditing(false)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: () => vgsApi.library.delete(entry.id),
    onSuccess: invalidate,
  })

  if (editing) {
    return (
      <li className="rounded border border-gray-200 bg-white p-3 shadow-sm">
        <EntryForm initial={entry} onSubmit={(body) => updateMutation.mutate(body)} onCancel={() => setEditing(false)} submitLabel="Save" />
      </li>
    )
  }

  return (
    <li className="rounded border border-gray-200 bg-white p-3 shadow-sm">
      <div className="flex items-start justify-between">
        <div>
          <span className="font-medium">{entry.title}</span>
          <span className="ml-2 text-xs text-gray-500">
            {entry.severity} · CVSS {entry.cvss_score || '—'}
          </span>
        </div>
        <span className="flex gap-2">
          <button onClick={() => setEditing(true)} className="text-xs text-purple-700 hover:underline">
            Edit
          </button>
          <button onClick={() => deleteMutation.mutate()} className="text-xs text-red-600 hover:underline">
            Delete
          </button>
        </span>
      </div>
      {entry.description && <p className="mt-1 text-xs text-gray-600">{entry.description}</p>}
    </li>
  )
}

export function ManageVulnerabilitiesTab() {
  const queryClient = useQueryClient()
  const [showAdd, setShowAdd] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')

  const { data: library } = useQuery({
    queryKey: ['vgs-vulnerability-library'],
    queryFn: vgsApi.library.list,
  })

  const createMutation = useMutation({
    mutationFn: (body: VgsVulnerabilityLibraryEntryInput) => vgsApi.library.create(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vgs-vulnerability-library'] })
      setShowAdd(false)
    },
  })

  const filtered = (library ?? []).filter((v) => v.title.toLowerCase().includes(searchTerm.toLowerCase()))

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-800">Vulnerability Library</h2>
        <button
          onClick={() => setShowAdd(!showAdd)}
          className="rounded bg-purple-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-purple-800"
        >
          {showAdd ? 'Close' : '+ Add vulnerability'}
        </button>
      </div>
      <p className="text-sm text-gray-500">
        Reusable vulnerability write-ups (title, severity, CVSS, description, remediation). Anyone building a
        report picks from this library in the Vulnerability Picker tab instead of retyping the same write-up
        every time.
      </p>

      {showAdd && (
        <div className="rounded border border-gray-200 bg-white p-3 shadow-sm">
          <EntryForm initial={EMPTY_FORM} onSubmit={(body) => createMutation.mutate(body)} submitLabel="Add to library" />
        </div>
      )}

      <input
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
        placeholder="Search…"
        className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
      />

      <ul className="space-y-2">
        {filtered.map((entry) => (
          <LibraryEntryCard key={entry.id} entry={entry} />
        ))}
        {filtered.length === 0 && <p className="text-sm text-gray-400">No library entries yet.</p>}
      </ul>
    </div>
  )
}
