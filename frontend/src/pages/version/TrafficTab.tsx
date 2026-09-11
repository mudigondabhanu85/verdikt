import { useRef, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../../api/client'
import { useAuth, canWrite } from '../../auth/AuthContext'
import { StatusBadge } from '../../components/Badges'

const SOURCE_LABELS: Record<string, string> = {
  manual: 'Manual',
  burp_live: 'Burp (live)',
  har: 'HAR file',
  burp_file: 'Burp file',
  zst_traffic: 'Zest (.zst)',
  webinspect_macro: 'WebInspect macro',
  agent: 'Agent',
}

// Matches backend MAX_TRAFFIC_IMPORT_BYTES (traffic_import.py) — checked
// here too so an oversized file fails fast with a clear message instead
// of sitting in "Importing…" for however long the upload takes before
// the server-side cap rejects it.
const MAX_IMPORT_SIZE_MB = 2048

function ImportSection({ versionId }: { versionId: string }) {
  const queryClient = useQueryClient()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [result, setResult] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const importMutation = useMutation({
    mutationFn: (file: File) => api.traffic.importFile(versionId, file),
    onSuccess: (res) => {
      setError(null)
      setResult(`Imported ${res.imported_count} interaction(s).`)
      queryClient.invalidateQueries({ queryKey: ['versions', versionId, 'traffic'] })
      if (fileInputRef.current) fileInputRef.current.value = ''
    },
    onError: (err) => {
      setResult(null)
      setError(err instanceof ApiError ? err.message : 'Import failed')
    },
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const file = fileInputRef.current?.files?.[0]
    if (!file) return
    setResult(null)
    if (file.size > MAX_IMPORT_SIZE_MB * 1024 * 1024) {
      setError(`File is ${(file.size / (1024 * 1024)).toFixed(0)}MB — the import limit is ${MAX_IMPORT_SIZE_MB}MB.`)
      return
    }
    setError(null)
    importMutation.mutate(file)
  }

  return (
    <form onSubmit={handleSubmit} className="mb-6 rounded border border-gray-200 bg-white p-4">
      <h3 className="mb-1 text-sm font-medium text-gray-800">Import a traffic file</h3>
      <p className="mb-3 text-xs text-gray-500">
        Supported today: .har, .zst (Zest), OpenAPI/Swagger (.yaml/.yml, or .json), Postman collections (.json —
        auto-detected by content, same extension as HAR), and Burp's "Save selected items"/"Save all items" XML
        export (.burp, including extensionless — Proxy &gt; HTTP history, right-click &gt; Save selected items).
        Imported API endpoints get scanned directly with no crawling needed; attach an "API token" credential
        (Credentials tab) to authenticate the requests. Burp's separate proprietary full-project save (Project &gt;
        Save/Save as) and .webmacro are recognized but report a clean "not yet supported" error rather than failing
        silently — the former is an undocumented binary format, the latter had no real sample export available to
        build against. Up to {MAX_IMPORT_SIZE_MB}MB per file.
      </p>
      <div className="flex gap-2">
        {/* No `accept` filter — an extensionless Burp export would be hidden by the OS
            file picker's "matching files only" view if we restricted it to specific
            extensions (HTML's accept attribute has no wildcard for "no extension"). The
            backend validates the actual file type and reports a clear error either way. */}
        <input ref={fileInputRef} type="file" className="text-sm" />
        <button
          type="submit"
          disabled={importMutation.isPending}
          className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
        >
          {importMutation.isPending ? 'Importing…' : 'Import'}
        </button>
      </div>
      {result && <p className="mt-2 text-sm text-green-700">{result}</p>}
      {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
    </form>
  )
}

function ManualEntrySection({ versionId }: { versionId: string }) {
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [method, setMethod] = useState('GET')
  const [url, setUrl] = useState('')
  const [requestBody, setRequestBody] = useState('')
  const [status, setStatus] = useState('200')
  const [responseBody, setResponseBody] = useState('')
  const [error, setError] = useState<string | null>(null)

  const addMutation = useMutation({
    mutationFn: () =>
      api.traffic.addManual(versionId, {
        request: { method, url, headers: {}, query_params: {}, body: requestBody || null },
        response: { status: status ? Number(status) : null, headers: {}, body: responseBody || null, timing_ms: null },
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['versions', versionId, 'traffic'] })
      setUrl('')
      setRequestBody('')
      setResponseBody('')
      setError(null)
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Failed to add interaction'),
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!url.trim()) return
    addMutation.mutate()
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="mb-6 text-sm text-purple-700 hover:underline"
      >
        + Add a single request/response manually
      </button>
    )
  }

  return (
    <form onSubmit={handleSubmit} className="mb-6 space-y-2 rounded border border-gray-200 bg-white p-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-gray-800">Add a single interaction</h3>
        <button type="button" onClick={() => setOpen(false)} className="text-xs text-gray-400 hover:underline">
          cancel
        </button>
      </div>
      <div className="flex gap-2">
        <select value={method} onChange={(e) => setMethod(e.target.value)} className="rounded border border-gray-300 px-3 py-2 text-sm">
          {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="URL"
          className="flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <input
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          placeholder="response status"
          className="w-32 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
      </div>
      <textarea
        value={requestBody}
        onChange={(e) => setRequestBody(e.target.value)}
        placeholder="request body (optional)"
        rows={2}
        className="w-full rounded border border-gray-300 px-3 py-2 font-mono text-xs focus:border-purple-500 focus:outline-none"
      />
      <textarea
        value={responseBody}
        onChange={(e) => setResponseBody(e.target.value)}
        placeholder="response body (optional)"
        rows={2}
        className="w-full rounded border border-gray-300 px-3 py-2 font-mono text-xs focus:border-purple-500 focus:outline-none"
      />
      {error && <p className="text-sm text-red-600">{error}</p>}
      <button
        type="submit"
        disabled={addMutation.isPending}
        className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
      >
        Add interaction
      </button>
    </form>
  )
}

export function TrafficTab({ versionId }: { versionId: string }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [expanded, setExpanded] = useState<string | null>(null)

  const { data: interactions, isLoading } = useQuery({
    queryKey: ['versions', versionId, 'traffic'],
    queryFn: () => api.traffic.list(versionId),
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['versions', versionId, 'traffic'] })

  const deleteMutation = useMutation({
    mutationFn: (interactionId: string) => api.traffic.deleteInteraction(versionId, interactionId),
    onSuccess: invalidate,
  })

  const clearAllMutation = useMutation({
    mutationFn: () => api.traffic.clearAll(versionId),
    onSuccess: invalidate,
  })

  return (
    <div>
      <p className="mb-4 text-sm text-gray-500">
        Traffic recorded outside a scan run — a HAR export, a Zest script, or a request the Montoya Burp extension's
        "Send to Verdikt" action captured. Every scan feeds this in automatically: each URL here is added to the
        site map for injection/XSS/etc. to test directly, and the crawler now also follows links reachable from
        these URLs (not just the URLs themselves) — this is what makes a client-rendered SPA's real API surface
        testable at all, since it never shows up in a plain crawl's static HTML.
      </p>

      {canWrite(user?.role) && (
        <>
          <ImportSection versionId={versionId} />
          <ManualEntrySection versionId={versionId} />
        </>
      )}

      {isLoading && <p className="text-gray-500">Loading…</p>}
      {interactions && interactions.length === 0 && <p className="text-gray-500">No traffic recorded yet.</p>}

      {canWrite(user?.role) && interactions && interactions.length > 0 && (
        <div className="mb-2 flex justify-end">
          <button
            onClick={() => {
              if (confirm(`Delete all ${interactions.length} traffic interaction(s) for this version?`)) {
                clearAllMutation.mutate()
              }
            }}
            disabled={clearAllMutation.isPending}
            className="text-xs text-red-600 hover:underline disabled:opacity-50"
          >
            Clear all
          </button>
        </div>
      )}

      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {interactions?.map((interaction) => (
          <li key={interaction.id}>
            <div className="flex w-full items-center justify-between px-4 py-3 text-left text-sm hover:bg-gray-50">
              <button
                onClick={() => setExpanded(expanded === interaction.id ? null : interaction.id)}
                className="flex min-w-0 flex-1 items-center gap-3 text-left"
              >
                <span className="w-16 shrink-0 font-mono text-xs text-gray-500">{interaction.request.method}</span>
                <span className="truncate">{interaction.request.url}</span>
              </button>
              <span className="flex shrink-0 items-center gap-2">
                {interaction.response.status && (
                  <span className="font-mono text-xs text-gray-500">{interaction.response.status}</span>
                )}
                <StatusBadge status={SOURCE_LABELS[interaction.source] ?? interaction.source} />
                <span className="text-xs text-gray-400">{new Date(interaction.timestamp).toLocaleString()}</span>
                {canWrite(user?.role) && (
                  <button
                    onClick={() => deleteMutation.mutate(interaction.id)}
                    disabled={deleteMutation.isPending}
                    className="text-xs text-red-600 hover:underline disabled:opacity-50"
                  >
                    Delete
                  </button>
                )}
              </span>
            </div>
            {expanded === interaction.id && (
              <div className="space-y-2 border-t border-gray-100 bg-gray-50 px-4 py-4 text-sm">
                <div>
                  <h4 className="mb-1 text-xs font-medium uppercase text-gray-500">Request</h4>
                  <pre className="overflow-x-auto rounded bg-white p-2 text-xs text-gray-700">
                    {interaction.request.method} {interaction.request.url}
                    {interaction.request.body ? `\n\n${interaction.request.body}` : ''}
                  </pre>
                </div>
                <div>
                  <h4 className="mb-1 text-xs font-medium uppercase text-gray-500">Response</h4>
                  <pre className="overflow-x-auto rounded bg-white p-2 text-xs text-gray-700">
                    {interaction.response.status ?? '—'}
                    {interaction.response.body ? `\n\n${interaction.response.body}` : ''}
                  </pre>
                </div>
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}
