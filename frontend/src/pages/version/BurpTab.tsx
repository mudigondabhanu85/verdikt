import { useState, type FormEvent } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../../api/client'
import type { BurpImportResult, BurpScanCreated } from '../../api/types'
import { useAuth, canWrite } from '../../auth/AuthContext'

function StartScanForm({ versionId }: { versionId: string }) {
  const [baseUrl, setBaseUrl] = useState('http://localhost:1337')
  const [apiKey, setApiKey] = useState('')
  const [urlsText, setUrlsText] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [created, setCreated] = useState<BurpScanCreated | null>(null)

  const startMutation = useMutation({
    mutationFn: () =>
      api.burp.startScan(versionId, {
        burp_base_url: baseUrl,
        burp_api_key: apiKey || undefined,
        urls: urlsText
          .split('\n')
          .map((u) => u.trim())
          .filter(Boolean),
      }),
    onSuccess: (result) => {
      setCreated(result)
      setError(null)
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Could not start scan'),
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!baseUrl.trim() || !urlsText.trim()) return
    setCreated(null)
    startMutation.mutate()
  }

  return (
    <form onSubmit={handleSubmit} className="mb-6 space-y-2 rounded border border-gray-200 bg-white p-4">
      <h3 className="text-sm font-medium text-gray-800">Start a Burp scan</h3>
      <p className="text-xs text-gray-500">
        Triggers a scan on Burp Suite Professional's local Scanner REST API — Burp Community Edition doesn't expose
        this.
      </p>
      <div className="flex flex-wrap gap-2">
        <input
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          placeholder="Burp base URL"
          className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <input
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="Burp API key (optional)"
          type="password"
          className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
      </div>
      <textarea
        value={urlsText}
        onChange={(e) => setUrlsText(e.target.value)}
        placeholder={'URLs to scan, one per line\nhttps://app.example.com/'}
        rows={3}
        className="w-full rounded border border-gray-300 px-3 py-2 font-mono text-xs focus:border-purple-500 focus:outline-none"
      />
      {error && <p className="text-sm text-red-600">{error}</p>}
      {created && (
        <p className="rounded border border-green-300 bg-green-50 px-3 py-2 text-sm text-green-800">
          Scan started (Burp task {created.task_id}). Once it finishes in Burp, import its results below into{' '}
          <Link to={`/scan-runs/${created.scan_run_id}`} className="underline">
            this scan run
          </Link>
          .
        </p>
      )}
      <button
        type="submit"
        disabled={startMutation.isPending}
        className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
      >
        {startMutation.isPending ? 'Starting…' : 'Start scan'}
      </button>
    </form>
  )
}

function ImportResultsForm({ versionId }: { versionId: string }) {
  const [baseUrl, setBaseUrl] = useState('http://localhost:1337')
  const [apiKey, setApiKey] = useState('')
  const [taskId, setTaskId] = useState('')
  const [scanRunId, setScanRunId] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<BurpImportResult | null>(null)

  const importMutation = useMutation({
    mutationFn: () =>
      api.burp.importResults(versionId, taskId, {
        burp_base_url: baseUrl,
        burp_api_key: apiKey || undefined,
        scan_run_id: scanRunId,
      }),
    onSuccess: (res) => {
      setResult(res)
      setError(null)
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Import failed'),
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!taskId.trim() || !scanRunId.trim()) return
    setResult(null)
    importMutation.mutate()
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-2 rounded border border-gray-200 bg-white p-4">
      <h3 className="text-sm font-medium text-gray-800">Import Burp scan results</h3>
      <p className="text-xs text-gray-500">
        This call blocks until Burp's scan reaches a terminal state — there's no separate status-check endpoint to
        poll instead, so the button below will just show "Importing…" for as long as the scan takes (Burp's own
        default poll timeout is one hour).
      </p>
      <div className="flex flex-wrap gap-2">
        <input
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          placeholder="Burp base URL"
          className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <input
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="Burp API key (optional)"
          type="password"
          className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <input
          value={taskId}
          onChange={(e) => setTaskId(e.target.value)}
          placeholder="Burp task ID"
          className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <input
          value={scanRunId}
          onChange={(e) => setScanRunId(e.target.value)}
          placeholder="scan run ID (from Start Scan above)"
          className="min-w-64 flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
      </div>
      {error && <p className="text-sm text-red-600">{error}</p>}
      {result && (
        <p className="rounded border border-green-300 bg-green-50 px-3 py-2 text-sm text-green-800">
          Scan {result.scan_status} — imported {result.imported_count} finding(s) into{' '}
          <Link to={`/scan-runs/${scanRunId}`} className="underline">
            the scan run
          </Link>
          .
        </p>
      )}
      <button
        type="submit"
        disabled={importMutation.isPending}
        className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
      >
        {importMutation.isPending ? 'Importing… (this may take a while)' : 'Import results'}
      </button>
    </form>
  )
}

export function BurpTab({ versionId }: { versionId: string }) {
  const { user } = useAuth()

  if (!canWrite(user?.role)) {
    return <p className="text-sm text-gray-500">Burp integration is managed by an org admin or project lead.</p>
  }

  return (
    <div>
      <StartScanForm versionId={versionId} />
      <ImportResultsForm versionId={versionId} />
    </div>
  )
}
