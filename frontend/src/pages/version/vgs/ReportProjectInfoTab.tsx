import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { vgsApi } from './api'

export function ReportProjectInfoTab({ versionId }: { versionId: string }) {
  const queryClient = useQueryClient()
  const { data: draft, isLoading } = useQuery({
    queryKey: ['vgs-report-draft', versionId],
    queryFn: () => vgsApi.draft.get(versionId),
  })

  const [appTitle, setAppTitle] = useState('')
  const [requesterName, setRequesterName] = useState('')
  const [analystName, setAnalystName] = useState('')
  const [urls, setUrls] = useState('')
  const [scope, setScope] = useState('')

  useEffect(() => {
    if (draft) {
      setAppTitle(draft.app_title)
      setRequesterName(draft.requester_name)
      setAnalystName(draft.analyst_name)
      setUrls(draft.urls)
      setScope(draft.scope)
    }
  }, [draft])

  const saveMutation = useMutation({
    mutationFn: () =>
      vgsApi.draft.update(versionId, {
        app_title: appTitle,
        requester_name: requesterName,
        analyst_name: analystName,
        urls,
        scope,
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['vgs-report-draft', versionId] }),
  })

  if (isLoading) return <p className="text-gray-500">Loading…</p>

  return (
    <div className="mx-auto max-w-xl space-y-4">
      <h2 className="text-center text-lg font-semibold text-gray-800">Project Info</h2>

      <label className="block">
        <span className="mb-1 block text-sm font-medium text-gray-700">Application Title</span>
        <input
          value={appTitle}
          onChange={(e) => setAppTitle(e.target.value)}
          className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
      </label>

      <label className="block">
        <span className="mb-1 block text-sm font-medium text-gray-700">Requested By</span>
        <input
          value={requesterName}
          onChange={(e) => setRequesterName(e.target.value)}
          className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
      </label>

      <label className="block">
        <span className="mb-1 block text-sm font-medium text-gray-700">Analyst Name</span>
        <input
          value={analystName}
          onChange={(e) => setAnalystName(e.target.value)}
          className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
      </label>

      <label className="block">
        <span className="mb-1 block text-sm font-medium text-gray-700">URLs</span>
        <textarea
          rows={2}
          value={urls}
          onChange={(e) => setUrls(e.target.value)}
          placeholder="Enter comma-separated or multiple URLs"
          className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
      </label>

      <label className="block">
        <span className="mb-1 block text-sm font-medium text-gray-700">Scope</span>
        <textarea
          rows={2}
          value={scope}
          onChange={(e) => setScope(e.target.value)}
          className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
      </label>

      <button
        onClick={() => saveMutation.mutate()}
        disabled={saveMutation.isPending}
        className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
      >
        {saveMutation.isPending ? 'Saving…' : 'Save'}
      </button>
      {saveMutation.isSuccess && <span className="ml-3 text-xs text-green-600">Saved.</span>}
    </div>
  )
}
