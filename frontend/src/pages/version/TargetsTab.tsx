import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { useAuth, canWrite } from '../../auth/AuthContext'

export function TargetsTab({ versionId }: { versionId: string }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [host, setHost] = useState('')
  const [port, setPort] = useState('')
  const [baseUrl, setBaseUrl] = useState('')

  const { data: targets, isLoading } = useQuery({
    queryKey: ['versions', versionId, 'targets'],
    queryFn: () => api.targets.list(versionId),
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['versions', versionId, 'targets'] })

  const createMutation = useMutation({
    mutationFn: () =>
      api.targets.create(versionId, { host, port: port ? Number(port) : null, base_url: baseUrl || null }),
    onSuccess: () => {
      invalidate()
      setHost('')
      setPort('')
      setBaseUrl('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (targetId: string) => api.targets.delete(versionId, targetId),
    onSuccess: invalidate,
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!host.trim()) return
    createMutation.mutate()
  }

  return (
    <div>
      <p className="mb-4 text-sm text-gray-500">Where recon starts crawling from — the entry point(s) for this engagement.</p>
      {canWrite(user?.role) && (
        <form onSubmit={handleSubmit} className="mb-6 flex flex-wrap gap-2">
          <input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="host"
            className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <input
            value={port}
            onChange={(e) => setPort(e.target.value)}
            placeholder="port (optional)"
            className="w-32 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <input
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="base URL (e.g. https://app.example.com/)"
            className="min-w-64 flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <button
            type="submit"
            disabled={createMutation.isPending}
            className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
          >
            Add
          </button>
        </form>
      )}

      {isLoading && <p className="text-gray-500">Loading…</p>}
      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {targets?.map((target) => (
          <li key={target.id} className="flex items-center justify-between px-4 py-3">
            <span>
              <span className="font-medium">{target.host}</span>
              {target.port && <span className="text-gray-400">:{target.port}</span>}
              {target.base_url && <span className="ml-2 text-gray-500">{target.base_url}</span>}
            </span>
            {canWrite(user?.role) && (
              <button
                onClick={() => deleteMutation.mutate(target.id)}
                className="text-xs text-red-600 hover:underline"
              >
                Delete
              </button>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}
