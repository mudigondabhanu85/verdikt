import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { useAuth, canWrite } from '../../auth/AuthContext'

export function ScopeTab({ versionId }: { versionId: string }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [host, setHost] = useState('')
  const [port, setPort] = useState('')
  const [pathPattern, setPathPattern] = useState('')

  const { data: entries, isLoading } = useQuery({
    queryKey: ['versions', versionId, 'scope-entries'],
    queryFn: () => api.versions.listScopeEntries(versionId),
  })

  const createMutation = useMutation({
    mutationFn: () =>
      api.versions.createScopeEntry(versionId, {
        host,
        port: port ? Number(port) : null,
        path_pattern: pathPattern || null,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['versions', versionId, 'scope-entries'] })
      setHost('')
      setPort('')
      setPathPattern('')
    },
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!host.trim()) return
    createMutation.mutate()
  }

  return (
    <div>
      <p className="mb-4 text-sm text-gray-500">
        The technical allow-list every agent enforces on every request — nothing outside this list is ever touched.
      </p>
      {canWrite(user?.role) && (
        <form onSubmit={handleSubmit} className="mb-6 flex flex-wrap gap-2">
          <input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="host (e.g. app.example.com)"
            className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <input
            value={port}
            onChange={(e) => setPort(e.target.value)}
            placeholder="port (optional)"
            className="w-32 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <input
            value={pathPattern}
            onChange={(e) => setPathPattern(e.target.value)}
            placeholder="path pattern (optional)"
            className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
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
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-gray-200 text-gray-500">
            <th className="py-2">Host</th>
            <th className="py-2">Port</th>
            <th className="py-2">Path pattern</th>
            <th className="py-2">In scope</th>
          </tr>
        </thead>
        <tbody>
          {entries?.map((entry) => (
            <tr key={entry.id} className="border-b border-gray-100">
              <td className="py-2">{entry.host}</td>
              <td className="py-2">{entry.port ?? 'any'}</td>
              <td className="py-2">{entry.path_pattern ?? '*'}</td>
              <td className="py-2">{entry.in_scope ? 'yes' : 'no (excluded)'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
