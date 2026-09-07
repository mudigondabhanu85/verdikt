import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { ScopeEntryOut } from '../../api/types'
import { useAuth, canWrite } from '../../auth/AuthContext'

function ScopeEntryRow({ entry, versionId }: { entry: ScopeEntryOut; versionId: string }) {
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [host, setHost] = useState(entry.host)
  const [port, setPort] = useState(entry.port?.toString() ?? '')
  const [pathPattern, setPathPattern] = useState(entry.path_pattern ?? '')
  const [inScope, setInScope] = useState(entry.in_scope)

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['versions', versionId, 'scope-entries'] })

  const updateMutation = useMutation({
    mutationFn: () =>
      api.versions.updateScopeEntry(versionId, entry.id, {
        host,
        port: port ? Number(port) : null,
        path_pattern: pathPattern || null,
        in_scope: inScope,
      }),
    onSuccess: () => {
      invalidate()
      setEditing(false)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.versions.deleteScopeEntry(versionId, entry.id),
    onSuccess: invalidate,
  })

  if (editing) {
    return (
      <tr className="border-b border-gray-100">
        <td className="py-2 pr-2">
          <input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            className="w-full rounded border border-gray-300 px-2 py-1 text-sm"
          />
        </td>
        <td className="py-2 pr-2">
          <input
            value={port}
            onChange={(e) => setPort(e.target.value)}
            placeholder="any"
            className="w-20 rounded border border-gray-300 px-2 py-1 text-sm"
          />
        </td>
        <td className="py-2 pr-2">
          <input
            value={pathPattern}
            onChange={(e) => setPathPattern(e.target.value)}
            placeholder="*"
            className="w-full rounded border border-gray-300 px-2 py-1 text-sm"
          />
        </td>
        <td className="py-2 pr-2">
          <select
            value={inScope ? 'yes' : 'no'}
            onChange={(e) => setInScope(e.target.value === 'yes')}
            className="rounded border border-gray-300 px-2 py-1 text-sm"
          >
            <option value="yes">yes</option>
            <option value="no">no (excluded)</option>
          </select>
        </td>
        <td className="py-2">
          <span className="flex gap-2">
            <button
              onClick={() => updateMutation.mutate()}
              disabled={!host.trim() || updateMutation.isPending}
              className="text-xs font-medium text-purple-700 hover:underline disabled:opacity-40"
            >
              Save
            </button>
            <button onClick={() => setEditing(false)} className="text-xs text-gray-500 hover:underline">
              Cancel
            </button>
          </span>
        </td>
      </tr>
    )
  }

  return (
    <tr className="border-b border-gray-100">
      <td className="py-2">{entry.host}</td>
      <td className="py-2">{entry.port ?? 'any'}</td>
      <td className="py-2">{entry.path_pattern ?? '*'}</td>
      <td className="py-2">{entry.in_scope ? 'yes' : 'no (excluded)'}</td>
      <td className="py-2">
        <span className="flex gap-2">
          <button onClick={() => setEditing(true)} className="text-xs text-purple-700 hover:underline">
            Edit
          </button>
          <button
            onClick={() => deleteMutation.mutate()}
            disabled={deleteMutation.isPending}
            className="text-xs text-red-600 hover:underline disabled:opacity-40"
          >
            Delete
          </button>
        </span>
      </td>
    </tr>
  )
}

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
        The technical allow-list every agent enforces on every request — nothing outside this list is ever
        touched. Adding a Target under the Targets tab auto-creates its matching entry here, so you usually
        won't need to add one by hand.
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
            {canWrite(user?.role) && <th className="py-2">Actions</th>}
          </tr>
        </thead>
        <tbody>
          {entries?.map((entry) =>
            canWrite(user?.role) ? (
              <ScopeEntryRow key={entry.id} entry={entry} versionId={versionId} />
            ) : (
              <tr key={entry.id} className="border-b border-gray-100">
                <td className="py-2">{entry.host}</td>
                <td className="py-2">{entry.port ?? 'any'}</td>
                <td className="py-2">{entry.path_pattern ?? '*'}</td>
                <td className="py-2">{entry.in_scope ? 'yes' : 'no (excluded)'}</td>
              </tr>
            ),
          )}
        </tbody>
      </table>
    </div>
  )
}
