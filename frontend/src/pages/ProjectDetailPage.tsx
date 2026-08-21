import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { useAuth, canWrite } from '../auth/AuthContext'

export function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [name, setName] = useState('')

  const { data: project } = useQuery({
    queryKey: ['projects', projectId],
    queryFn: () => api.projects.get(projectId!),
    enabled: !!projectId,
  })

  const { data: versions, isLoading } = useQuery({
    queryKey: ['projects', projectId, 'versions'],
    queryFn: () => api.versions.list(projectId!),
    enabled: !!projectId,
  })

  const createMutation = useMutation({
    mutationFn: (body: { name: string }) => api.versions.create(projectId!, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'versions'] })
      setName('')
    },
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    createMutation.mutate({ name })
  }

  return (
    <div>
      <Link to="/" className="mb-2 inline-block text-sm text-purple-700 hover:underline">
        ← Projects
      </Link>
      <h1 className="mb-6 text-2xl font-semibold">{project?.name ?? 'Project'}</h1>

      <h2 className="mb-3 text-lg font-medium text-gray-800">Versions</h2>
      <p className="mb-4 text-sm text-gray-500">
        A Version is one engagement — its own scope, targets, credentials, authorization record, and scan runs.
      </p>

      {canWrite(user?.role) && (
        <form onSubmit={handleSubmit} className="mb-6 flex gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="New version name (e.g. 2026-Q1 pentest)"
            className="flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <button
            type="submit"
            disabled={createMutation.isPending}
            className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
          >
            Create
          </button>
        </form>
      )}

      {isLoading && <p className="text-gray-500">Loading…</p>}
      {versions && versions.length === 0 && <p className="text-gray-500">No versions yet.</p>}

      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {versions?.map((version) => (
          <li key={version.id}>
            <Link to={`/versions/${version.id}`} className="flex items-center justify-between px-4 py-3 hover:bg-gray-50">
              <span className="font-medium text-gray-900">{version.name}</span>
              {version.is_authorized ? (
                <span className="rounded-full border border-green-300 bg-green-100 px-2 py-0.5 text-xs text-green-800">
                  authorized
                </span>
              ) : (
                <span className="rounded-full border border-red-300 bg-red-100 px-2 py-0.5 text-xs text-red-800">
                  not authorized
                </span>
              )}
            </Link>
          </li>
        ))}
      </ul>
    </div>
  )
}
