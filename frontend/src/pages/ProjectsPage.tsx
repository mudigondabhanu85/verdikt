import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useAuth, canWrite } from '../auth/AuthContext'

export function ProjectsPage() {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [includeArchived, setIncludeArchived] = useState(false)
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null)
  const [deleteConfirmText, setDeleteConfirmText] = useState('')

  const { data: projects, isLoading } = useQuery({
    queryKey: ['projects', includeArchived],
    queryFn: () => api.projects.list(includeArchived),
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['projects'] })

  const createMutation = useMutation({
    mutationFn: (body: { name: string }) => api.projects.create(body),
    onSuccess: () => {
      invalidate()
      setName('')
    },
  })

  const archiveMutation = useMutation({
    mutationFn: (id: string) => api.projects.archive(id),
    onSuccess: invalidate,
  })

  const unarchiveMutation = useMutation({
    mutationFn: (id: string) => api.projects.unarchive(id),
    onSuccess: invalidate,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.projects.delete(id),
    onSuccess: () => {
      invalidate()
      setDeleteConfirmId(null)
      setDeleteConfirmText('')
    },
  })
  const deleteError =
    deleteMutation.isError && deleteMutation.variables === deleteConfirmId
      ? (deleteMutation.error as Error).message
      : null

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    createMutation.mutate({ name })
  }

  const isOrgAdmin = user?.role === 'org_admin'

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Projects</h1>
        <label className="flex items-center gap-2 text-xs text-gray-500">
          <input
            type="checkbox"
            checked={includeArchived}
            onChange={(e) => setIncludeArchived(e.target.checked)}
          />
          Show archived
        </label>
      </div>

      {canWrite(user?.role) && (
        <form onSubmit={handleSubmit} className="mb-6 flex gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="New project name"
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
      {projects && projects.length === 0 && <p className="text-gray-500">No projects yet.</p>}

      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {projects?.map((project) => (
          <li key={project.id} className="flex items-center justify-between px-4 py-3">
            <Link to={`/projects/${project.id}`} className="flex-1 hover:opacity-80">
              <span className="font-medium text-gray-900">{project.name}</span>
              <span className="ml-3 text-xs text-gray-400">
                created {new Date(project.created_at).toLocaleDateString()}
              </span>
              {project.archived_at && <span className="ml-2 text-xs text-amber-600">archived</span>}
            </Link>

            {canWrite(user?.role) && (
              <span className="flex items-center gap-3">
                {project.archived_at ? (
                  <button
                    onClick={() => unarchiveMutation.mutate(project.id)}
                    className="text-xs text-purple-700 hover:underline"
                  >
                    Unarchive
                  </button>
                ) : (
                  <button
                    onClick={() => archiveMutation.mutate(project.id)}
                    className="text-xs text-gray-600 hover:underline"
                  >
                    Archive
                  </button>
                )}
                {isOrgAdmin &&
                  (deleteConfirmId === project.id ? (
                    <span className="flex items-center gap-1">
                      <input
                        autoFocus
                        value={deleteConfirmText}
                        onChange={(e) => setDeleteConfirmText(e.target.value)}
                        placeholder={`type "${project.name}"`}
                        className="w-40 rounded border border-red-300 px-2 py-1 text-xs"
                      />
                      <button
                        disabled={deleteConfirmText !== project.name || deleteMutation.isPending}
                        onClick={() => deleteMutation.mutate(project.id)}
                        className="text-xs font-medium text-red-700 hover:underline disabled:opacity-40"
                      >
                        Confirm delete
                      </button>
                      <button
                        onClick={() => {
                          setDeleteConfirmId(null)
                          setDeleteConfirmText('')
                        }}
                        className="text-xs text-gray-500 hover:underline"
                      >
                        Cancel
                      </button>
                      {deleteError && <span className="text-xs text-red-600">{deleteError}</span>}
                    </span>
                  ) : (
                    <button
                      onClick={() => setDeleteConfirmId(project.id)}
                      className="text-xs text-red-600 hover:underline"
                    >
                      Delete
                    </button>
                  ))}
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}
