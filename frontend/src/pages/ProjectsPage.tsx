import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useAuth, canWrite } from '../auth/AuthContext'

export function ProjectsPage() {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [name, setName] = useState('')

  const { data: projects, isLoading } = useQuery({
    queryKey: ['projects'],
    queryFn: api.projects.list,
  })

  const createMutation = useMutation({
    mutationFn: (body: { name: string }) => api.projects.create(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects'] })
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
      <h1 className="mb-6 text-2xl font-semibold">Projects</h1>

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
          <li key={project.id}>
            <Link to={`/projects/${project.id}`} className="block px-4 py-3 hover:bg-gray-50">
              <span className="font-medium text-gray-900">{project.name}</span>
              <span className="ml-3 text-xs text-gray-400">
                created {new Date(project.created_at).toLocaleDateString()}
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  )
}
