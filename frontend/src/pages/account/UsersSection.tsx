import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../../api/client'
import { BASELINE_ROLES, type Role, type UserOut } from '../../api/types'

// A project multi-select, shown only for roles ProjectMembership actually
// restricts — org_admin always sees every project regardless of what's
// assigned (see backend/app/api/deps.py's own docstring), so showing this
// control for one would be a lie about what it does. Submits the whole
// selected set on every change (a PUT, matching the backend's own
// "replace, don't add/remove incrementally" contract), not per-checkbox.
function ProjectAssignmentControl({
  user,
  projects,
}: {
  user: UserOut
  projects: { id: string; name: string }[]
}) {
  const queryClient = useQueryClient()
  const [pending, setPending] = useState<string[] | null>(null)
  const selected = pending ?? user.project_ids

  const updateMutation = useMutation({
    mutationFn: (projectIds: string[]) => api.users.updateProjectMemberships(user.id, projectIds),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setPending(null)
    },
    onError: () => setPending(null),
  })

  function toggle(projectId: string, checked: boolean) {
    const next = checked ? [...selected, projectId] : selected.filter((id) => id !== projectId)
    setPending(next)
    updateMutation.mutate(next)
  }

  if (projects.length === 0) {
    return <span className="text-xs text-gray-400">No projects to assign yet</span>
  }

  return (
    <details className="text-xs">
      <summary className="cursor-pointer text-purple-700 hover:underline">
        {selected.length === 0 ? 'No projects assigned' : `${selected.length} project(s) assigned`}
      </summary>
      <ul className="mt-2 max-h-40 space-y-1 overflow-y-auto rounded border border-gray-200 bg-gray-50 p-2">
        {projects.map((p) => (
          <li key={p.id}>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={selected.includes(p.id)}
                disabled={updateMutation.isPending}
                onChange={(e) => toggle(p.id, e.target.checked)}
              />
              {p.name}
            </label>
          </li>
        ))}
      </ul>
    </details>
  )
}

function RoleControl({ user }: { user: UserOut }) {
  const queryClient = useQueryClient()
  const [error, setError] = useState<string | null>(null)

  const updateMutation = useMutation({
    mutationFn: (role: Role) => api.users.updateRole(user.id, role),
    onSuccess: () => {
      setError(null)
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Could not change role'),
  })

  return (
    <span className="inline-flex flex-col">
      <select
        value={user.role}
        disabled={updateMutation.isPending}
        onChange={(e) => updateMutation.mutate(e.target.value as Role)}
        className="rounded border border-gray-300 px-2 py-1 text-xs focus:border-purple-500 focus:outline-none"
      >
        {BASELINE_ROLES.map((r) => (
          <option key={r} value={r}>
            {r}
          </option>
        ))}
      </select>
      {error && <span className="mt-1 text-xs text-red-600">{error}</span>}
    </span>
  )
}

export function UsersSection() {
  const queryClient = useQueryClient()
  const [email, setEmail] = useState('')
  const [role, setRole] = useState<Role>('analyst')
  const [setPasswordDirectly, setSetPasswordDirectly] = useState(false)
  const [password, setPassword] = useState('')
  const [lastInviteLink, setLastInviteLink] = useState<string | null>(null)
  const [lastDirectAccount, setLastDirectAccount] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const { data: users, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: api.users.list,
  })
  const { data: projects } = useQuery({
    queryKey: ['projects', 'all-for-assignment'],
    queryFn: () => api.projects.list(true),
  })
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['users'] })

  const inviteMutation = useMutation({
    mutationFn: () =>
      api.users.invite({ email, role, password: setPasswordDirectly ? password : undefined }),
    onSuccess: (invited) => {
      invalidate()
      if (invited.invite_token) {
        setLastInviteLink(`${window.location.origin}/accept-invite?token=${invited.invite_token}`)
        setLastDirectAccount(null)
      } else {
        setLastDirectAccount(invited.email)
        setLastInviteLink(null)
      }
      setEmail('')
      setPassword('')
      setError(null)
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Invite failed'),
  })

  const deactivateMutation = useMutation({
    mutationFn: (id: string) => api.users.deactivate(id),
    onSuccess: invalidate,
  })

  const reactivateMutation = useMutation({
    mutationFn: (id: string) => api.users.reactivate(id),
    onSuccess: invalidate,
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!email.trim()) return
    if (setPasswordDirectly && password.length < 8) return
    inviteMutation.mutate()
  }

  return (
    <section className="mb-10">
      <h2 className="mb-3 text-lg font-medium text-gray-800">Users</h2>
      <p className="mb-4 text-sm text-gray-500">
        Invite teammates by email and assign a role, or set their password directly instead of sending an
        invite link. Deactivated users can't log in but keep their audit history. org_admin always sees every
        project; every other role only sees the projects assigned to them below.
      </p>

      <form onSubmit={handleSubmit} className="mb-4 flex flex-wrap items-center gap-2">
        <input
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="teammate@company.com"
          type="email"
          className="min-w-64 flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <select
          value={role}
          onChange={(e) => setRole(e.target.value as Role)}
          className="rounded border border-gray-300 px-3 py-2 text-sm"
        >
          {BASELINE_ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <label className="flex items-center gap-1 text-xs text-gray-600">
          <input
            type="checkbox"
            checked={setPasswordDirectly}
            onChange={(e) => setSetPasswordDirectly(e.target.checked)}
          />
          Set password directly
        </label>
        {setPasswordDirectly && (
          <input
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="password (min. 8 characters)"
            type="password"
            minLength={8}
            className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
        )}
        <button
          type="submit"
          disabled={inviteMutation.isPending}
          className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
        >
          {setPasswordDirectly ? 'Create user' : 'Invite'}
        </button>
      </form>

      {error && <p className="mb-3 text-sm text-red-600">{error}</p>}
      {lastInviteLink && (
        <div className="mb-4 rounded border border-purple-200 bg-purple-50 px-3 py-2 text-xs">
          <p className="mb-1 font-medium text-purple-800">Invite link (shown once — copy it now):</p>
          <input
            readOnly
            value={lastInviteLink}
            onFocus={(e) => e.currentTarget.select()}
            className="w-full rounded border border-purple-200 bg-white px-2 py-1 font-mono text-xs"
          />
        </div>
      )}
      {lastDirectAccount && (
        <p className="mb-4 rounded border border-green-200 bg-green-50 px-3 py-2 text-xs text-green-800">
          {lastDirectAccount} can log in now with the password you set — no invite link needed.
        </p>
      )}

      {isLoading && <p className="text-gray-500">Loading…</p>}
      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {users?.map((u) => (
          <li key={u.id} className="flex items-center justify-between gap-3 px-4 py-3 text-sm">
            <span>
              <span className="font-medium">{u.email}</span>
              {u.invited_at && !u.invite_accepted_at && (
                <span className="ml-2 text-xs text-amber-600">pending invite</span>
              )}
              {!u.is_active && <span className="ml-2 text-xs text-red-600">deactivated</span>}
              <br />
              {u.role !== 'org_admin' ? (
                <ProjectAssignmentControl user={u} projects={projects ?? []} />
              ) : (
                <span className="text-xs text-gray-400">All projects (org_admin)</span>
              )}
            </span>
            <span className="flex items-center gap-3">
              <RoleControl user={u} />
              {u.is_active ? (
                <button
                  onClick={() => deactivateMutation.mutate(u.id)}
                  disabled={deactivateMutation.isPending}
                  className="text-xs text-red-600 hover:underline"
                >
                  Deactivate
                </button>
              ) : (
                <button
                  onClick={() => reactivateMutation.mutate(u.id)}
                  disabled={reactivateMutation.isPending}
                  className="text-xs text-purple-700 hover:underline"
                >
                  Reactivate
                </button>
              )}
            </span>
          </li>
        ))}
      </ul>
    </section>
  )
}
