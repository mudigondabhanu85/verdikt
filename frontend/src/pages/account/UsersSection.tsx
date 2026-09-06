import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../../api/client'
import { BASELINE_ROLES, type Role } from '../../api/types'

export function UsersSection() {
  const queryClient = useQueryClient()
  const [email, setEmail] = useState('')
  const [role, setRole] = useState<Role>('analyst')
  const [lastInviteLink, setLastInviteLink] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const { data: users, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: api.users.list,
  })
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['users'] })

  const inviteMutation = useMutation({
    mutationFn: () => api.users.invite({ email, role }),
    onSuccess: (invited) => {
      invalidate()
      setLastInviteLink(`${window.location.origin}/accept-invite?token=${invited.invite_token}`)
      setEmail('')
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
    inviteMutation.mutate()
  }

  return (
    <section className="mb-10">
      <h2 className="mb-3 text-lg font-medium text-gray-800">Users</h2>
      <p className="mb-4 text-sm text-gray-500">
        Invite teammates by email and assign a role. The invite link is shown once — share it with the invitee
        directly (no email is sent automatically yet). Deactivated users can't log in but keep their audit history.
      </p>

      <form onSubmit={handleSubmit} className="mb-4 flex flex-wrap gap-2">
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
        <button
          type="submit"
          disabled={inviteMutation.isPending}
          className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
        >
          Invite
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

      {isLoading && <p className="text-gray-500">Loading…</p>}
      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {users?.map((u) => (
          <li key={u.id} className="flex items-center justify-between px-4 py-3 text-sm">
            <span>
              <span className="font-medium">{u.email}</span>
              <span className="ml-2 text-xs text-gray-400">{u.role}</span>
              {u.invited_at && !u.invite_accepted_at && (
                <span className="ml-2 text-xs text-amber-600">pending invite</span>
              )}
              {!u.is_active && <span className="ml-2 text-xs text-red-600">deactivated</span>}
            </span>
            <span className="flex items-center gap-3">
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
