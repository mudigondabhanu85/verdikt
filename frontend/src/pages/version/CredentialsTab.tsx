import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { useAuth, canWrite } from '../../auth/AuthContext'
import { MacroSection } from './MacroSection'

export function CredentialsTab({ versionId }: { versionId: string }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [label, setLabel] = useState('')
  const [username, setUsername] = useState('')
  const [secret, setSecret] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [loginEndpoint, setLoginEndpoint] = useState('')
  const [extraCookies, setExtraCookies] = useState('')

  const [editingId, setEditingId] = useState<string | null>(null)
  const [editLabel, setEditLabel] = useState('')
  const [editSecret, setEditSecret] = useState('')
  const [editLoginEndpoint, setEditLoginEndpoint] = useState('')

  function parseExtraCookies(raw: string): Record<string, string> | null {
    const trimmed = raw.trim()
    if (!trimmed) return null
    const entries = trimmed
      .split(',')
      .map((pair) => pair.split('=').map((s) => s.trim()))
      .filter(([k, v]) => k && v !== undefined) as [string, string][]
    return entries.length ? Object.fromEntries(entries) : null
  }

  const { data: credentials, isLoading } = useQuery({
    queryKey: ['versions', versionId, 'credentials'],
    queryFn: () => api.credentials.list(versionId),
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['versions', versionId, 'credentials'] })

  const createMutation = useMutation({
    mutationFn: () =>
      api.credentials.create(versionId, {
        label,
        username,
        secret,
        login_endpoint: loginEndpoint || null,
        extra_cookies: parseExtraCookies(extraCookies),
      }),
    onSuccess: () => {
      invalidate()
      setLabel('')
      setUsername('')
      setSecret('')
      setLoginEndpoint('')
      setExtraCookies('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.credentials.delete(versionId, id),
    onSuccess: invalidate,
  })

  const updateMutation = useMutation({
    mutationFn: (id: string) =>
      api.credentials.update(versionId, id, {
        label: editLabel || undefined,
        secret: editSecret || undefined,
        login_endpoint: editLoginEndpoint || undefined,
      }),
    onSuccess: () => {
      invalidate()
      setEditingId(null)
    },
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!label.trim() || !username.trim() || !secret.trim()) return
    createMutation.mutate()
  }

  function startEdit(cred: { id: string; label: string; login_endpoint: string | null }) {
    setEditingId(cred.id)
    setEditLabel(cred.label)
    setEditSecret('')
    setEditLoginEndpoint(cred.login_endpoint ?? '')
  }

  return (
    <div>
      <p className="mb-4 text-sm text-gray-500">
        Secrets are envelope-encrypted server-side and never echoed back — the list below only ever shows a masked
        reference. Leave "login endpoint" blank to fall back to automatic &lt;form&gt; discovery during recon.
      </p>
      {canWrite(user?.role) && (
        <form onSubmit={handleSubmit} className="mb-6 space-y-2">
          <div className="flex flex-wrap gap-2">
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="label (e.g. Standard User)"
              className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
            />
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="username"
              className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
            />
            <input
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder="password / secret"
              type="password"
              className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
            />
            <button
              type="button"
              onClick={() => setShowAdvanced((v) => !v)}
              className="text-xs text-purple-700 hover:underline"
            >
              {showAdvanced ? 'Hide' : 'Show'} login config
            </button>
          </div>
          {showAdvanced && (
            <>
              <input
                value={loginEndpoint}
                onChange={(e) => setLoginEndpoint(e.target.value)}
                placeholder="explicit login endpoint (optional, for JSON/REST logins)"
                className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
              />
              <input
                value={extraCookies}
                onChange={(e) => setExtraCookies(e.target.value)}
                placeholder="extra static cookies, e.g. security=low (comma-separated for more than one)"
                className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
              />
            </>
          )}
          <button
            type="submit"
            disabled={createMutation.isPending}
            className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
          >
            Add credential
          </button>
        </form>
      )}

      {isLoading && <p className="text-gray-500">Loading…</p>}
      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {credentials?.map((cred) => (
          <li key={cred.id} className="px-4 py-3">
            <div className="flex items-center justify-between">
              <span>
                <span className="font-medium">{cred.label}</span>
                <span className="ml-2 text-gray-500">{cred.masked_reference}</span>
                <span className="ml-2 text-xs text-gray-400">{cred.credential_type}</span>
              </span>
              {canWrite(user?.role) && (
                <span className="flex items-center gap-3">
                  <button
                    onClick={() => (editingId === cred.id ? setEditingId(null) : startEdit(cred))}
                    className="text-xs text-purple-700 hover:underline"
                  >
                    {editingId === cred.id ? 'Cancel' : 'Edit'}
                  </button>
                  <button
                    onClick={() => deleteMutation.mutate(cred.id)}
                    className="text-xs text-red-600 hover:underline"
                  >
                    Delete
                  </button>
                </span>
              )}
            </div>
            {editingId === cred.id && (
              <div className="mt-2 space-y-2 rounded border border-purple-200 bg-purple-50 p-3">
                <div className="flex flex-wrap gap-2">
                  <input
                    value={editLabel}
                    onChange={(e) => setEditLabel(e.target.value)}
                    placeholder="label"
                    className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
                  />
                  <input
                    value={editSecret}
                    onChange={(e) => setEditSecret(e.target.value)}
                    placeholder="new secret (leave blank to keep current)"
                    type="password"
                    className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
                  />
                  <input
                    value={editLoginEndpoint}
                    onChange={(e) => setEditLoginEndpoint(e.target.value)}
                    placeholder="login endpoint"
                    className="min-w-64 flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
                  />
                </div>
                <button
                  onClick={() => updateMutation.mutate(cred.id)}
                  disabled={updateMutation.isPending}
                  className="rounded bg-purple-700 px-4 py-2 text-xs font-medium text-white hover:bg-purple-800 disabled:opacity-50"
                >
                  Save changes
                </button>
              </div>
            )}
            {canWrite(user?.role) && <MacroSection versionId={versionId} credentialId={cred.id} />}
          </li>
        ))}
      </ul>
    </div>
  )
}
