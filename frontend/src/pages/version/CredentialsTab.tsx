import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../../api/client'
import type { TestLoginResult } from '../../api/types'
import { useAuth, canWrite } from '../../auth/AuthContext'
import { MacroSection } from './MacroSection'

// The direct answer to "how do I confirm login is working and getting a
// 200": one button, one clear pass/fail banner with the actual URL and
// status code hit — not just "a session was created" (that can happen
// with a garbage token and still 401 on every real request, which is
// exactly the failure mode this exists to catch). See
// backend/app/api/routes/credentials.py's test_login for what it
// actually checks (and doesn't — <form> auto-discovery needs a real
// crawl this quick check skips).
function TestLoginControl({ versionId, credentialId }: { versionId: string; credentialId: string }) {
  const [result, setResult] = useState<TestLoginResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const testMutation = useMutation({
    mutationFn: () => api.credentials.testLogin(versionId, credentialId),
    onSuccess: (res) => {
      setError(null)
      setResult(res)
    },
    onError: (err) => {
      setResult(null)
      setError(err instanceof ApiError ? err.message : 'Test failed')
    },
  })

  return (
    <div className="mt-1">
      <button
        onClick={() => testMutation.mutate()}
        disabled={testMutation.isPending}
        className="text-xs text-purple-700 hover:underline disabled:opacity-50"
      >
        {testMutation.isPending ? 'Testing…' : 'Test login'}
      </button>
      {result && (
        <p className={`mt-1 text-xs ${result.ok ? 'text-green-700' : 'text-red-600'}`}>
          {result.ok ? '✅' : '❌'} {result.message}
        </p>
      )}
      {error && <p className="mt-1 text-xs text-red-600">❌ {error}</p>}
    </div>
  )
}

export function CredentialsTab({ versionId }: { versionId: string }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [label, setLabel] = useState('')
  const [credentialType, setCredentialType] = useState<'username_password' | 'api_token'>('username_password')
  const [username, setUsername] = useState('')
  const [secret, setSecret] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [loginEndpoint, setLoginEndpoint] = useState('')
  const [extraCookies, setExtraCookies] = useState('')
  const [extraHeaderRows, setExtraHeaderRows] = useState<{ name: string; value: string }[]>([
    { name: '', value: '' },
  ])
  const [privilegeRank, setPrivilegeRank] = useState('')

  const [editingId, setEditingId] = useState<string | null>(null)
  const [editLabel, setEditLabel] = useState('')
  const [editUsername, setEditUsername] = useState('')
  const [editSecret, setEditSecret] = useState('')
  const [editLoginEndpoint, setEditLoginEndpoint] = useState('')
  const [editPrivilegeRank, setEditPrivilegeRank] = useState('')

  function parseKeyValuePairs(raw: string): Record<string, string> | null {
    const trimmed = raw.trim()
    if (!trimmed) return null
    const entries = trimmed
      .split(',')
      .map((pair) => pair.split('=').map((s) => s.trim()))
      .filter(([k, v]) => k && v !== undefined) as [string, string][]
    return entries.length ? Object.fromEntries(entries) : null
  }

  function headerRowsToObject(rows: { name: string; value: string }[]): Record<string, string> | null {
    const entries = rows
      .map(({ name, value }) => [name.trim(), value.trim()] as [string, string])
      .filter(([name, value]) => name && value)
    return entries.length ? Object.fromEntries(entries) : null
  }

  function updateHeaderRow(index: number, field: 'name' | 'value', value: string) {
    setExtraHeaderRows((rows) => rows.map((row, i) => (i === index ? { ...row, [field]: value } : row)))
  }

  function addHeaderRow() {
    setExtraHeaderRows((rows) => [...rows, { name: '', value: '' }])
  }

  function removeHeaderRow(index: number) {
    setExtraHeaderRows((rows) => (rows.length > 1 ? rows.filter((_, i) => i !== index) : rows))
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
        credential_type: credentialType,
        // api_token has no real "username" (it's not a login) — the
        // schema requires the field regardless, so a fixed placeholder
        // goes in rather than asking the analyst to type something
        // meaningless. login_endpoint/extra_cookies don't apply either
        // (see backend/app/agents/login.py's api_token branch, which
        // returns a session straight from `secret` as a bearer token,
        // skipping login entirely).
        username: credentialType === 'api_token' ? 'api-token' : username,
        secret,
        login_endpoint: credentialType === 'api_token' ? null : loginEndpoint || null,
        extra_cookies: credentialType === 'api_token' ? null : parseKeyValuePairs(extraCookies),
        // Unlike extra_cookies, this applies for BOTH credential types —
        // it's the header-shaped escape hatch for api_token specifically
        // (which otherwise can only ever send a literal
        // "Authorization: Bearer <token>", never a custom header name
        // like "X-API-Key"), as well as a header layered on top of a
        // real login/macro flow. See app.models.credential.CredentialSet.extra_headers.
        extra_headers: headerRowsToObject(extraHeaderRows),
        privilege_rank: privilegeRank.trim() ? Number(privilegeRank) : null,
      }),
    onSuccess: () => {
      invalidate()
      setLabel('')
      setUsername('')
      setSecret('')
      setLoginEndpoint('')
      setExtraCookies('')
      setExtraHeaderRows([{ name: '', value: '' }])
      setPrivilegeRank('')
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
        username: editUsername || undefined,
        secret: editSecret || undefined,
        login_endpoint: editLoginEndpoint || undefined,
        privilege_rank: editPrivilegeRank.trim() ? Number(editPrivilegeRank) : undefined,
      }),
    onSuccess: () => {
      invalidate()
      setEditingId(null)
    },
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (credentialType === 'api_token') {
      if (!label.trim() || !secret.trim()) return
    } else if (!label.trim() || !username.trim() || !secret.trim()) {
      return
    }
    createMutation.mutate()
  }

  function startEdit(cred: {
    id: string
    label: string
    login_endpoint: string | null
    privilege_rank: number | null
  }) {
    setEditingId(cred.id)
    setEditLabel(cred.label)
    // Blank, not pre-filled — the backend never echoes back the current
    // username (only masked_reference, e.g. "dvaAdmin (****3$)"), same
    // reason editSecret starts blank. Both are "leave blank to keep
    // current" fields, not "here's the current value, edit it in place".
    setEditUsername('')
    setEditSecret('')
    setEditLoginEndpoint(cred.login_endpoint ?? '')
    // Unlike username/secret, privilege_rank IS returned by the API —
    // safe (and more usable) to pre-fill for in-place editing.
    setEditPrivilegeRank(cred.privilege_rank == null ? '' : String(cred.privilege_rank))
  }

  return (
    <div>
      <p className="mb-4 text-sm text-gray-500">
        Secrets are envelope-encrypted server-side and never echoed back — the list below only ever shows a masked
        reference. Leave "login endpoint" blank to fall back to automatic &lt;form&gt; discovery during recon.
        "API token" skips login entirely — for an imported OpenAPI/Postman collection with no login flow, just a
        pre-issued bearer token/API key sent on every request. Use "extra static headers" to save a custom auth
        header (e.g. an API key under a header name other than Authorization) alongside a login macro, or to give an
        API token credential a header name other than "Authorization: Bearer". Set "privilege rank" on two or more
        credentials
        (higher = more privileged) to enable role-vs-role vertical escalation testing — e.g. does a Standard User's
        session get into an endpoint only an Admin's should.
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
            <select
              value={credentialType}
              onChange={(e) => setCredentialType(e.target.value as 'username_password' | 'api_token')}
              className="rounded border border-gray-300 px-3 py-2 text-sm"
            >
              <option value="username_password">Username / password</option>
              <option value="api_token">API token (bearer, no login)</option>
            </select>
            {credentialType !== 'api_token' && (
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="username"
                className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
              />
            )}
            <input
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder={credentialType === 'api_token' ? 'bearer token / API key' : 'password / secret'}
              type="password"
              className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
            />
            <input
              value={privilegeRank}
              onChange={(e) => setPrivilegeRank(e.target.value)}
              placeholder="privilege rank (optional)"
              type="number"
              title='Higher = more privileged. Set on two or more credentials with different values (e.g. "Standard User"=1, "Admin"=10) to enable role-vs-role vertical escalation testing.'
              className="w-40 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
            />
            {credentialType !== 'api_token' && (
              <button
                type="button"
                onClick={() => setShowAdvanced((v) => !v)}
                className="text-xs text-purple-700 hover:underline"
              >
                {showAdvanced ? 'Hide' : 'Show'} login config
              </button>
            )}
          </div>
          <div className="space-y-1 rounded border border-gray-200 bg-gray-50 p-2">
            <p className="text-xs font-medium text-gray-600">Extra static headers (optional)</p>
            {extraHeaderRows.map((row, i) => (
              <div key={i} className="flex gap-2">
                <input
                  value={row.name}
                  onChange={(e) => updateHeaderRow(i, 'name', e.target.value)}
                  placeholder="Header name, e.g. X-API-Key"
                  className="flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
                />
                <input
                  value={row.value}
                  onChange={(e) => updateHeaderRow(i, 'value', e.target.value)}
                  placeholder="Value"
                  className="flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => removeHeaderRow(i)}
                  disabled={extraHeaderRows.length === 1}
                  className="text-xs text-red-600 hover:underline disabled:opacity-30"
                >
                  Remove
                </button>
              </div>
            ))}
            <button type="button" onClick={addHeaderRow} className="text-xs text-purple-700 hover:underline">
              + Add header
            </button>
          </div>
          {showAdvanced && credentialType !== 'api_token' && (
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
                {cred.privilege_rank != null && (
                  <span className="ml-2 rounded-full border border-gray-300 bg-gray-100 px-2 py-0.5 text-xs text-gray-600">
                    rank {cred.privilege_rank}
                  </span>
                )}
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
                    value={editUsername}
                    onChange={(e) => setEditUsername(e.target.value)}
                    placeholder="new username (leave blank to keep current)"
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
                    value={editPrivilegeRank}
                    onChange={(e) => setEditPrivilegeRank(e.target.value)}
                    placeholder="privilege rank"
                    type="number"
                    className="w-32 rounded border border-gray-300 px-2 py-2 text-sm focus:border-purple-500 focus:outline-none"
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
            <TestLoginControl versionId={versionId} credentialId={cred.id} />
            {canWrite(user?.role) && <MacroSection versionId={versionId} credentialId={cred.id} />}
          </li>
        ))}
      </ul>
    </div>
  )
}
