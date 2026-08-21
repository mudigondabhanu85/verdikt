import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { AI_PROVIDER_TYPES, type AiProviderType } from '../api/types'

function ApiKeysSection() {
  const queryClient = useQueryClient()
  const [label, setLabel] = useState('')
  const [justCreated, setJustCreated] = useState<string | null>(null)

  const { data: keys, isLoading } = useQuery({ queryKey: ['api-keys'], queryFn: api.apiKeys.list })
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['api-keys'] })

  const createMutation = useMutation({
    mutationFn: (body: { label: string }) => api.apiKeys.create(body),
    onSuccess: (created) => {
      invalidate()
      setJustCreated(created.api_key)
      setLabel('')
    },
  })

  const revokeMutation = useMutation({
    mutationFn: (id: string) => api.apiKeys.revoke(id),
    onSuccess: invalidate,
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!label.trim()) return
    createMutation.mutate({ label })
  }

  return (
    <section className="mb-10">
      <h2 className="mb-3 text-lg font-medium text-gray-800">API Keys</h2>
      <p className="mb-4 text-sm text-gray-500">For CI/automation clients — sent the same way as a login token, via Authorization: Bearer.</p>

      {justCreated && (
        <p className="mb-4 rounded border border-yellow-300 bg-yellow-50 px-3 py-2 font-mono text-xs text-yellow-800">
          Save this now — it won't be shown again: {justCreated}
        </p>
      )}

      <form onSubmit={handleSubmit} className="mb-4 flex gap-2">
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="label (e.g. CI pipeline)"
          className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <button
          type="submit"
          disabled={createMutation.isPending}
          className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
        >
          Create key
        </button>
      </form>

      {isLoading && <p className="text-gray-500">Loading…</p>}
      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {keys?.map((key) => (
          <li key={key.id} className="flex items-center justify-between px-4 py-3 text-sm">
            <span>
              <span className="font-medium">{key.label}</span>
              <span className="ml-2 font-mono text-xs text-gray-400">{key.key_prefix}…</span>
              {key.revoked_at && <span className="ml-2 text-xs text-red-600">revoked</span>}
            </span>
            {!key.revoked_at && (
              <button onClick={() => revokeMutation.mutate(key.id)} className="text-xs text-red-600 hover:underline">
                Revoke
              </button>
            )}
          </li>
        ))}
      </ul>
    </section>
  )
}

function AiProviderConfigsSection() {
  const queryClient = useQueryClient()
  const [label, setLabel] = useState('')
  const [provider, setProvider] = useState<AiProviderType>('claude')
  const [model, setModel] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [baseUrl, setBaseUrl] = useState('')

  const { data: configs, isLoading } = useQuery({
    queryKey: ['ai-provider-configs'],
    queryFn: api.aiProviderConfigs.list,
  })
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['ai-provider-configs'] })

  const createMutation = useMutation({
    mutationFn: () =>
      api.aiProviderConfigs.create({ label, provider, model, api_key: apiKey, base_url: baseUrl || undefined }),
    onSuccess: () => {
      invalidate()
      setLabel('')
      setModel('')
      setApiKey('')
      setBaseUrl('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.aiProviderConfigs.delete(id),
    onSuccess: invalidate,
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!label.trim() || !model.trim() || !apiKey.trim()) return
    createMutation.mutate()
  }

  return (
    <section>
      <h2 className="mb-3 text-lg font-medium text-gray-800">AI Provider Configs</h2>
      <p className="mb-4 text-sm text-gray-500">Pick a provider per scan run — omitted, a scan falls back to the deployment default.</p>

      <form onSubmit={handleSubmit} className="mb-4 flex flex-wrap gap-2">
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="label"
          className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <select
          value={provider}
          onChange={(e) => setProvider(e.target.value as AiProviderType)}
          className="rounded border border-gray-300 px-3 py-2 text-sm"
        >
          {AI_PROVIDER_TYPES.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <input
          value={model}
          onChange={(e) => setModel(e.target.value)}
          placeholder="model"
          className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <input
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="API key"
          type="password"
          className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        {provider === 'custom' && (
          <input
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="base URL"
            className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
        )}
        <button
          type="submit"
          disabled={createMutation.isPending}
          className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
        >
          Add
        </button>
      </form>

      {isLoading && <p className="text-gray-500">Loading…</p>}
      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {configs?.map((cfg) => (
          <li key={cfg.id} className="flex items-center justify-between px-4 py-3 text-sm">
            <span>
              <span className="font-medium">{cfg.label}</span>
              <span className="ml-2 text-xs text-gray-400">{cfg.provider} / {cfg.model}</span>
              <span className="ml-2 font-mono text-xs text-gray-400">{cfg.masked_reference}</span>
            </span>
            <button onClick={() => deleteMutation.mutate(cfg.id)} className="text-xs text-red-600 hover:underline">
              Delete
            </button>
          </li>
        ))}
      </ul>
    </section>
  )
}

export function AccountPage() {
  const { user } = useAuth()
  const { data: org } = useQuery({ queryKey: ['organizations', 'me'], queryFn: api.organizations.me })

  return (
    <div>
      <h1 className="mb-2 text-2xl font-semibold">Account</h1>
      {user && (
        <p className="mb-8 text-sm text-gray-500">
          {user.email} · <span className="uppercase">{user.role}</span> {org && <>· {org.name}</>}
        </p>
      )}

      {user?.role === 'org_admin' && (
        <>
          <ApiKeysSection />
          <AiProviderConfigsSection />
        </>
      )}
      {user?.role !== 'org_admin' && (
        <p className="text-sm text-gray-500">API keys and AI provider configuration are managed by an org admin.</p>
      )}
    </div>
  )
}
