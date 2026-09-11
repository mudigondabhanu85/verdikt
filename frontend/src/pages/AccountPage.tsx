import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, BASE_URL } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import {
  AI_PROVIDER_TYPES,
  type AiProviderAuthType,
  type AiProviderType,
  BASELINE_ROLES,
  type Role,
} from '../api/types'
import { CMDBConfigsSection } from './account/CMDBConfigsSection'
import { NotificationConfigsSection } from './account/NotificationConfigsSection'
import { TicketingConfigsSection } from './account/TicketingConfigsSection'
import { UsersSection } from './account/UsersSection'
import { VGSConfigsSection } from './account/VGSConfigsSection'
import { SamlConfigsSection } from './account/SamlConfigsSection'
import { BrandingSection } from './account/BrandingSection'

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

// "paste a new secret into this existing config" is a routine, frequent
// action for any bearer-token-style auth (most self-hosted/in-house
// gateways use short-lived session tokens) — its own small component
// (rather than inline in the list) so its open/closed + input state
// doesn't have to live in a per-row array in the parent.
function RotateSecretControl({ configId }: { configId: string }) {
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [value, setValue] = useState('')

  const rotateMutation = useMutation({
    mutationFn: () => api.aiProviderConfigs.rotateSecret(configId, { api_key: value || undefined }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-provider-configs'] })
      setOpen(false)
      setValue('')
    },
  })

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="text-xs text-purple-700 hover:underline">
        Rotate token
      </button>
    )
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        if (value.trim()) rotateMutation.mutate()
      }}
      className="flex items-center gap-1"
    >
      <input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="new token/key"
        type="password"
        autoFocus
        className="w-32 rounded border border-gray-300 px-2 py-1 text-xs focus:border-purple-500 focus:outline-none"
      />
      <button
        type="submit"
        disabled={rotateMutation.isPending}
        className="text-xs text-purple-700 hover:underline disabled:opacity-50"
      >
        Save
      </button>
      <button type="button" onClick={() => setOpen(false)} className="text-xs text-gray-400 hover:underline">
        cancel
      </button>
    </form>
  )
}

// Lets an org route different agent roles to different models on the
// same provider account after the fact — heavier reasoning
// (business-logic hypothesis generation, attack-chain analysis) to a
// stronger/costlier model, cheap mechanical classification to a
// smaller/faster one — without touching the secret (RotateSecretControl's
// job) or re-picking "set default". Same open/closed pattern as that
// component, for the same reason (per-row state without a parent array).
function ModelTiersControl({
  configId,
  currentModel,
  currentReasoning,
  currentClassification,
}: {
  configId: string
  currentModel: string
  currentReasoning: string | null
  currentClassification: string | null
}) {
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [model, setModel] = useState('')
  const [reasoning, setReasoning] = useState('')
  const [classification, setClassification] = useState('')

  const updateMutation = useMutation({
    mutationFn: () =>
      api.aiProviderConfigs.updateModels(configId, {
        model: model.trim() || undefined,
        model_reasoning: reasoning.trim(),
        model_classification: classification.trim(),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-provider-configs'] })
      setOpen(false)
    },
  })

  if (!open) {
    return (
      <button
        onClick={() => {
          setModel(currentModel)
          setReasoning(currentReasoning ?? '')
          setClassification(currentClassification ?? '')
          setOpen(true)
        }}
        className="text-xs text-purple-700 hover:underline"
      >
        Route models by task
      </button>
    )
  }

  const tierInput = (value: string, onChange: (v: string) => void, placeholder: string, width: string) => (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className={`${width} rounded border border-gray-300 px-2 py-1 text-xs focus:border-purple-500 focus:outline-none`}
    />
  )

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        updateMutation.mutate()
      }}
      className="flex items-center gap-1"
    >
      {tierInput(model, setModel, 'specialist model (default)', 'w-48')}
      {tierInput(reasoning, setReasoning, 'reasoning model (blank = default)', 'w-48')}
      {tierInput(classification, setClassification, 'classification model (blank = default)', 'w-48')}
      <button
        type="submit"
        disabled={updateMutation.isPending}
        className="text-xs text-purple-700 hover:underline disabled:opacity-50"
      >
        Save
      </button>
      <button type="button" onClick={() => setOpen(false)} className="text-xs text-gray-400 hover:underline">
        cancel
      </button>
    </form>
  )
}

function AiProviderConfigsSection() {
  const queryClient = useQueryClient()
  const [label, setLabel] = useState('')
  const [provider, setProvider] = useState<AiProviderType>('claude')
  const [model, setModel] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [authType, setAuthType] = useState<AiProviderAuthType>('api_key')

  const { data: configs, isLoading } = useQuery({
    queryKey: ['ai-provider-configs'],
    queryFn: api.aiProviderConfigs.list,
  })
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['ai-provider-configs'] })

  const createMutation = useMutation({
    mutationFn: () =>
      api.aiProviderConfigs.create({
        label,
        provider,
        model,
        api_key: apiKey,
        base_url: baseUrl || undefined,
        auth_type: authType,
      }),
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

  const setDefaultMutation = useMutation({
    mutationFn: (id: string) => api.aiProviderConfigs.setDefault(id),
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
      <p className="mb-4 text-sm text-gray-500">
        Configure once and mark it "Default" to route every scan through it automatically — no .env editing
        needed. A scan can still pick a different one of its own; with no default set, it falls back to the
        deployment's own AI_PROVIDER setting.
      </p>

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
        <select
          value={authType}
          onChange={(e) => setAuthType(e.target.value as AiProviderAuthType)}
          className="rounded border border-gray-300 px-3 py-2 text-sm"
        >
          <option value="api_key">API Key</option>
          <option value="bearer_token">Bearer Token</option>
        </select>
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
              {cfg.is_default && (
                <span className="ml-2 rounded-full border border-green-300 bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800">
                  Default
                </span>
              )}
              <span className="ml-2 text-xs text-gray-400">{cfg.provider} / {cfg.model}</span>
              <span className="ml-2 text-xs text-gray-400">({cfg.auth_type})</span>
              {cfg.model_reasoning && (
                <span className="ml-2 text-xs text-gray-400">reasoning={cfg.model_reasoning}</span>
              )}
              {cfg.model_classification && (
                <span className="ml-2 text-xs text-gray-400">classification={cfg.model_classification}</span>
              )}
              <span className="ml-2 font-mono text-xs text-gray-400">{cfg.masked_reference}</span>
            </span>
            <span className="flex items-center gap-3">
              <RotateSecretControl configId={cfg.id} />
              <ModelTiersControl
                configId={cfg.id}
                currentModel={cfg.model}
                currentReasoning={cfg.model_reasoning}
                currentClassification={cfg.model_classification}
              />
              {!cfg.is_default && (
                <button
                  onClick={() => setDefaultMutation.mutate(cfg.id)}
                  disabled={setDefaultMutation.isPending}
                  className="text-xs text-purple-700 hover:underline disabled:opacity-50"
                >
                  Set as default
                </button>
              )}
              <button onClick={() => deleteMutation.mutate(cfg.id)} className="text-xs text-red-600 hover:underline">
                Delete
              </button>
            </span>
          </li>
        ))}
      </ul>
    </section>
  )
}

function OidcProvidersSection() {
  const queryClient = useQueryClient()
  const [label, setLabel] = useState('')
  const [issuer, setIssuer] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [redirectUri, setRedirectUri] = useState(`${BASE_URL}/auth/oidc/callback`)
  const [defaultRole, setDefaultRole] = useState<Role>('viewer')

  const { data: configs, isLoading } = useQuery({
    queryKey: ['oidc-provider-configs'],
    queryFn: api.oidcProviderConfigs.list,
  })
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['oidc-provider-configs'] })

  const createMutation = useMutation({
    mutationFn: () =>
      api.oidcProviderConfigs.create({
        label,
        issuer,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        default_role: defaultRole,
      }),
    onSuccess: () => {
      invalidate()
      setLabel('')
      setIssuer('')
      setClientId('')
      setClientSecret('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.oidcProviderConfigs.delete(id),
    onSuccess: invalidate,
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!label.trim() || !issuer.trim() || !clientId.trim() || !clientSecret.trim()) return
    createMutation.mutate()
  }

  return (
    <section className="mb-10">
      <h2 className="mb-3 text-lg font-medium text-gray-800">SSO Providers</h2>
      <p className="mb-4 text-sm text-gray-500">
        There's no public directory of an org's SSO providers, so share each config's sign-in link directly with
        your users rather than expecting them to find it themselves. The redirect URI below must also be registered
        with the identity provider itself.
      </p>

      <form onSubmit={handleSubmit} className="mb-4 space-y-2">
        <div className="flex flex-wrap gap-2">
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="label (e.g. Okta)"
            className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <input
            value={issuer}
            onChange={(e) => setIssuer(e.target.value)}
            placeholder="issuer URL"
            className="min-w-64 flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <select
            value={defaultRole}
            onChange={(e) => setDefaultRole(e.target.value as Role)}
            className="rounded border border-gray-300 px-3 py-2 text-sm"
          >
            {BASELINE_ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </div>
        <div className="flex flex-wrap gap-2">
          <input
            value={clientId}
            onChange={(e) => setClientId(e.target.value)}
            placeholder="client ID"
            className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <input
            value={clientSecret}
            onChange={(e) => setClientSecret(e.target.value)}
            placeholder="client secret"
            type="password"
            className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <input
            value={redirectUri}
            onChange={(e) => setRedirectUri(e.target.value)}
            placeholder="redirect URI"
            className="min-w-64 flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
        </div>
        <button
          type="submit"
          disabled={createMutation.isPending}
          className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
        >
          Add provider
        </button>
      </form>

      {isLoading && <p className="text-gray-500">Loading…</p>}
      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {configs?.map((cfg) => {
          const signInLink = `${window.location.origin}/login?sso=${cfg.id}`
          return (
            <li key={cfg.id} className="px-4 py-3 text-sm">
              <div className="flex items-center justify-between">
                <span>
                  <span className="font-medium">{cfg.label}</span>
                  <span className="ml-2 text-xs text-gray-400">{cfg.issuer}</span>
                  <span className="ml-2 rounded-full border border-gray-300 px-2 py-0.5 text-xs uppercase text-gray-500">
                    default: {cfg.default_role}
                  </span>
                </span>
                <button onClick={() => deleteMutation.mutate(cfg.id)} className="text-xs text-red-600 hover:underline">
                  Delete
                </button>
              </div>
              <div className="mt-1 flex items-center gap-2">
                <span className="text-xs text-gray-400">Sign-in link:</span>
                <code className="rounded bg-gray-50 px-2 py-0.5 text-xs text-gray-600">{signInLink}</code>
                <button
                  onClick={() => navigator.clipboard.writeText(signInLink)}
                  className="text-xs text-purple-700 hover:underline"
                >
                  Copy
                </button>
              </div>
            </li>
          )
        })}
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
          <OidcProvidersSection />
          <SamlConfigsSection />
          <NotificationConfigsSection />
          <TicketingConfigsSection />
          <CMDBConfigsSection />
          <VGSConfigsSection />
          <UsersSection />
          <BrandingSection />
        </>
      )}
      {user?.role !== 'org_admin' && (
        <p className="text-sm text-gray-500">API keys and AI provider configuration are managed by an org admin.</p>
      )}
    </div>
  )
}
