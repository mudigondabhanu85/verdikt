import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { TICKETING_PROVIDER_TYPES, type TicketingProviderType } from '../../api/types'

export function TicketingConfigsSection() {
  const queryClient = useQueryClient()
  const [label, setLabel] = useState('')
  const [provider, setProvider] = useState<TicketingProviderType>('jira')
  const [baseUrl, setBaseUrl] = useState('')
  const [email, setEmail] = useState('')
  const [apiToken, setApiToken] = useState('')
  const [projectKey, setProjectKey] = useState('')
  const [issueType, setIssueType] = useState('Task')

  const { data: configs, isLoading } = useQuery({
    queryKey: ['ticketing-configs'],
    queryFn: api.ticketingConfigs.list,
  })
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['ticketing-configs'] })

  const createMutation = useMutation({
    mutationFn: () =>
      api.ticketingConfigs.create({
        label,
        provider,
        base_url: baseUrl,
        email,
        api_token: apiToken,
        project_key: projectKey,
        issue_type: issueType,
      }),
    onSuccess: () => {
      invalidate()
      setLabel('')
      setBaseUrl('')
      setEmail('')
      setApiToken('')
      setProjectKey('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.ticketingConfigs.delete(id),
    onSuccess: invalidate,
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!label.trim() || !baseUrl.trim() || !email.trim() || !apiToken.trim() || !projectKey.trim()) return
    createMutation.mutate()
  }

  return (
    <section className="mb-10">
      <h2 className="mb-3 text-lg font-medium text-gray-800">Ticketing</h2>
      <p className="mb-4 text-sm text-gray-500">
        Lets an analyst create a real Jira issue straight from a finding instead of copy-pasting it. The API token is
        a personal Jira Cloud API token, not your account password.
      </p>

      <form onSubmit={handleSubmit} className="mb-4 space-y-2">
        <div className="flex flex-wrap gap-2">
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="label"
            className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value as TicketingProviderType)}
            className="rounded border border-gray-300 px-3 py-2 text-sm"
          >
            {TICKETING_PROVIDER_TYPES.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
          <input
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="base URL (e.g. https://acme.atlassian.net)"
            className="min-w-64 flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
        </div>
        <div className="flex flex-wrap gap-2">
          <input
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="account email"
            className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <input
            value={apiToken}
            onChange={(e) => setApiToken(e.target.value)}
            placeholder="API token"
            type="password"
            className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <input
            value={projectKey}
            onChange={(e) => setProjectKey(e.target.value)}
            placeholder="project key (e.g. SEC)"
            className="w-40 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <input
            value={issueType}
            onChange={(e) => setIssueType(e.target.value)}
            placeholder="issue type"
            className="w-32 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
        </div>
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
              <span className="ml-2 text-xs text-gray-400">
                {cfg.provider} / {cfg.project_key} / {cfg.issue_type}
              </span>
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
