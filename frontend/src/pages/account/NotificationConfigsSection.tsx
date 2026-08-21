import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../../api/client'
import { NOTIFICATION_PROVIDER_TYPES, type NotificationProviderType } from '../../api/types'

export function NotificationConfigsSection() {
  const queryClient = useQueryClient()
  const [label, setLabel] = useState('')
  const [provider, setProvider] = useState<NotificationProviderType>('slack')
  const [webhookUrl, setWebhookUrl] = useState('')
  const [testResult, setTestResult] = useState<Record<string, string>>({})

  const { data: configs, isLoading } = useQuery({
    queryKey: ['notification-configs'],
    queryFn: api.notificationConfigs.list,
  })
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['notification-configs'] })

  const createMutation = useMutation({
    mutationFn: () => api.notificationConfigs.create({ label, provider, webhook_url: webhookUrl }),
    onSuccess: () => {
      invalidate()
      setLabel('')
      setWebhookUrl('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.notificationConfigs.delete(id),
    onSuccess: invalidate,
  })

  const testMutation = useMutation({
    mutationFn: (id: string) => api.notificationConfigs.test(id),
    onSuccess: (_data, id) => setTestResult((prev) => ({ ...prev, [id]: 'Sent — check the channel.' })),
    onError: (err, id) =>
      setTestResult((prev) => ({ ...prev, [id]: err instanceof ApiError ? err.message : 'Test failed' })),
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!label.trim() || !webhookUrl.trim()) return
    createMutation.mutate()
  }

  return (
    <section className="mb-10">
      <h2 className="mb-3 text-lg font-medium text-gray-800">Notifications</h2>
      <p className="mb-4 text-sm text-gray-500">
        Posts a summary to Slack whenever a scan run reaches a terminal state. Best-effort — a broken webhook never
        fails the scan itself; use "Send test" below to confirm the URL works.
      </p>

      <form onSubmit={handleSubmit} className="mb-4 flex flex-wrap gap-2">
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="label (e.g. #security-alerts)"
          className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <select
          value={provider}
          onChange={(e) => setProvider(e.target.value as NotificationProviderType)}
          className="rounded border border-gray-300 px-3 py-2 text-sm"
        >
          {NOTIFICATION_PROVIDER_TYPES.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <input
          value={webhookUrl}
          onChange={(e) => setWebhookUrl(e.target.value)}
          placeholder="webhook URL"
          type="password"
          className="min-w-64 flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
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
          <li key={cfg.id} className="px-4 py-3 text-sm">
            <div className="flex items-center justify-between">
              <span>
                <span className="font-medium">{cfg.label}</span>
                <span className="ml-2 text-xs text-gray-400">{cfg.provider}</span>
                <span className="ml-2 font-mono text-xs text-gray-400">{cfg.masked_reference}</span>
              </span>
              <span className="flex items-center gap-3">
                <button
                  onClick={() => testMutation.mutate(cfg.id)}
                  disabled={testMutation.isPending}
                  className="text-xs text-purple-700 hover:underline"
                >
                  Send test
                </button>
                <button onClick={() => deleteMutation.mutate(cfg.id)} className="text-xs text-red-600 hover:underline">
                  Delete
                </button>
              </span>
            </div>
            {testResult[cfg.id] && <p className="mt-1 text-xs text-gray-500">{testResult[cfg.id]}</p>}
          </li>
        ))}
      </ul>
    </section>
  )
}
