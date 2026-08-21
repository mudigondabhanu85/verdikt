import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { useAuth, canWrite } from '../../auth/AuthContext'
import { BUSINESS_RULE_TYPES, type BusinessRuleType } from '../../api/types'

const CONFIG_PLACEHOLDERS: Record<BusinessRuleType, string> = {
  resource_isolation: '{\n  "url": "https://app.example.com/rest/basket/6",\n  "method": "GET"\n}',
  workflow_order: '{\n  "precondition": {"method": "GET", "url": "..."},\n  "guarded_action": {"method": "POST", "url": "..."}\n}',
  price_or_quantity_tampering:
    '{\n  "url": "https://app.example.com/rest/basket",\n  "body_template": "{\\"qty\\": {value}}",\n  "baseline_value": "1"\n}',
  race_condition_limited_use:
    '{\n  "url": "https://app.example.com/rest/coupon/redeem",\n  "concurrency": 10,\n  "max_allowed_successes": 1\n}',
}

export function BusinessRulesTab({ versionId }: { versionId: string }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [ruleType, setRuleType] = useState<BusinessRuleType>('resource_isolation')
  const [title, setTitle] = useState('')
  const [configText, setConfigText] = useState('')
  const [error, setError] = useState<string | null>(null)

  const { data: rules, isLoading } = useQuery({
    queryKey: ['versions', versionId, 'business-rules'],
    queryFn: () => api.businessRules.list(versionId),
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['versions', versionId, 'business-rules'] })

  const createMutation = useMutation({
    mutationFn: (config: Record<string, unknown>) => api.businessRules.create(versionId, { rule_type: ruleType, title, config }),
    onSuccess: () => {
      invalidate()
      setTitle('')
      setConfigText('')
      setError(null)
    },
    onError: (err) => setError(err instanceof Error ? err.message : 'Failed to create rule'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.businessRules.delete(versionId, id),
    onSuccess: invalidate,
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (!title.trim()) return
    try {
      const config = JSON.parse(configText || '{}')
      createMutation.mutate(config)
    } catch {
      setError('Config must be valid JSON')
    }
  }

  return (
    <div>
      <p className="mb-4 text-sm text-gray-500">
        Business logic rules the AI can't infer on its own — pointed at real, analyst-supplied endpoints/values.
      </p>
      {canWrite(user?.role) && (
        <form onSubmit={handleSubmit} className="mb-6 space-y-2">
          <div className="flex gap-2">
            <select
              value={ruleType}
              onChange={(e) => setRuleType(e.target.value as BusinessRuleType)}
              className="rounded border border-gray-300 px-3 py-2 text-sm"
            >
              {BUSINESS_RULE_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="title"
              className="flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
            />
          </div>
          <textarea
            value={configText}
            onChange={(e) => setConfigText(e.target.value)}
            placeholder={CONFIG_PLACEHOLDERS[ruleType]}
            rows={5}
            className="w-full rounded border border-gray-300 px-3 py-2 font-mono text-xs focus:border-purple-500 focus:outline-none"
          />
          {error && <p className="text-sm text-red-600">{error}</p>}
          <button
            type="submit"
            disabled={createMutation.isPending}
            className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
          >
            Add rule
          </button>
        </form>
      )}

      {isLoading && <p className="text-gray-500">Loading…</p>}
      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {rules?.map((rule) => (
          <li key={rule.id} className="px-4 py-3">
            <div className="flex items-center justify-between">
              <span>
                <span className="font-medium">{rule.title}</span>
                <span className="ml-2 text-xs text-gray-400">{rule.rule_type}</span>
              </span>
              {canWrite(user?.role) && (
                <button
                  onClick={() => deleteMutation.mutate(rule.id)}
                  className="text-xs text-red-600 hover:underline"
                >
                  Delete
                </button>
              )}
            </div>
            <pre className="mt-1 overflow-x-auto rounded bg-gray-50 p-2 text-xs text-gray-600">
              {JSON.stringify(rule.config, null, 2)}
            </pre>
          </li>
        ))}
      </ul>
    </div>
  )
}
