import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { useAuth, canWrite } from '../../auth/AuthContext'
import { BUSINESS_RULE_TYPES, type BusinessRuleType } from '../../api/types'
import { ResourceIsolationForm } from './business-rules/ResourceIsolationForm'
import { WorkflowOrderForm } from './business-rules/WorkflowOrderForm'
import { PriceOrQuantityTamperingForm } from './business-rules/PriceOrQuantityTamperingForm'
import { RaceConditionForm } from './business-rules/RaceConditionForm'

const RULE_TYPE_LABELS: Record<BusinessRuleType, string> = {
  resource_isolation: 'Resource isolation (IDOR)',
  workflow_order: 'Workflow step order',
  price_or_quantity_tampering: 'Price/quantity tampering',
  race_condition_limited_use: 'Race condition (limited-use)',
}

export function BusinessRulesTab({ versionId }: { versionId: string }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [ruleType, setRuleType] = useState<BusinessRuleType>('resource_isolation')
  const [title, setTitle] = useState('')
  const [config, setConfig] = useState<Record<string, unknown> | null>(null)
  const [error, setError] = useState<string | null>(null)
  // Bumped every time ruleType changes, forced onto each sub-form's key
  // so React remounts it with fresh internal state instead of carrying
  // over stale field values from the previous rule type's shape.
  const [formKey, setFormKey] = useState(0)

  const { data: rules, isLoading } = useQuery({
    queryKey: ['versions', versionId, 'business-rules'],
    queryFn: () => api.businessRules.list(versionId),
  })

  const { data: credentials } = useQuery({
    queryKey: ['versions', versionId, 'credentials'],
    queryFn: () => api.credentials.list(versionId),
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['versions', versionId, 'business-rules'] })

  const createMutation = useMutation({
    mutationFn: (cfg: Record<string, unknown>) => api.businessRules.create(versionId, { rule_type: ruleType, title, config: cfg }),
    onSuccess: () => {
      invalidate()
      setTitle('')
      setConfig(null)
      setError(null)
      setFormKey((k) => k + 1)
    },
    onError: (err) => setError(err instanceof Error ? err.message : 'Failed to create rule'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.businessRules.delete(versionId, id),
    onSuccess: invalidate,
  })

  function handleRuleTypeChange(next: BusinessRuleType) {
    setRuleType(next)
    setConfig(null)
    setFormKey((k) => k + 1)
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (!title.trim() || !config) return
    createMutation.mutate(config)
  }

  return (
    <div>
      <p className="mb-4 text-sm text-gray-500">
        Business logic rules the AI can't infer on its own — pointed at real, analyst-supplied endpoints/values.
      </p>
      {canWrite(user?.role) && (
        <form onSubmit={handleSubmit} className="mb-6 space-y-3 rounded border border-gray-200 bg-white p-4">
          <div className="flex gap-2">
            <select
              value={ruleType}
              onChange={(e) => handleRuleTypeChange(e.target.value as BusinessRuleType)}
              className="rounded border border-gray-300 px-3 py-2 text-sm"
            >
              {BUSINESS_RULE_TYPES.map((t) => (
                <option key={t} value={t}>
                  {RULE_TYPE_LABELS[t]}
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

          {ruleType === 'resource_isolation' && (
            <ResourceIsolationForm key={formKey} onChange={(cfg) => setConfig(cfg as Record<string, unknown> | null)} />
          )}
          {ruleType === 'workflow_order' && (
            <WorkflowOrderForm
              key={formKey}
              credentials={credentials ?? []}
              onChange={(cfg) => setConfig(cfg as Record<string, unknown> | null)}
            />
          )}
          {ruleType === 'price_or_quantity_tampering' && (
            <PriceOrQuantityTamperingForm
              key={formKey}
              credentials={credentials ?? []}
              onChange={(cfg) => setConfig(cfg as Record<string, unknown> | null)}
            />
          )}
          {ruleType === 'race_condition_limited_use' && (
            <RaceConditionForm
              key={formKey}
              credentials={credentials ?? []}
              onChange={(cfg) => setConfig(cfg as Record<string, unknown> | null)}
            />
          )}

          {error && <p className="text-sm text-red-600">{error}</p>}
          <button
            type="submit"
            disabled={createMutation.isPending || !config || !title.trim()}
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
                <span className="ml-2 text-xs text-gray-400">{RULE_TYPE_LABELS[rule.rule_type] ?? rule.rule_type}</span>
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
