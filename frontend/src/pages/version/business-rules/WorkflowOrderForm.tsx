import { useEffect, useState } from 'react'
import type { CredentialSetOut, HttpCallConfig, WorkflowOrderConfig } from '../../../api/types'
import { HttpMethodSelect } from './HttpMethodSelect'
import { CredentialSelect } from './CredentialSelect'

function HttpCallFields({
  label,
  call,
  onChange,
}: {
  label: string
  call: HttpCallConfig
  onChange: (call: HttpCallConfig) => void
}) {
  return (
    <div>
      <h4 className="mb-1 text-xs font-medium uppercase text-gray-500">{label}</h4>
      <div className="mb-1 flex gap-2">
        <HttpMethodSelect value={call.method} onChange={(method) => onChange({ ...call, method })} />
        <input
          value={call.url}
          onChange={(e) => onChange({ ...call, url: e.target.value })}
          placeholder="URL"
          className="flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
      </div>
      <textarea
        value={call.body ?? ''}
        onChange={(e) => onChange({ ...call, body: e.target.value || null })}
        placeholder="body (optional)"
        rows={2}
        className="w-full rounded border border-gray-300 px-3 py-2 font-mono text-xs focus:border-purple-500 focus:outline-none"
      />
    </div>
  )
}

export function WorkflowOrderForm({
  credentials,
  onChange,
}: {
  credentials: CredentialSetOut[]
  onChange: (config: WorkflowOrderConfig | null) => void
}) {
  const [precondition, setPrecondition] = useState<HttpCallConfig>({ method: 'GET', url: '' })
  const [guardedAction, setGuardedAction] = useState<HttpCallConfig>({ method: 'POST', url: '' })
  const [credentialSetId, setCredentialSetId] = useState('')

  useEffect(() => {
    const valid = precondition.url.trim() && guardedAction.url.trim()
    onChange(
      valid
        ? {
            precondition,
            guarded_action: guardedAction,
            credential_set_id: credentialSetId || null,
          }
        : null,
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [precondition, guardedAction, credentialSetId])

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-500">
        Proves a step can be skipped — e.g. checking out before adding a shipping address. "Guarded action" should
        only succeed after "precondition" has genuinely happened.
      </p>
      <HttpCallFields label="Precondition" call={precondition} onChange={setPrecondition} />
      <HttpCallFields label="Guarded action" call={guardedAction} onChange={setGuardedAction} />
      <div className="flex items-center gap-2">
        <span className="text-xs text-gray-500">Test as:</span>
        <CredentialSelect credentials={credentials} value={credentialSetId} onChange={setCredentialSetId} />
      </div>
    </div>
  )
}
