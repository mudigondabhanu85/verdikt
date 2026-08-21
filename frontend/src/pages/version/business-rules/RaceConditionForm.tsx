import { useEffect, useState } from 'react'
import type { CredentialSetOut, RaceConditionConfig } from '../../../api/types'
import { HttpMethodSelect } from './HttpMethodSelect'
import { CredentialSelect } from './CredentialSelect'

export function RaceConditionForm({
  credentials,
  onChange,
}: {
  credentials: CredentialSetOut[]
  onChange: (config: RaceConditionConfig | null) => void
}) {
  const [method, setMethod] = useState('POST')
  const [url, setUrl] = useState('')
  const [body, setBody] = useState('')
  const [contentType, setContentType] = useState('application/json')
  const [concurrency, setConcurrency] = useState(10)
  const [maxAllowedSuccesses, setMaxAllowedSuccesses] = useState(1)
  const [credentialSetId, setCredentialSetId] = useState('')

  useEffect(() => {
    onChange(
      url.trim()
        ? {
            method,
            url,
            body: body || null,
            content_type: contentType,
            concurrency,
            max_allowed_successes: maxAllowedSuccesses,
            credential_set_id: credentialSetId || null,
          }
        : null,
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [method, url, body, contentType, concurrency, maxAllowedSuccesses, credentialSetId])

  return (
    <div className="space-y-2">
      <p className="text-xs text-gray-500">
        Fires `concurrency` simultaneous requests at a limited-use endpoint (e.g. redeem-once coupon) and flags it if
        more than max_allowed_successes actually succeed.
      </p>
      <div className="flex gap-2">
        <HttpMethodSelect value={method} onChange={setMethod} />
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://app.example.com/rest/coupon/redeem"
          className="flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <input
          value={contentType}
          onChange={(e) => setContentType(e.target.value)}
          className="w-48 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
      </div>
      <textarea
        value={body}
        onChange={(e) => setBody(e.target.value)}
        placeholder="body (optional)"
        rows={2}
        className="w-full rounded border border-gray-300 px-3 py-2 font-mono text-xs focus:border-purple-500 focus:outline-none"
      />
      <div className="flex flex-wrap items-center gap-3">
        <label className="text-xs text-gray-500">
          Concurrency:
          <input
            type="number"
            min={2}
            value={concurrency}
            onChange={(e) => setConcurrency(Number(e.target.value))}
            className="ml-1 w-20 rounded border border-gray-300 px-2 py-1 text-sm focus:border-purple-500 focus:outline-none"
          />
        </label>
        <label className="text-xs text-gray-500">
          Max allowed successes:
          <input
            type="number"
            min={1}
            value={maxAllowedSuccesses}
            onChange={(e) => setMaxAllowedSuccesses(Number(e.target.value))}
            className="ml-1 w-20 rounded border border-gray-300 px-2 py-1 text-sm focus:border-purple-500 focus:outline-none"
          />
        </label>
        <span className="text-xs text-gray-500">Test as:</span>
        <CredentialSelect credentials={credentials} value={credentialSetId} onChange={setCredentialSetId} />
      </div>
    </div>
  )
}
