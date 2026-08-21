import { useEffect, useState } from 'react'
import type { CredentialSetOut, PriceOrQuantityTamperingConfig } from '../../../api/types'
import { HttpMethodSelect } from './HttpMethodSelect'
import { CredentialSelect } from './CredentialSelect'

export function PriceOrQuantityTamperingForm({
  credentials,
  onChange,
}: {
  credentials: CredentialSetOut[]
  onChange: (config: PriceOrQuantityTamperingConfig | null) => void
}) {
  const [method, setMethod] = useState('POST')
  const [url, setUrl] = useState('')
  const [bodyTemplate, setBodyTemplate] = useState('{"qty": {value}}')
  const [contentType, setContentType] = useState('application/json')
  const [baselineValue, setBaselineValue] = useState('1')
  const [tamperValuesText, setTamperValuesText] = useState('')
  const [credentialSetId, setCredentialSetId] = useState('')

  const hasPlaceholder = bodyTemplate.includes('{value}')

  useEffect(() => {
    const valid = url.trim() && hasPlaceholder
    const tamperValues = tamperValuesText
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean)
    onChange(
      valid
        ? {
            method,
            url,
            body_template: bodyTemplate,
            content_type: contentType,
            baseline_value: baselineValue,
            tamper_values: tamperValues.length > 0 ? tamperValues : null,
            credential_set_id: credentialSetId || null,
          }
        : null,
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [method, url, bodyTemplate, contentType, baselineValue, tamperValuesText, credentialSetId])

  return (
    <div className="space-y-2">
      <p className="text-xs text-gray-500">
        Re-sends the request with tampered values swapped into body_template's {'{value}'} placeholder (e.g. a
        negative price or quantity) and compares against the baseline response.
      </p>
      <div className="flex gap-2">
        <HttpMethodSelect value={method} onChange={setMethod} />
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://app.example.com/rest/basket"
          className="flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <input
          value={contentType}
          onChange={(e) => setContentType(e.target.value)}
          className="w-48 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
      </div>
      <textarea
        value={bodyTemplate}
        onChange={(e) => setBodyTemplate(e.target.value)}
        rows={2}
        className="w-full rounded border border-gray-300 px-3 py-2 font-mono text-xs focus:border-purple-500 focus:outline-none"
      />
      {!hasPlaceholder && <p className="text-xs text-red-600">body_template must contain a {'{value}'} placeholder</p>}
      <div className="flex flex-wrap items-center gap-2">
        <label className="text-xs text-gray-500">
          Baseline value:
          <input
            value={baselineValue}
            onChange={(e) => setBaselineValue(e.target.value)}
            className="ml-1 w-20 rounded border border-gray-300 px-2 py-1 text-sm focus:border-purple-500 focus:outline-none"
          />
        </label>
        <label className="text-xs text-gray-500">
          Tamper values (comma-separated, optional):
          <input
            value={tamperValuesText}
            onChange={(e) => setTamperValuesText(e.target.value)}
            placeholder="-1, 0, 0.01"
            className="ml-1 w-40 rounded border border-gray-300 px-2 py-1 text-sm focus:border-purple-500 focus:outline-none"
          />
        </label>
        <span className="text-xs text-gray-500">Test as:</span>
        <CredentialSelect credentials={credentials} value={credentialSetId} onChange={setCredentialSetId} />
      </div>
    </div>
  )
}
