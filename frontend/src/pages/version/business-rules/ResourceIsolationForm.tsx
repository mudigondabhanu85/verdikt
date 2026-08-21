import { useEffect, useState } from 'react'
import type { ResourceIsolationConfig } from '../../../api/types'
import { HttpMethodSelect } from './HttpMethodSelect'

export function ResourceIsolationForm({
  onChange,
}: {
  onChange: (config: ResourceIsolationConfig | null) => void
}) {
  const [url, setUrl] = useState('')
  const [method, setMethod] = useState('GET')

  useEffect(() => {
    onChange(url.trim() ? { url, method } : null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, method])

  return (
    <div className="space-y-2">
      <p className="text-xs text-gray-500">
        A real endpoint with a real numeric resource ID in the path (e.g. "/rest/basket/6") — recon can't discover
        this on SPA-heavy apps, so point at it directly.
      </p>
      <div className="flex gap-2">
        <HttpMethodSelect value={method} onChange={setMethod} />
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://app.example.com/rest/basket/6"
          className="flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
      </div>
    </div>
  )
}
