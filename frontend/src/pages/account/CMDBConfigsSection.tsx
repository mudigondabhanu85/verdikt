import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../../api/client'
import { CMDB_PROVIDER_TYPES, type AssetMetadataOut, type CMDBProviderType } from '../../api/types'

export function CMDBConfigsSection() {
  const queryClient = useQueryClient()
  const [label, setLabel] = useState('')
  const [provider, setProvider] = useState<CMDBProviderType>('generic_rest')
  const [lookupUrlTemplate, setLookupUrlTemplate] = useState('')
  const [authHeaderName, setAuthHeaderName] = useState('Authorization')
  const [authHeaderValue, setAuthHeaderValue] = useState('')
  const [ownerJsonPath, setOwnerJsonPath] = useState('owner')
  const [criticalityJsonPath, setCriticalityJsonPath] = useState('criticality')
  const [identifierByConfig, setIdentifierByConfig] = useState<Record<string, string>>({})
  const [lookupResult, setLookupResult] = useState<Record<string, AssetMetadataOut | string>>({})

  const { data: configs, isLoading } = useQuery({
    queryKey: ['cmdb-configs'],
    queryFn: api.cmdbConfigs.list,
  })
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['cmdb-configs'] })

  const createMutation = useMutation({
    mutationFn: () =>
      api.cmdbConfigs.create({
        label,
        provider,
        lookup_url_template: lookupUrlTemplate,
        auth_header_name: authHeaderName,
        auth_header_value: authHeaderValue,
        owner_json_path: ownerJsonPath,
        criticality_json_path: criticalityJsonPath,
      }),
    onSuccess: () => {
      invalidate()
      setLabel('')
      setLookupUrlTemplate('')
      setAuthHeaderValue('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.cmdbConfigs.delete(id),
    onSuccess: invalidate,
  })

  const lookupMutation = useMutation({
    mutationFn: ({ id, identifier }: { id: string; identifier: string }) => api.cmdbConfigs.lookup(id, identifier),
    onSuccess: (data, { id }) => setLookupResult((prev) => ({ ...prev, [id]: data })),
    onError: (err, { id }) =>
      setLookupResult((prev) => ({ ...prev, [id]: err instanceof ApiError ? err.message : 'Lookup failed' })),
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!label.trim() || !lookupUrlTemplate.trim() || !authHeaderValue.trim()) return
    createMutation.mutate()
  }

  return (
    <section className="mb-10">
      <h2 className="mb-3 text-lg font-medium text-gray-800">CMDB integration</h2>
      <p className="mb-4 text-sm text-gray-500">
        Looks up asset owner/criticality metadata from your CMDB. The lookup URL template uses{' '}
        <code>{'{identifier}'}</code> as a placeholder for the asset identifier; the JSON paths are dot-separated
        (e.g. <code>owner.email</code>) into the CMDB's response body.
      </p>

      <form onSubmit={handleSubmit} className="mb-4 flex flex-wrap gap-2">
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="label (e.g. Corp CMDB)"
          className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <select
          value={provider}
          onChange={(e) => setProvider(e.target.value as CMDBProviderType)}
          className="rounded border border-gray-300 px-3 py-2 text-sm"
        >
          {CMDB_PROVIDER_TYPES.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <input
          value={lookupUrlTemplate}
          onChange={(e) => setLookupUrlTemplate(e.target.value)}
          placeholder="https://cmdb.example.com/assets/{identifier}"
          className="min-w-72 flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <input
          value={authHeaderName}
          onChange={(e) => setAuthHeaderName(e.target.value)}
          placeholder="auth header name"
          className="w-40 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <input
          value={authHeaderValue}
          onChange={(e) => setAuthHeaderValue(e.target.value)}
          placeholder="auth header value"
          type="password"
          className="w-48 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <input
          value={ownerJsonPath}
          onChange={(e) => setOwnerJsonPath(e.target.value)}
          placeholder="owner JSON path"
          className="w-40 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <input
          value={criticalityJsonPath}
          onChange={(e) => setCriticalityJsonPath(e.target.value)}
          placeholder="criticality JSON path"
          className="w-40 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
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
        {configs?.map((cfg) => {
          const result = lookupResult[cfg.id]
          return (
            <li key={cfg.id} className="px-4 py-3 text-sm">
              <div className="flex items-center justify-between">
                <span>
                  <span className="font-medium">{cfg.label}</span>
                  <span className="ml-2 text-xs text-gray-400">{cfg.provider}</span>
                  <span className="ml-2 font-mono text-xs text-gray-400">{cfg.masked_reference}</span>
                </span>
                <button onClick={() => deleteMutation.mutate(cfg.id)} className="text-xs text-red-600 hover:underline">
                  Delete
                </button>
              </div>
              <div className="mt-2 flex items-center gap-2">
                <input
                  value={identifierByConfig[cfg.id] ?? ''}
                  onChange={(e) => setIdentifierByConfig((prev) => ({ ...prev, [cfg.id]: e.target.value }))}
                  placeholder="asset identifier"
                  className="rounded border border-gray-300 px-2 py-1 text-xs focus:border-purple-500 focus:outline-none"
                />
                <button
                  onClick={() =>
                    lookupMutation.mutate({ id: cfg.id, identifier: identifierByConfig[cfg.id] ?? '' })
                  }
                  disabled={lookupMutation.isPending || !identifierByConfig[cfg.id]?.trim()}
                  className="text-xs text-purple-700 hover:underline disabled:opacity-50"
                >
                  Look up
                </button>
              </div>
              {result &&
                (typeof result === 'string' ? (
                  <p className="mt-1 text-xs text-red-600">{result}</p>
                ) : (
                  <div className="mt-1 text-xs text-gray-600">
                    <p>
                      Owner: <span className="font-medium">{result.owner ?? '—'}</span> · Criticality:{' '}
                      <span className="font-medium">{result.criticality ?? '—'}</span>
                    </p>
                    <pre className="mt-1 max-h-40 overflow-auto rounded bg-gray-50 p-2 text-[11px]">
                      {JSON.stringify(result.raw, null, 2)}
                    </pre>
                  </div>
                ))}
            </li>
          )
        })}
      </ul>
    </section>
  )
}
