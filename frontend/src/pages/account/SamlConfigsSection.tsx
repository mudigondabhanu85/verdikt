import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, downloadSamlMetadata } from '../../api/client'

export function SamlConfigsSection() {
  const queryClient = useQueryClient()
  const [label, setLabel] = useState('')
  const [idpMetadataXml, setIdpMetadataXml] = useState<Record<string, string>>({})

  const { data: configs, isLoading } = useQuery({
    queryKey: ['saml-configs'],
    queryFn: api.samlConfigs.list,
  })
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['saml-configs'] })

  const createMutation = useMutation({
    mutationFn: () => api.samlConfigs.create({ label }),
    onSuccess: () => {
      invalidate()
      setLabel('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.samlConfigs.delete(id),
    onSuccess: invalidate,
  })

  const uploadIdpMutation = useMutation({
    mutationFn: (id: string) => api.samlConfigs.uploadIdpMetadata(id, { idp_metadata_xml: idpMetadataXml[id] }),
    onSuccess: invalidate,
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!label.trim()) return
    createMutation.mutate()
  }

  return (
    <section className="mb-10">
      <h2 className="mb-3 text-lg font-medium text-gray-800">SAML (Okta) SSO</h2>
      <p className="mb-4 text-sm text-gray-500">
        Create a config, download its SP metadata XML and hand it to your Okta admin when creating the Okta SAML
        app integration, then paste back the IdP metadata Okta gives you to complete the trust relationship. Full
        assertion handshake (actually logging in) requires a real Okta tenant to validate against — this build
        generates and stores real, valid SP/IdP metadata, but hasn't been round-tripped against a live Okta org.
      </p>

      <form onSubmit={handleSubmit} className="mb-4 flex flex-wrap gap-2">
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="label (e.g. Okta)"
          className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
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
                <span className="ml-2 text-xs text-gray-400">
                  {cfg.has_idp_metadata ? 'IdP metadata configured' : 'awaiting IdP metadata'}
                </span>
              </span>
              <span className="flex items-center gap-3">
                <button
                  onClick={() => downloadSamlMetadata(cfg.id)}
                  className="text-xs text-purple-700 hover:underline"
                >
                  Download SP metadata
                </button>
                <button onClick={() => deleteMutation.mutate(cfg.id)} className="text-xs text-red-600 hover:underline">
                  Delete
                </button>
              </span>
            </div>
            <div className="mt-2 flex gap-2">
              <textarea
                value={idpMetadataXml[cfg.id] ?? ''}
                onChange={(e) => setIdpMetadataXml((prev) => ({ ...prev, [cfg.id]: e.target.value }))}
                placeholder="Paste Okta's IdP metadata XML here"
                rows={2}
                className="min-w-64 flex-1 rounded border border-gray-300 px-3 py-2 font-mono text-xs focus:border-purple-500 focus:outline-none"
              />
              <button
                onClick={() => uploadIdpMutation.mutate(cfg.id)}
                disabled={uploadIdpMutation.isPending || !idpMetadataXml[cfg.id]?.trim()}
                className="rounded border border-purple-700 px-3 py-2 text-xs font-medium text-purple-700 hover:bg-purple-50 disabled:opacity-50"
              >
                Save IdP metadata
              </button>
            </div>
          </li>
        ))}
      </ul>
    </section>
  )
}
