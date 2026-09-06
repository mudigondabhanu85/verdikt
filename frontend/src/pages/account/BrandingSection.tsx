import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'

export function BrandingSection() {
  const queryClient = useQueryClient()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [companyName, setCompanyName] = useState('')
  const [primaryColorHex, setPrimaryColorHex] = useState('')

  const { data: branding, isLoading } = useQuery({
    queryKey: ['org-branding'],
    queryFn: api.orgBranding.get,
  })
  useEffect(() => {
    if (branding) {
      setCompanyName(branding.company_name ?? '')
      setPrimaryColorHex(branding.primary_color_hex ?? '')
    }
  }, [branding])
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['org-branding'] })

  const updateMutation = useMutation({
    mutationFn: () =>
      api.orgBranding.update({ company_name: companyName || null, primary_color_hex: primaryColorHex || null }),
    onSuccess: invalidate,
  })

  const uploadLogoMutation = useMutation({
    mutationFn: (file: File) => api.orgBranding.uploadLogo(file),
    onSuccess: invalidate,
  })

  const deleteLogoMutation = useMutation({
    mutationFn: () => api.orgBranding.deleteLogo(),
    onSuccess: invalidate,
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    updateMutation.mutate()
  }

  return (
    <section className="mb-10">
      <h2 className="mb-3 text-lg font-medium text-gray-800">Report branding</h2>
      <p className="mb-4 text-sm text-gray-500">
        Company name, accent color, and logo appear on the cover page and headers of every generated report
        (Word/PDF/HTML) once set — leave blank for Verdikt's default look.
      </p>

      {isLoading && <p className="text-gray-500">Loading…</p>}

      <form onSubmit={handleSubmit} className="mb-4 flex flex-wrap items-center gap-2">
        <input
          value={companyName}
          onChange={(e) => setCompanyName(e.target.value)}
          placeholder="Company name"
          className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <input
          value={primaryColorHex}
          onChange={(e) => setPrimaryColorHex(e.target.value)}
          placeholder="#1a56db"
          className="w-28 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
        />
        <button
          type="submit"
          disabled={updateMutation.isPending}
          className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
        >
          Save
        </button>
      </form>

      <div className="flex items-center gap-3 rounded border border-gray-200 bg-white px-4 py-3 text-sm">
        {branding?.logo_object_key ? (
          <>
            <span className="text-gray-600">Logo uploaded</span>
            <button
              onClick={() => deleteLogoMutation.mutate()}
              disabled={deleteLogoMutation.isPending}
              className="text-xs text-red-600 hover:underline"
            >
              Remove logo
            </button>
          </>
        ) : (
          <span className="text-gray-400">No logo uploaded</span>
        )}
        <input
          ref={fileInputRef}
          type="file"
          accept="image/png,image/jpeg,image/gif,image/webp"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0]
            if (file) uploadLogoMutation.mutate(file)
            e.target.value = ''
          }}
        />
        <button
          onClick={() => fileInputRef.current?.click()}
          disabled={uploadLogoMutation.isPending}
          className="rounded border border-purple-700 px-3 py-1.5 text-xs font-medium text-purple-700 hover:bg-purple-50 disabled:opacity-50"
        >
          Upload logo
        </button>
      </div>
    </section>
  )
}
