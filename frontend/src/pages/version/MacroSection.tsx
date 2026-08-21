import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../../api/client'

export function MacroSection({ versionId, credentialId }: { versionId: string; credentialId: string }) {
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [startUrl, setStartUrl] = useState('')
  const [error, setError] = useState<string | null>(null)

  const { data: macros } = useQuery({
    queryKey: ['versions', versionId, 'credentials', credentialId, 'macros'],
    queryFn: () => api.credentials.listMacros(versionId, credentialId),
  })

  const recordMutation = useMutation({
    mutationFn: () => api.credentials.recordMacro(versionId, credentialId, { start_url: startUrl }),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ['versions', versionId, 'credentials', credentialId, 'macros'],
      })
      setOpen(false)
      setStartUrl('')
      setError(null)
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Recording failed'),
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!startUrl.trim()) return
    setError(null)
    recordMutation.mutate()
  }

  return (
    <div className="mt-1 text-xs">
      {macros && macros.length > 0 ? (
        <span className="text-gray-400">
          {macros.length} recorded macro{macros.length > 1 ? 's' : ''} (latest {macros[macros.length - 1].step_count}{' '}
          steps)
        </span>
      ) : (
        <span className="text-gray-400">No login macro recorded</span>
      )}
      {!open && (
        <button onClick={() => setOpen(true)} className="ml-2 text-purple-700 hover:underline">
          {macros && macros.length > 0 ? 'Re-record' : 'Record'} macro
        </button>
      )}

      {open && !recordMutation.isPending && (
        <form onSubmit={handleSubmit} className="mt-2 flex items-center gap-2 rounded border border-gray-200 bg-gray-50 p-2">
          <input
            value={startUrl}
            onChange={(e) => setStartUrl(e.target.value)}
            placeholder="login page URL to start from"
            className="flex-1 rounded border border-gray-300 px-2 py-1 text-xs focus:border-purple-500 focus:outline-none"
          />
          <button type="submit" className="rounded bg-purple-700 px-2 py-1 text-xs font-medium text-white hover:bg-purple-800">
            Start recording
          </button>
          <button type="button" onClick={() => setOpen(false)} className="text-gray-400 hover:underline">
            cancel
          </button>
        </form>
      )}

      {recordMutation.isPending && (
        <p className="mt-2 rounded border border-yellow-300 bg-yellow-50 px-2 py-1 text-xs text-yellow-800">
          A real browser window just opened on the machine running the API server — this only works when that's a
          machine you can see. Log in there (including any manual OTP step) and close the window to finish; this
          request will keep waiting until you do.
        </p>
      )}

      {error && <p className="mt-1 text-red-600">{error}</p>}
    </div>
  )
}
