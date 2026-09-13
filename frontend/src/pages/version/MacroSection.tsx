import { useState, type ChangeEvent, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError, downloadBrowserExtension, VNC_BASE_URL } from '../../api/client'

// "choose": which recording path (shown right after clicking Record
// macro). "record": the existing in-app VNC flow. "extension": the
// download-and-instructions panel for the standalone browser
// extension — a real Chrome/Edge extension can't be silently
// auto-installed from a web page (browsers only allow installation
// from the Web Store, and this one isn't published there — see
// browser-extension/README.md), so "download + walk the user through
// Load unpacked" is the closest equivalent to one-click install.
type Panel = 'choose' | 'record' | 'extension' | null

export function MacroSection({ versionId, credentialId }: { versionId: string; credentialId: string }) {
  const queryClient = useQueryClient()
  const [panel, setPanel] = useState<Panel>(null)
  const [startUrl, setStartUrl] = useState('')
  const [recordingId, setRecordingId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [downloading, setDownloading] = useState(false)

  const invalidateMacros = () =>
    queryClient.invalidateQueries({ queryKey: ['versions', versionId, 'credentials', credentialId, 'macros'] })

  const { data: macros } = useQuery({
    queryKey: ['versions', versionId, 'credentials', credentialId, 'macros'],
    queryFn: () => api.credentials.listMacros(versionId, credentialId),
  })

  // Split into start/finish rather than one call that blocks until the
  // analyst closes the browser — closing the *remote*, VNC-streamed
  // window itself turned out unreliable (a dropped connection, or just
  // not finding its close button through a scaled-down canvas silently
  // lost the whole recording, since the backend request was still just
  // waiting with nothing to show for it). "Finish recording" below is
  // the fix: it's a button in Verdikt's own UI, and closing the browser
  // is something the backend does itself the moment it's clicked.
  const startMutation = useMutation({
    mutationFn: () => api.credentials.startRecordingMacro(versionId, credentialId, { start_url: startUrl }),
    onSuccess: (res) => {
      setRecordingId(res.recording_id)
      setError(null)
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Could not start recording'),
  })

  const finishMutation = useMutation({
    mutationFn: (id: string) => api.credentials.finishRecordingMacro(versionId, credentialId, id),
    onSuccess: () => {
      invalidateMacros()
      setPanel(null)
      setStartUrl('')
      setRecordingId(null)
      setError(null)
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Could not save the recording'),
  })

  const cancelMutation = useMutation({
    mutationFn: (id: string) => api.credentials.cancelRecordingMacro(versionId, credentialId, id),
    onSuccess: () => {
      setPanel(null)
      setStartUrl('')
      setRecordingId(null)
      setError(null)
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Could not cancel the recording'),
  })

  const uploadMutation = useMutation({
    mutationFn: (steps: Record<string, unknown>[]) =>
      api.credentials.uploadMacro(versionId, credentialId, { steps }),
    onSuccess: () => {
      invalidateMacros()
      setError(null)
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Upload failed'),
  })

  const [manageOpen, setManageOpen] = useState(false)

  const deleteMutation = useMutation({
    mutationFn: (macroId: string) => api.credentials.deleteMacro(versionId, credentialId, macroId),
    onSuccess: () => {
      invalidateMacros()
      setError(null)
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Could not delete the macro'),
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!startUrl.trim()) return
    setError(null)
    startMutation.mutate()
  }

  async function handleDownloadExtension() {
    setError(null)
    setDownloading(true)
    try {
      await downloadBrowserExtension()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not download the extension')
    } finally {
      setDownloading(false)
    }
  }

  async function handleFileSelected(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = '' // allow re-selecting the same file next time
    if (!file) return
    setError(null)
    try {
      const parsed = JSON.parse(await file.text())
      const steps = Array.isArray(parsed) ? parsed : parsed.steps
      if (!Array.isArray(steps)) throw new Error('not a macro steps array')
      uploadMutation.mutate(steps)
    } catch {
      setError('Could not read that file — expected the .json exported by the browser extension')
    }
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
      {panel === null && (
        <button onClick={() => setPanel('choose')} className="ml-2 text-purple-700 hover:underline">
          {macros && macros.length > 0 ? 'Re-record' : 'Record'} macro
        </button>
      )}
      <label className="ml-2 cursor-pointer text-purple-700 hover:underline">
        Upload macro
        <input type="file" accept="application/json" onChange={handleFileSelected} className="hidden" />
      </label>
      {macros && macros.length > 0 && (
        <button onClick={() => setManageOpen((v) => !v)} className="ml-2 text-purple-700 hover:underline">
          {manageOpen ? 'Hide' : 'Manage'}
        </button>
      )}

      {manageOpen && macros && macros.length > 0 && (
        <ul className="mt-2 divide-y divide-gray-200 rounded border border-gray-200 bg-gray-50">
          {macros.map((macro) => (
            <li key={macro.id} className="flex items-center justify-between px-2 py-1">
              <span className="text-gray-500">
                {macro.step_count} steps — recorded {new Date(macro.created_at).toLocaleString()}
              </span>
              <button
                onClick={() => deleteMutation.mutate(macro.id)}
                disabled={deleteMutation.isPending}
                className="text-red-600 hover:underline disabled:opacity-50"
              >
                Delete
              </button>
            </li>
          ))}
        </ul>
      )}

      {panel === 'choose' && (
        <div className="mt-2 rounded border border-gray-200 bg-gray-50 p-2">
          <p className="mb-2 text-gray-500">How do you want to record this login?</p>
          <div className="flex flex-col items-start gap-1">
            <button
              onClick={() => setPanel('record')}
              className="rounded bg-purple-700 px-2 py-1 font-medium text-white hover:bg-purple-800"
            >
              Record in-browser (recommended)
            </button>
            <span className="text-gray-400">Streams a real browser here over VNC — nothing to install.</span>
            <button onClick={() => setPanel('extension')} className="mt-1 text-purple-700 hover:underline">
              Use the browser extension instead
            </button>
            <span className="text-gray-400">
              For recording on a machine/network segment without direct access to this Verdikt instance.
            </span>
          </div>
          <button onClick={() => setPanel(null)} className="mt-2 text-gray-400 hover:underline">
            cancel
          </button>
        </div>
      )}

      {panel === 'extension' && (
        <div className="mt-2 rounded border border-gray-200 bg-gray-50 p-2">
          <button
            onClick={handleDownloadExtension}
            disabled={downloading}
            className="rounded bg-purple-700 px-2 py-1 font-medium text-white hover:bg-purple-800 disabled:opacity-50"
          >
            {downloading ? 'Downloading…' : 'Download extension (.zip)'}
          </button>
          <p className="mt-1 text-gray-500">
            Chrome/Edge won't let a web page install an extension directly — this one isn't published to the Web
            Store, so "Load unpacked" is the real install step. After downloading:
          </p>
          <ol className="ml-4 mt-1 list-decimal text-gray-500">
            <li>Unzip it.</li>
            <li>
              Open <code className="rounded bg-gray-200 px-1">chrome://extensions</code> (or{' '}
              <code className="rounded bg-gray-200 px-1">edge://extensions</code>), enable "Developer mode".
            </li>
            <li>Click "Load unpacked" and select the unzipped folder.</li>
            <li>
              On the login page, click the extension icon → "Start Recording", log in, "Stop Recording", then
              "Export macro (.json)".
            </li>
          </ol>
          <p className="mt-1 text-gray-500">
            Come back here and use <strong>"Upload macro"</strong> above to attach the exported file.
          </p>
          <button onClick={() => setPanel(null)} className="mt-2 text-gray-400 hover:underline">
            close
          </button>
        </div>
      )}

      {panel === 'record' && !recordingId && (
        <form onSubmit={handleSubmit} className="mt-2 flex items-center gap-2 rounded border border-gray-200 bg-gray-50 p-2">
          <input
            value={startUrl}
            onChange={(e) => setStartUrl(e.target.value)}
            placeholder="login page URL to start from"
            className="flex-1 rounded border border-gray-300 px-2 py-1 text-xs focus:border-purple-500 focus:outline-none"
          />
          <button
            type="submit"
            disabled={startMutation.isPending}
            className="rounded bg-purple-700 px-2 py-1 text-xs font-medium text-white hover:bg-purple-800 disabled:opacity-50"
          >
            {startMutation.isPending ? 'Starting…' : 'Start recording'}
          </button>
          <button type="button" onClick={() => setPanel(null)} className="text-gray-400 hover:underline">
            cancel
          </button>
        </form>
      )}

      {recordingId && (
        <div className="mt-2 rounded border border-yellow-300 bg-yellow-50 p-2">
          <p className="mb-2 text-xs text-yellow-800">
            A real browser window just opened — it's below, streamed live over VNC (no extension, no local display
            needed on your end). Log in there (including any manual OTP step — the URL you gave doesn't have to be
            the final destination; following an Okta/SSO redirect and back is fine). Your mouse wheel over the box
            below scrolls the <em>remote</em> page, not this one — scroll this page from outside the box. When
            you're done, click <strong>"Finish recording"</strong> below (not anything inside the box) to save it.
          </p>
          <iframe
            title="Login macro recorder (live)"
            src={`${VNC_BASE_URL}/vnc_lite.html?autoconnect=true&resize=scale&reconnect=true`}
            className="block h-[550px] w-full rounded border border-gray-300 bg-black"
          />
          <div className="mt-2 flex items-center gap-2">
            <button
              onClick={() => finishMutation.mutate(recordingId)}
              disabled={finishMutation.isPending || cancelMutation.isPending}
              className="rounded bg-purple-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-purple-800 disabled:opacity-50"
            >
              {finishMutation.isPending ? 'Saving…' : 'Finish recording'}
            </button>
            <button
              onClick={() => cancelMutation.mutate(recordingId)}
              disabled={finishMutation.isPending || cancelMutation.isPending}
              className="text-gray-500 hover:underline disabled:opacity-50"
            >
              {cancelMutation.isPending ? 'Cancelling…' : 'Cancel (discard)'}
            </button>
          </div>
        </div>
      )}

      {uploadMutation.isPending && <p className="mt-2 text-gray-400">Uploading macro…</p>}

      {error && <p className="mt-1 text-red-600">{error}</p>}
    </div>
  )
}
