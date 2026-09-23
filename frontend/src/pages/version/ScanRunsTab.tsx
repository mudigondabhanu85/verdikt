import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../../api/client'
import { useAuth, canWrite, canRunAutonomousPentest } from '../../auth/AuthContext'
import { StatusBadge, FindingCountsSummary } from '../../components/Badges'

// "3m 12s" / "45s" — never a raw millisecond count, and never a
// negative/garbage value if the timestamps are momentarily inconsistent
// (e.g. clock skew between the row's own started_at and the moment this
// renders for a still-running scan).
function formatDuration(startedAt: string | null, completedAt: string | null): string | null {
  if (!startedAt) return null
  const end = completedAt ? new Date(completedAt).getTime() : Date.now()
  const start = new Date(startedAt).getTime()
  const totalSeconds = Math.max(0, Math.round((end - start) / 1000))
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`
}

// The consent step for POST .../autonomous-pentest-sessions — a typed-
// match confirmation naming the real target host(s), not a generic
// "are you sure" dialog, since this is the one action in the app that
// runs live exploitation tooling with real side effects against a real
// target. See backend/app/api/routes/autonomous_pentest.py's own
// docstring for why this is a request field, not just RBAC.
function AutonomousPentestPanel({ versionId, onDone }: { versionId: string; onDone: () => void }) {
  const [objective, setObjective] = useState('')
  const [confirmationText, setConfirmationText] = useState('')
  const [showConfirm, setShowConfirm] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const phraseQuery = useQuery({
    queryKey: ['versions', versionId, 'autonomous-pentest-confirmation-phrase'],
    queryFn: () => api.autonomousPentest.confirmationPhrase(versionId),
    enabled: showConfirm,
  })

  const startMutation = useMutation({
    mutationFn: () => api.autonomousPentest.create(versionId, { confirmation_text: confirmationText, objective }),
    onSuccess: () => {
      setError(null)
      onDone()
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'Could not start the session'),
  })

  if (!showConfirm) {
    return (
      <div className="mt-2 rounded border border-purple-200 bg-purple-50 p-3">
        <label className="mb-1 block text-xs font-medium text-purple-900">
          What should the AI investigate?
        </label>
        <input
          value={objective}
          onChange={(e) => setObjective(e.target.value)}
          placeholder="e.g. identify SQL injection vulnerabilities"
          className="w-full rounded border border-gray-300 px-2 py-1.5 text-sm focus:border-purple-500 focus:outline-none"
        />
        <div className="mt-2 flex items-center gap-2">
          <button
            onClick={() => setShowConfirm(true)}
            disabled={!objective.trim()}
            className="rounded bg-purple-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-purple-800 disabled:opacity-50"
          >
            Continue
          </button>
          <button onClick={onDone} className="text-xs text-gray-500 hover:underline">
            Cancel
          </button>
        </div>
      </div>
    )
  }

  const phrase = phraseQuery.data?.confirmation_phrase

  return (
    <div className="mt-2 rounded border border-purple-200 bg-purple-50 p-3">
      <p className="mb-2 text-xs text-purple-900">
        This starts a session that runs real exploitation tooling (curl, nmap, sqlmap, nikto,
        ffuf) inside an isolated sandbox, restricted at the network layer to only this
        Version's in-scope target host(s). To confirm, type the phrase below exactly.
      </p>
      {phraseQuery.isLoading && <p className="text-xs text-gray-500">Loading…</p>}
      {phraseQuery.isError && (
        <p className="text-xs text-red-600">
          {phraseQuery.error instanceof ApiError ? phraseQuery.error.message : 'Could not load the confirmation phrase'}
        </p>
      )}
      {phrase && (
        <>
          <p className="mb-2 rounded bg-white px-2 py-1.5 font-mono text-xs text-gray-800">{phrase}</p>
          <input
            value={confirmationText}
            onChange={(e) => setConfirmationText(e.target.value)}
            placeholder="Type the phrase above"
            className="w-full rounded border border-gray-300 px-2 py-1.5 text-sm focus:border-purple-500 focus:outline-none"
          />
        </>
      )}
      <div className="mt-2 flex items-center gap-2">
        <button
          onClick={() => startMutation.mutate()}
          disabled={!phrase || confirmationText !== phrase || startMutation.isPending}
          className="rounded bg-purple-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-purple-800 disabled:opacity-50"
        >
          {startMutation.isPending ? 'Starting…' : 'Start AI-driven pentest'}
        </button>
        <button onClick={() => setShowConfirm(false)} className="text-xs text-gray-500 hover:underline">
          Back
        </button>
      </div>
      {error && <p className="mt-2 text-xs text-red-600">{error}</p>}
    </div>
  )
}

export function ScanRunsTab({ versionId }: { versionId: string }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null)
  const [showAutonomousPanel, setShowAutonomousPanel] = useState(false)

  const { data: scanRuns, isLoading } = useQuery({
    queryKey: ['versions', versionId, 'scan-runs'],
    queryFn: () => api.scanRuns.list(versionId),
    refetchInterval: (query) => (query.state.data?.some((s) => s.status === 'running' || s.status === 'pending') ? 3000 : false),
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['versions', versionId, 'scan-runs'] })

  const startMutation = useMutation({
    mutationFn: () => api.scanRuns.create(versionId),
    onSuccess: invalidate,
  })

  const retestMutation = useMutation({
    mutationFn: (priorId: string) => api.scanRuns.retest(versionId, priorId),
    onSuccess: invalidate,
  })

  const cancelMutation = useMutation({
    mutationFn: (scanRunId: string) => api.scanRuns.cancel(scanRunId),
    onSuccess: invalidate,
  })

  const deleteMutation = useMutation({
    mutationFn: (scanRunId: string) => api.scanRuns.delete(scanRunId),
    onSuccess: () => {
      invalidate()
      setDeleteConfirmId(null)
    },
  })

  return (
    <div>
      {(canWrite(user?.role) || canRunAutonomousPentest(user?.role)) && (
        <div className="mb-6">
          <div className="flex flex-wrap items-center gap-2">
            {canWrite(user?.role) && (
              <button
                onClick={() => startMutation.mutate()}
                disabled={startMutation.isPending}
                className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
              >
                {startMutation.isPending ? 'Starting…' : 'Start new scan'}
              </button>
            )}
            {canRunAutonomousPentest(user?.role) && !showAutonomousPanel && (
              <button
                onClick={() => setShowAutonomousPanel(true)}
                className="rounded border border-purple-700 px-4 py-2 text-sm font-medium text-purple-700 hover:bg-purple-50"
              >
                Start AI-driven pentest
              </button>
            )}
          </div>
          {startMutation.isError && (
            <p className="mt-2 text-sm text-red-600">{(startMutation.error as Error).message}</p>
          )}
          {showAutonomousPanel && (
            <AutonomousPentestPanel
              versionId={versionId}
              onDone={() => {
                setShowAutonomousPanel(false)
                invalidate()
              }}
            />
          )}
        </div>
      )}

      {isLoading && <p className="text-gray-500">Loading…</p>}
      {scanRuns && scanRuns.length === 0 && <p className="text-gray-500">No scan runs yet.</p>}

      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {scanRuns?.map((run) => {
          const isActive = run.status === 'pending' || run.status === 'running'
          const duration = formatDuration(run.started_at, run.completed_at)
          return (
            <li key={run.id} className="flex items-center justify-between gap-4 px-4 py-3">
              <Link to={`/scan-runs/${run.id}`} className="flex-1 hover:underline">
                <div>
                  <span className="mr-3 font-mono text-xs text-gray-400">{run.id.slice(0, 8)}</span>
                  {run.mode === 'autonomous_ai' && (
                    <span className="mr-3 rounded bg-purple-100 px-1.5 py-0.5 text-xs font-medium text-purple-800">
                      AI pentest
                    </span>
                  )}
                  <StatusBadge status={run.status} />
                  {run.started_at && (
                    <span className="ml-3 text-xs text-gray-400">{new Date(run.started_at).toLocaleString()}</span>
                  )}
                  {duration && (
                    <span className="ml-3 text-xs text-gray-400">
                      {isActive ? `running ${duration}` : duration}
                    </span>
                  )}
                  {run.error && <span className="ml-3 text-xs text-red-600">{run.error}</span>}
                  {run.warning && (
                    <span className="ml-3 text-xs text-amber-700" title={run.warning}>
                      ⚠ found nothing — likely misconfigured
                    </span>
                  )}
                </div>
                {!isActive && (
                  <div className="mt-1">
                    {Object.values(run.finding_counts_by_severity).some((c) => c > 0) ? (
                      <FindingCountsSummary counts={run.finding_counts_by_severity} />
                    ) : (
                      <span className="text-xs text-gray-400">No findings</span>
                    )}
                  </div>
                )}
              </Link>
              {canWrite(user?.role) && (
                <span className="flex items-center gap-3">
                  {!isActive && run.mode !== 'autonomous_ai' && (
                    <button
                      onClick={() => retestMutation.mutate(run.id)}
                      disabled={retestMutation.isPending}
                      className="text-xs text-purple-700 hover:underline"
                    >
                      Retest
                    </button>
                  )}
                  {isActive && (
                    <button
                      onClick={() => cancelMutation.mutate(run.id)}
                      disabled={cancelMutation.isPending}
                      className="text-xs text-amber-700 hover:underline disabled:opacity-40"
                    >
                      Cancel
                    </button>
                  )}
                  {!isActive &&
                    (deleteConfirmId === run.id ? (
                      <span className="flex items-center gap-2">
                        <span className="text-xs text-gray-500">Delete this scan?</span>
                        <button
                          onClick={() => deleteMutation.mutate(run.id)}
                          disabled={deleteMutation.isPending}
                          className="text-xs font-medium text-red-700 hover:underline disabled:opacity-40"
                        >
                          Confirm
                        </button>
                        <button
                          onClick={() => setDeleteConfirmId(null)}
                          className="text-xs text-gray-500 hover:underline"
                        >
                          Cancel
                        </button>
                      </span>
                    ) : (
                      <button
                        onClick={() => setDeleteConfirmId(run.id)}
                        className="text-xs text-red-600 hover:underline"
                      >
                        Delete
                      </button>
                    ))}
                </span>
              )}
            </li>
          )
        })}
      </ul>
    </div>
  )
}
