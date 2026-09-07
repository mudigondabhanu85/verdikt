import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '../../api/client'
import { useAuth, canWrite } from '../../auth/AuthContext'
import { StatusBadge } from '../../components/Badges'

export function ScanRunsTab({ versionId }: { versionId: string }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null)

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
      {canWrite(user?.role) && (
        <div className="mb-6">
          <button
            onClick={() => startMutation.mutate()}
            disabled={startMutation.isPending}
            className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
          >
            {startMutation.isPending ? 'Starting…' : 'Start new scan'}
          </button>
          {startMutation.isError && (
            <p className="mt-2 text-sm text-red-600">{(startMutation.error as Error).message}</p>
          )}
        </div>
      )}

      {isLoading && <p className="text-gray-500">Loading…</p>}
      {scanRuns && scanRuns.length === 0 && <p className="text-gray-500">No scan runs yet.</p>}

      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {scanRuns?.map((run) => {
          const isActive = run.status === 'pending' || run.status === 'running'
          return (
            <li key={run.id} className="flex items-center justify-between px-4 py-3">
              <Link to={`/scan-runs/${run.id}`} className="flex-1 hover:underline">
                <span className="mr-3 font-mono text-xs text-gray-400">{run.id.slice(0, 8)}</span>
                <StatusBadge status={run.status} />
                {run.started_at && (
                  <span className="ml-3 text-xs text-gray-400">{new Date(run.started_at).toLocaleString()}</span>
                )}
                {run.error && <span className="ml-3 text-xs text-red-600">{run.error}</span>}
              </Link>
              {canWrite(user?.role) && (
                <span className="flex items-center gap-3">
                  {!isActive && (
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
