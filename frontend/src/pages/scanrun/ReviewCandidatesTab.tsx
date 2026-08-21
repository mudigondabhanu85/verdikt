import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { useAuth, canReview } from '../../auth/AuthContext'
import { StatusBadge } from '../../components/Badges'

export function ReviewCandidatesTab({ scanRunId }: { scanRunId: string }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()

  const { data: candidates, isLoading } = useQuery({
    queryKey: ['scan-runs', scanRunId, 'review-candidates'],
    queryFn: () => api.reviewCandidates.list(scanRunId),
  })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['scan-runs', scanRunId, 'review-candidates'] })
    queryClient.invalidateQueries({ queryKey: ['scan-runs', scanRunId, 'findings'] })
  }

  const promoteMutation = useMutation({
    mutationFn: (id: string) => api.reviewCandidates.promote(id),
    onSuccess: invalidate,
  })

  const dismissMutation = useMutation({
    mutationFn: (id: string) => api.reviewCandidates.dismiss(id),
    onSuccess: invalidate,
  })

  return (
    <div>
      <p className="mb-4 text-sm text-gray-500">
        Signals that couldn't be auto-confirmed (per §2's Confirmed-Only Findings Policy) — an analyst decides
        whether each one is real.
      </p>

      {isLoading && <p className="text-gray-500">Loading…</p>}
      {candidates && candidates.length === 0 && <p className="text-gray-500">No review candidates.</p>}

      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {candidates?.map((candidate) => (
          <li key={candidate.id} className="px-4 py-3">
            <div className="mb-1 flex items-center justify-between">
              <span className="font-medium">{candidate.title}</span>
              <StatusBadge status={candidate.status} />
            </div>
            <p className="mb-1 text-xs text-gray-500">{candidate.check_type} · confidence: {candidate.llm_confidence}</p>
            <p className="mb-2 text-sm text-gray-600">{candidate.llm_reasoning}</p>
            <p className="mb-2 font-mono text-xs text-gray-500">{candidate.affected_endpoint}</p>
            {canReview(user?.role) && candidate.status === 'pending' && (
              <div className="flex gap-3">
                <button
                  onClick={() => promoteMutation.mutate(candidate.id)}
                  disabled={promoteMutation.isPending}
                  className="rounded bg-green-700 px-3 py-1 text-xs font-medium text-white hover:bg-green-800 disabled:opacity-50"
                >
                  Promote to Finding
                </button>
                <button
                  onClick={() => dismissMutation.mutate(candidate.id)}
                  disabled={dismissMutation.isPending}
                  className="rounded border border-gray-300 px-3 py-1 text-xs text-gray-600 hover:bg-gray-100 disabled:opacity-50"
                >
                  Dismiss
                </button>
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}
