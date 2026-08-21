import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { useAuth, canWrite } from '../../auth/AuthContext'

export function AuthorizationTab({ versionId }: { versionId: string }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [approverName, setApproverName] = useState('')
  const [attestationText, setAttestationText] = useState('')
  const [letter, setLetter] = useState<File | null>(null)

  const { data: records, isLoading } = useQuery({
    queryKey: ['versions', versionId, 'authorization'],
    queryFn: () => api.versions.listAuthorizationRecords(versionId),
  })

  const createMutation = useMutation({
    mutationFn: () =>
      api.versions.addAuthorizationRecord(versionId, {
        approver_name: approverName,
        attestation_text: attestationText || undefined,
        letter: letter ?? undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['versions', versionId, 'authorization'] })
      queryClient.invalidateQueries({ queryKey: ['versions', versionId] })
      setApproverName('')
      setAttestationText('')
      setLetter(null)
    },
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!approverName.trim() || (!attestationText.trim() && !letter)) return
    createMutation.mutate()
  }

  return (
    <div>
      <p className="mb-4 text-sm text-gray-500">
        §1's authorization gate — a scan can't be started until at least one record exists here (an attestation
        and/or an uploaded authorization letter).
      </p>
      {canWrite(user?.role) && (
        <form onSubmit={handleSubmit} className="mb-6 space-y-2">
          <input
            value={approverName}
            onChange={(e) => setApproverName(e.target.value)}
            placeholder="approver name"
            className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <textarea
            value={attestationText}
            onChange={(e) => setAttestationText(e.target.value)}
            placeholder="attestation text (e.g. 'I confirm authorization to test this scope')"
            rows={2}
            className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
          <input
            type="file"
            onChange={(e) => setLetter(e.target.files?.[0] ?? null)}
            className="text-sm"
          />
          <button
            type="submit"
            disabled={createMutation.isPending}
            className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
          >
            Record authorization
          </button>
        </form>
      )}

      {isLoading && <p className="text-gray-500">Loading…</p>}
      {records && records.length === 0 && <p className="text-sm text-red-600">No authorization on record yet.</p>}
      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {records?.map((record) => (
          <li key={record.id} className="px-4 py-3">
            <div className="font-medium">{record.approver_name}</div>
            {record.attestation_text && <div className="text-sm text-gray-600">{record.attestation_text}</div>}
            {record.letter_object_key && <div className="text-xs text-gray-400">letter uploaded</div>}
            <div className="text-xs text-gray-400">{new Date(record.attested_at).toLocaleString()}</div>
          </li>
        ))}
      </ul>
    </div>
  )
}
