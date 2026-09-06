import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AuthenticatedImage } from '../../../components/AuthenticatedImage'
import { vgsApi } from './api'

function StepsPanel({ versionId, vulnId }: { versionId: string; vulnId: string }) {
  const queryClient = useQueryClient()
  const fileInputRef = useRef<HTMLInputElement>(null)

  const { data: steps } = useQuery({
    queryKey: ['vgs-evidence-steps', versionId, vulnId],
    queryFn: () => vgsApi.evidenceSteps.list(versionId, vulnId),
  })

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ['vgs-evidence-steps', versionId, vulnId] })

  const addStepMutation = useMutation({
    mutationFn: (file?: File) => vgsApi.evidenceSteps.add(versionId, vulnId, '', file),
    onSuccess: invalidate,
  })

  const updateCommentMutation = useMutation({
    mutationFn: ({ stepId, comment }: { stepId: string; comment: string }) =>
      vgsApi.evidenceSteps.update(versionId, vulnId, stepId, { comment }),
    onSuccess: invalidate,
  })

  const removeStepMutation = useMutation({
    mutationFn: (stepId: string) => vgsApi.evidenceSteps.delete(versionId, vulnId, stepId),
    onSuccess: invalidate,
  })

  return (
    <div>
      {(steps ?? []).map((step, idx) => (
        <div key={step.id} className="mb-3 rounded border border-gray-200 p-3">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-sm font-semibold">Step {idx + 1}</span>
            <button onClick={() => removeStepMutation.mutate(step.id)} className="text-lg font-bold text-red-500">
              −
            </button>
          </div>
          <textarea
            defaultValue={step.comment}
            rows={2}
            placeholder="Enter comment…"
            onBlur={(e) => updateCommentMutation.mutate({ stepId: step.id, comment: e.target.value })}
            className="w-full resize-y rounded border border-gray-300 px-2 py-1.5 text-sm"
          />
          <div className="mt-2 flex flex-wrap gap-2">
            {step.screenshot_object_keys.map((key) => (
              <AuthenticatedImage
                key={key}
                objectKey={key}
                alt={`Step ${idx + 1} evidence`}
                className="max-w-xs rounded border"
              />
            ))}
          </div>
        </div>
      ))}

      <div className="flex items-center gap-2">
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0]
            addStepMutation.mutate(file)
            e.target.value = ''
          }}
        />
        <button
          onClick={() => fileInputRef.current?.click()}
          className="rounded bg-green-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-green-700"
        >
          + Add Step (with screenshot)
        </button>
        <button
          onClick={() => addStepMutation.mutate(undefined)}
          className="rounded border border-gray-300 px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-50"
        >
          + Add Step (no screenshot)
        </button>
      </div>
    </div>
  )
}

export function ReportEvidenceTab({ versionId }: { versionId: string }) {
  const { data: vulnerabilities } = useQuery({
    queryKey: ['vgs-report-vulnerabilities', versionId],
    queryFn: () => vgsApi.vulnerabilities.list(versionId),
  })

  const [activeId, setActiveId] = useState<string | null>(null)

  useEffect(() => {
    if (vulnerabilities && vulnerabilities.length > 0 && !activeId) {
      setActiveId(vulnerabilities[0].id)
    }
  }, [vulnerabilities, activeId])

  if (!vulnerabilities || vulnerabilities.length === 0) {
    return <p className="text-gray-500">Select vulnerabilities in the "Report: Vulnerabilities" tab first.</p>
  }

  const active = vulnerabilities.find((v) => v.id === activeId)

  return (
    <div className="flex gap-6">
      <div className="w-1/4 border-r border-gray-200 pr-4">
        <h3 className="mb-2 font-semibold text-gray-800">Selected Vulnerabilities</h3>
        <ul className="space-y-1">
          {vulnerabilities.map((v) => (
            <li
              key={v.id}
              onClick={() => setActiveId(v.id)}
              className={`cursor-pointer rounded border px-3 py-2 text-sm ${
                activeId === v.id ? 'border-purple-300 bg-purple-100 font-medium' : 'border-transparent hover:bg-gray-100'
              }`}
            >
              {v.title}
            </li>
          ))}
        </ul>
      </div>
      <div className="w-3/4">
        <h3 className="mb-3 text-base font-semibold text-gray-800">Evidence for: {active?.title}</h3>
        {activeId && <StepsPanel versionId={versionId} vulnId={activeId} />}
      </div>
    </div>
  )
}
