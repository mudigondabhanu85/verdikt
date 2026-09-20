import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { useAuth, canWrite } from '../../auth/AuthContext'

// LLM03 Excessive Agency — per-target, since a forbidden action ("never
// approve a refund without a valid order ID") only ever makes sense
// attached to the one bot it was written for, not the whole version the
// way a business rule is.
function AgencyProbesSection({ versionId, targetId }: { versionId: string; targetId: string }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [expanded, setExpanded] = useState(false)
  const [forbiddenAction, setForbiddenAction] = useState('')

  const { data: probes } = useQuery({
    queryKey: ['versions', versionId, 'chatbot-targets', targetId, 'agency-probes'],
    queryFn: () => api.chatbotAgencyProbes.list(versionId, targetId),
    enabled: expanded,
  })

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ['versions', versionId, 'chatbot-targets', targetId, 'agency-probes'] })

  const createMutation = useMutation({
    mutationFn: () => api.chatbotAgencyProbes.create(versionId, targetId, { forbidden_action: forbiddenAction }),
    onSuccess: () => {
      invalidate()
      setForbiddenAction('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (probeId: string) => api.chatbotAgencyProbes.delete(versionId, targetId, probeId),
    onSuccess: invalidate,
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!forbiddenAction.trim()) return
    createMutation.mutate()
  }

  return (
    <div className="mt-2">
      <button onClick={() => setExpanded((v) => !v)} className="text-xs text-purple-700 hover:underline">
        {expanded ? 'Hide' : 'Show'} forbidden actions to test
        {probes && probes.length > 0 ? ` (${probes.length})` : ''}
      </button>
      {expanded && (
        <div className="mt-2 space-y-2 rounded border border-purple-200 bg-purple-50 p-3">
          <p className="text-xs text-gray-500">
            Describe an action this bot should never agree to, e.g. "process a refund without a valid order ID" —
            a scan will try to talk it into agreeing to/simulating that action.
          </p>
          {canWrite(user?.role) && (
            <form onSubmit={handleSubmit} className="flex gap-2">
              <input
                value={forbiddenAction}
                onChange={(e) => setForbiddenAction(e.target.value)}
                placeholder="forbidden action (plain language)"
                className="flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
              />
              <button
                type="submit"
                disabled={createMutation.isPending || !forbiddenAction.trim()}
                className="rounded bg-purple-700 px-3 py-2 text-xs font-medium text-white hover:bg-purple-800 disabled:opacity-50"
              >
                Add
              </button>
            </form>
          )}
          <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
            {probes?.map((probe) => (
              <li key={probe.id} className="flex items-center justify-between px-3 py-2 text-sm">
                <span>{probe.forbidden_action}</span>
                {canWrite(user?.role) && (
                  <button
                    onClick={() => deleteMutation.mutate(probe.id)}
                    className="text-xs text-red-600 hover:underline"
                  >
                    Delete
                  </button>
                )}
              </li>
            ))}
            {probes?.length === 0 && <li className="px-3 py-2 text-xs text-gray-400">None yet.</li>}
          </ul>
        </div>
      )}
    </div>
  )
}

export function ChatbotTargetsTab({ versionId }: { versionId: string }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [label, setLabel] = useState('')
  const [endpointUrl, setEndpointUrl] = useState('')
  const [httpMethod, setHttpMethod] = useState('POST')
  const [requestBodyTemplate, setRequestBodyTemplate] = useState('{"message": "{message}"}')
  const [contentType, setContentType] = useState('application/json')
  const [responseTextPath, setResponseTextPath] = useState('reply')
  const [showAuth, setShowAuth] = useState(false)
  const [authHeaderName, setAuthHeaderName] = useState('Authorization')
  const [authHeaderValue, setAuthHeaderValue] = useState('')
  const [error, setError] = useState<string | null>(null)

  const { data: targets, isLoading } = useQuery({
    queryKey: ['versions', versionId, 'chatbot-targets'],
    queryFn: () => api.chatbotTargets.list(versionId),
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['versions', versionId, 'chatbot-targets'] })

  const createMutation = useMutation({
    mutationFn: () =>
      api.chatbotTargets.create(versionId, {
        label,
        endpoint_url: endpointUrl,
        http_method: httpMethod,
        request_body_template: requestBodyTemplate,
        content_type: contentType,
        response_text_path: responseTextPath,
        auth_header_name: showAuth && authHeaderValue.trim() ? authHeaderName : null,
        auth_header_value: showAuth && authHeaderValue.trim() ? authHeaderValue : null,
      }),
    onSuccess: () => {
      invalidate()
      setLabel('')
      setEndpointUrl('')
      setRequestBodyTemplate('{"message": "{message}"}')
      setResponseTextPath('reply')
      setAuthHeaderValue('')
      setError(null)
    },
    onError: (err) => setError(err instanceof Error ? err.message : 'Failed to create chatbot target'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.chatbotTargets.delete(versionId, id),
    onSuccess: invalidate,
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (!label.trim() || !endpointUrl.trim() || !requestBodyTemplate.includes('{message}') || !responseTextPath.trim()) {
      setError('Request body template must contain a literal {message} placeholder.')
      return
    }
    createMutation.mutate()
  }

  return (
    <div>
      <p className="mb-4 text-sm text-gray-500">
        Chatbot/LLM prompt-injection testing has no way to auto-discover "this endpoint is a chat interface" —
        configure it explicitly below and a scan will test it for direct prompt injection and system-prompt/hidden-
        context extraction. "Response path" is a dot-path into the JSON reply naming where the bot's reply text
        lives (e.g. <code>reply</code>, or <code>choices.0.message.content</code>).
      </p>
      {canWrite(user?.role) && (
        <form onSubmit={handleSubmit} className="mb-6 space-y-2 rounded border border-gray-200 bg-white p-4">
          <div className="flex flex-wrap gap-2">
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="label (e.g. Support Bot)"
              className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
            />
            <input
              value={endpointUrl}
              onChange={(e) => setEndpointUrl(e.target.value)}
              placeholder="chat endpoint URL"
              className="min-w-64 flex-1 rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
            />
            <select
              value={httpMethod}
              onChange={(e) => setHttpMethod(e.target.value)}
              className="rounded border border-gray-300 px-3 py-2 text-sm"
            >
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
            </select>
          </div>
          <input
            value={requestBodyTemplate}
            onChange={(e) => setRequestBodyTemplate(e.target.value)}
            placeholder='request body template, must contain {message} — e.g. {"message": "{message}"}'
            className="w-full rounded border border-gray-300 px-3 py-2 font-mono text-sm focus:border-purple-500 focus:outline-none"
          />
          <div className="flex flex-wrap gap-2">
            <input
              value={contentType}
              onChange={(e) => setContentType(e.target.value)}
              placeholder="content type"
              className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
            />
            <input
              value={responseTextPath}
              onChange={(e) => setResponseTextPath(e.target.value)}
              placeholder="response text path (e.g. reply)"
              className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
            />
            <button
              type="button"
              onClick={() => setShowAuth((v) => !v)}
              className="text-xs text-purple-700 hover:underline"
            >
              {showAuth ? 'Hide' : 'Show'} auth header
            </button>
          </div>
          {showAuth && (
            <div className="flex flex-wrap gap-2">
              <input
                value={authHeaderName}
                onChange={(e) => setAuthHeaderName(e.target.value)}
                placeholder="auth header name"
                className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
              />
              <input
                value={authHeaderValue}
                onChange={(e) => setAuthHeaderValue(e.target.value)}
                placeholder="auth header value (optional)"
                type="password"
                className="rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
              />
            </div>
          )}
          {error && <p className="text-sm text-red-600">{error}</p>}
          <button
            type="submit"
            disabled={createMutation.isPending}
            className="rounded bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
          >
            Add chatbot target
          </button>
        </form>
      )}

      {isLoading && <p className="text-gray-500">Loading…</p>}
      <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
        {targets?.map((target) => (
          <li key={target.id} className="px-4 py-3">
            <div className="flex items-center justify-between">
              <span>
                <span className="font-medium">{target.label}</span>
                <span className="ml-2 text-gray-500">
                  {target.http_method} {target.endpoint_url}
                </span>
                {target.masked_reference && (
                  <span className="ml-2 rounded-full border border-gray-300 bg-gray-100 px-2 py-0.5 text-xs text-gray-600">
                    {target.auth_header_name}: {target.masked_reference}
                  </span>
                )}
              </span>
              {canWrite(user?.role) && (
                <button
                  onClick={() => deleteMutation.mutate(target.id)}
                  className="text-xs text-red-600 hover:underline"
                >
                  Delete
                </button>
              )}
            </div>
            <AgencyProbesSection versionId={versionId} targetId={target.id} />
          </li>
        ))}
      </ul>
    </div>
  )
}
