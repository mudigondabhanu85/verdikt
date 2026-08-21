import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../../api/client'

export function TicketSection({ findingId }: { findingId: string }) {
  const queryClient = useQueryClient()
  const [selectedConfig, setSelectedConfig] = useState('')

  const { data: configs } = useQuery({
    queryKey: ['ticketing-configs'],
    queryFn: api.ticketingConfigs.list,
  })

  const { data: tickets } = useQuery({
    queryKey: ['findings', findingId, 'tickets'],
    queryFn: () => api.findingTickets.list(findingId),
  })

  const createMutation = useMutation({
    mutationFn: (ticketingConfigId: string) => api.findingTickets.create(findingId, ticketingConfigId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['findings', findingId, 'tickets'] }),
  })

  if (!configs || configs.length === 0) {
    return null // no ticketing system configured for this org — nothing to offer here
  }

  return (
    <div>
      <h4 className="mb-1 font-medium text-gray-700">Ticket</h4>
      {tickets && tickets.length > 0 && (
        <ul className="mb-2 space-y-0.5 text-xs">
          {tickets.map((t) => (
            <li key={t.id}>
              <a href={t.external_url} target="_blank" rel="noreferrer" className="text-purple-700 hover:underline">
                {t.external_key}
              </a>
            </li>
          ))}
        </ul>
      )}
      <div className="flex items-center gap-2">
        <select
          value={selectedConfig}
          onChange={(e) => setSelectedConfig(e.target.value)}
          className="rounded border border-gray-300 px-2 py-1 text-xs"
        >
          <option value="">Select a ticketing system…</option>
          {configs.map((cfg) => (
            <option key={cfg.id} value={cfg.id}>
              {cfg.label} ({cfg.project_key})
            </option>
          ))}
        </select>
        <button
          onClick={() => selectedConfig && createMutation.mutate(selectedConfig)}
          disabled={!selectedConfig || createMutation.isPending}
          className="rounded border border-gray-300 bg-white px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
        >
          {createMutation.isPending ? 'Creating…' : 'Create ticket'}
        </button>
      </div>
      {createMutation.isError && (
        <p className="mt-1 text-xs text-red-600">
          {createMutation.error instanceof ApiError ? createMutation.error.message : 'Could not create ticket'}
        </p>
      )}
    </div>
  )
}
