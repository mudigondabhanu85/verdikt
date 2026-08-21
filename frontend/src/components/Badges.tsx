import type { Severity } from '../api/types'

const SEVERITY_COLORS: Record<Severity, string> = {
  Critical: 'bg-red-100 text-red-800 border-red-300',
  High: 'bg-orange-100 text-orange-800 border-orange-300',
  Medium: 'bg-yellow-100 text-yellow-800 border-yellow-300',
  Low: 'bg-blue-100 text-blue-800 border-blue-300',
}

export function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_COLORS[severity as Severity] ?? 'bg-gray-100 text-gray-800 border-gray-300'
  return (
    <span className={`inline-block rounded-full border px-2 py-0.5 text-xs font-medium ${cls}`}>{severity}</span>
  )
}

const STATUS_COLORS: Record<string, string> = {
  running: 'bg-blue-100 text-blue-800 border-blue-300',
  completed: 'bg-green-100 text-green-800 border-green-300',
  failed: 'bg-red-100 text-red-800 border-red-300',
  skipped: 'bg-gray-100 text-gray-700 border-gray-300',
  pending: 'bg-gray-100 text-gray-700 border-gray-300',
  promoted: 'bg-green-100 text-green-800 border-green-300',
  dismissed: 'bg-gray-100 text-gray-500 border-gray-300',
}

export function StatusBadge({ status, testId }: { status: string; testId?: string }) {
  const cls = STATUS_COLORS[status] ?? 'bg-gray-100 text-gray-800 border-gray-300'
  return (
    <span data-testid={testId} className={`inline-block rounded-full border px-2 py-0.5 text-xs font-medium ${cls}`}>
      {status}
    </span>
  )
}
