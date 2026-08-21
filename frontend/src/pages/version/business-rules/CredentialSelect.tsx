import type { CredentialSetOut } from '../../../api/types'

export function CredentialSelect({
  credentials,
  value,
  onChange,
}: {
  credentials: CredentialSetOut[]
  value: string
  onChange: (credentialSetId: string) => void
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="rounded border border-gray-300 px-3 py-2 text-sm"
    >
      <option value="">(no credential — anonymous)</option>
      {credentials.map((c) => (
        <option key={c.id} value={c.id}>
          {c.label}
        </option>
      ))}
    </select>
  )
}
