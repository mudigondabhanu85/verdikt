const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']

export function HttpMethodSelect({ value, onChange }: { value: string; onChange: (method: string) => void }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="rounded border border-gray-300 px-3 py-2 text-sm"
    >
      {METHODS.map((m) => (
        <option key={m} value={m}>
          {m}
        </option>
      ))}
    </select>
  )
}
