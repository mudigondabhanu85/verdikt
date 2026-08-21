import { useState } from 'react'
import { downloadReport } from '../../api/client'

const FORMATS = ['json', 'html', 'pdf', 'docx', 'csv'] as const

export function ReportsTab({ scanRunId }: { scanRunId: string }) {
  const [downloading, setDownloading] = useState<string | null>(null)

  async function handleDownload(format: (typeof FORMATS)[number]) {
    setDownloading(format)
    try {
      await downloadReport(scanRunId, format)
    } finally {
      setDownloading(null)
    }
  }

  return (
    <div>
      <p className="mb-4 text-sm text-gray-500">
        Each format includes an LLM-generated executive summary plus every confirmed finding.
      </p>
      <div className="flex gap-3">
        {FORMATS.map((format) => (
          <button
            key={format}
            onClick={() => handleDownload(format)}
            disabled={downloading === format}
            className="rounded border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            {downloading === format ? 'Downloading…' : `Download .${format}`}
          </button>
        ))}
      </div>
    </div>
  )
}
