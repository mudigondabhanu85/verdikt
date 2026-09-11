import { useState } from 'react'
import { downloadReport } from '../../api/client'

const FORMATS = ['json', 'html', 'pdf', 'docx', 'csv'] as const

export function ReportsTab({ scanRunId }: { scanRunId: string }) {
  const [downloading, setDownloading] = useState<string | null>(null)

  async function handleDownload(format: (typeof FORMATS)[number] | 'vgs.docx') {
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
      <div className="flex flex-wrap gap-3">
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
        <button
          onClick={() => handleDownload('vgs.docx')}
          disabled={downloading === 'vgs.docx'}
          className="rounded border border-purple-300 bg-purple-50 px-4 py-2 text-sm font-medium text-purple-700 hover:bg-purple-100 disabled:opacity-50"
          title="Same VGS-shaped format (pie chart, summary table) as the VGS workspace's own report, built fresh from just this scan's findings — no curation required."
        >
          {downloading === 'vgs.docx' ? 'Downloading…' : 'Download VGS-format .docx'}
        </button>
      </div>
    </div>
  )
}
