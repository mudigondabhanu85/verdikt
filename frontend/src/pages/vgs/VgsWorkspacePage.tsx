import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { api } from '../../api/client'
import { Tabs } from '../../components/Tabs'
import { ReportProjectInfoTab } from '../version/vgs/ReportProjectInfoTab'
import { ReportVulnerabilitiesTab } from '../version/vgs/ReportVulnerabilitiesTab'
import { ReportEvidenceTab } from '../version/vgs/ReportEvidenceTab'
import { ReportGenerateTab } from '../version/vgs/ReportGenerateTab'
import { ManageVulnerabilitiesTab } from './ManageVulnerabilitiesTab'

export function VgsWorkspacePage() {
  const { versionId } = useParams<{ versionId: string }>()

  const { data: version } = useQuery({
    queryKey: ['versions', versionId],
    queryFn: () => api.versions.get(versionId!),
    enabled: !!versionId,
  })

  if (!versionId) return null

  return (
    <div>
      <Link to="/vgs" className="mb-2 inline-block text-sm text-purple-700 hover:underline">
        ← VGS
      </Link>
      <h1 className="mb-1 text-2xl font-semibold">DVAReporter</h1>
      {version && <p className="mb-6 text-sm text-gray-500">Building a report for: {version.name}</p>}

      <Tabs
        tabs={[
          { key: 'project', label: 'Project Info', content: <ReportProjectInfoTab versionId={versionId} /> },
          { key: 'picker', label: 'Vulnerability Picker', content: <ReportVulnerabilitiesTab versionId={versionId} /> },
          { key: 'manage', label: 'Manage Vulnerabilities', content: <ManageVulnerabilitiesTab /> },
          { key: 'evidence', label: 'Evidences', content: <ReportEvidenceTab versionId={versionId} /> },
          { key: 'generate', label: 'Generate Report', content: <ReportGenerateTab versionId={versionId} /> },
        ]}
      />
    </div>
  )
}
