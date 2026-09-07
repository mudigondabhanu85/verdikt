import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { Tabs } from '../components/Tabs'
import { ScopeTab } from './version/ScopeTab'
import { TargetsTab } from './version/TargetsTab'
import { CredentialsTab } from './version/CredentialsTab'
import { AuthorizationTab } from './version/AuthorizationTab'
import { BusinessRulesTab } from './version/BusinessRulesTab'
import { ScanRunsTab } from './version/ScanRunsTab'
import { TrafficTab } from './version/TrafficTab'
import { BurpTab } from './version/BurpTab'

export function VersionDetailPage() {
  const { versionId } = useParams<{ versionId: string }>()

  const { data: version } = useQuery({
    queryKey: ['versions', versionId],
    queryFn: () => api.versions.get(versionId!),
    enabled: !!versionId,
  })

  if (!versionId) return null

  return (
    <div>
      {version && (
        <Link to={`/projects/${version.project_id}`} className="mb-2 inline-block text-sm text-purple-700 hover:underline">
          ← Project
        </Link>
      )}
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">{version?.name ?? 'Version'}</h1>
        <Link
          to={`/vgs/${versionId}`}
          className="rounded bg-purple-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-purple-800"
        >
          Build VGS report →
        </Link>
      </div>

      <Tabs
        tabs={[
          { key: 'scan-runs', label: 'Scan Runs', content: <ScanRunsTab versionId={versionId} /> },
          { key: 'scope', label: 'Scope', content: <ScopeTab versionId={versionId} /> },
          { key: 'targets', label: 'Targets', content: <TargetsTab versionId={versionId} /> },
          { key: 'credentials', label: 'Credentials', content: <CredentialsTab versionId={versionId} /> },
          { key: 'authorization', label: 'Authorization', content: <AuthorizationTab versionId={versionId} /> },
          { key: 'business-rules', label: 'Business Rules', content: <BusinessRulesTab versionId={versionId} /> },
          { key: 'traffic', label: 'Traffic', content: <TrafficTab versionId={versionId} /> },
          { key: 'burp', label: 'Burp', content: <BurpTab versionId={versionId} isAuthorized={!!version?.is_authorized} /> },
        ]}
      />
    </div>
  )
}
