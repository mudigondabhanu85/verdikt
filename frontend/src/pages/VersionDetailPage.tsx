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
      <h1 className="mb-6 text-2xl font-semibold">{version?.name ?? 'Version'}</h1>

      <Tabs
        tabs={[
          { key: 'scan-runs', label: 'Scan Runs', content: <ScanRunsTab versionId={versionId} isAuthorized={!!version?.is_authorized} /> },
          { key: 'scope', label: 'Scope', content: <ScopeTab versionId={versionId} /> },
          { key: 'targets', label: 'Targets', content: <TargetsTab versionId={versionId} /> },
          { key: 'credentials', label: 'Credentials', content: <CredentialsTab versionId={versionId} /> },
          { key: 'authorization', label: 'Authorization', content: <AuthorizationTab versionId={versionId} /> },
          { key: 'business-rules', label: 'Business Rules', content: <BusinessRulesTab versionId={versionId} /> },
        ]}
      />
    </div>
  )
}
