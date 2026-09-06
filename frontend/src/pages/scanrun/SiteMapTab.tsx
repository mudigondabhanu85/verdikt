import { useMemo, useState } from 'react'
import type { ScanRunDetail } from '../../api/types'

interface SiteMapEndpoint {
  url: string
  status: number | null
}

interface SiteMapForm {
  action_url: string
  method: string
  fields: string[]
}

interface SiteMapParameter {
  url: string
  name: string
}

interface SiteMapData {
  endpoints: SiteMapEndpoint[]
  forms: SiteMapForm[]
  parameters: SiteMapParameter[]
  websocket_endpoints: string[]
}

interface TechStackFingerprint {
  server_software?: string[]
  backend_languages?: string[]
  frontend_frameworks?: string[]
  cms?: string[]
}

interface TreeNode {
  segment: string
  fullPath: string
  children: Map<string, TreeNode>
  entries: SiteMapEndpoint[]
}

function makeNode(segment: string, fullPath: string): TreeNode {
  return { segment, fullPath, children: new Map(), entries: [] }
}

function buildTree(endpoints: SiteMapEndpoint[]): TreeNode {
  const root = makeNode('/', '/')
  for (const ep of endpoints) {
    let pathname: string
    try {
      pathname = new URL(ep.url).pathname
    } catch {
      pathname = ep.url
    }
    const segments = pathname.split('/').filter(Boolean)
    if (segments.length === 0) {
      root.entries.push(ep)
      continue
    }
    let node = root
    let acc = ''
    for (const seg of segments) {
      acc += `/${seg}`
      let child = node.children.get(seg)
      if (!child) {
        child = makeNode(seg, acc)
        node.children.set(seg, child)
      }
      node = child
    }
    node.entries.push(ep)
  }
  return root
}

function statusBadgeClass(status: number | null): string {
  if (status === null) return 'bg-gray-100 text-gray-500 border-gray-300'
  if (status >= 200 && status < 300) return 'bg-green-100 text-green-800 border-green-300'
  if (status >= 300 && status < 400) return 'bg-amber-100 text-amber-800 border-amber-300'
  return 'bg-red-100 text-red-700 border-red-300'
}

function StatusChip({ status }: { status: number | null }) {
  return (
    <span className={`inline-block rounded-full border px-2 py-0.5 text-xs font-mono ${statusBadgeClass(status)}`}>
      {status ?? '—'}
    </span>
  )
}

function countEndpoints(node: TreeNode): number {
  let count = node.entries.length
  for (const child of node.children.values()) count += countEndpoints(child)
  return count
}

function TreeBranch({ node, depth, defaultOpen }: { node: TreeNode; depth: number; defaultOpen: boolean }) {
  const childList = Array.from(node.children.values()).sort((a, b) => a.segment.localeCompare(b.segment))
  const total = countEndpoints(node)

  return (
    <details open={defaultOpen} className="ml-0">
      <summary
        className="cursor-pointer select-none rounded px-2 py-1 text-sm hover:bg-gray-50"
        style={{ marginLeft: depth * 12 }}
      >
        <span className="font-mono text-gray-700">/{node.segment}</span>
        <span className="ml-2 text-xs text-gray-400">({total})</span>
      </summary>
      <div>
        {node.entries.map((ep) => (
          <div
            key={ep.url}
            className="flex items-center gap-2 py-1 text-xs"
            style={{ marginLeft: (depth + 1) * 12 + 16 }}
          >
            <StatusChip status={ep.status} />
            <span className="break-all font-mono text-gray-600">{ep.url}</span>
          </div>
        ))}
        {childList.map((child) => (
          <TreeBranch key={child.fullPath} node={child} depth={depth + 1} defaultOpen={false} />
        ))}
      </div>
    </details>
  )
}

function SiteMapTree({ endpoints }: { endpoints: SiteMapEndpoint[] }) {
  const root = useMemo(() => buildTree(endpoints), [endpoints])
  const topLevel = Array.from(root.children.values()).sort((a, b) => a.segment.localeCompare(b.segment))
  const openAll = endpoints.length <= 10

  return (
    <div className="rounded border border-gray-200 bg-white p-2">
      {root.entries.map((ep) => (
        <div key={ep.url} className="flex items-center gap-2 py-1 text-xs">
          <StatusChip status={ep.status} />
          <span className="break-all font-mono text-gray-600">{ep.url}</span>
        </div>
      ))}
      {topLevel.map((child) => (
        <TreeBranch key={child.fullPath} node={child} depth={0} defaultOpen={openAll} />
      ))}
    </div>
  )
}

function FingerprintCard({ fingerprint }: { fingerprint: TechStackFingerprint }) {
  const rows: [string, string[] | undefined][] = [
    ['Server software', fingerprint.server_software],
    ['Backend languages', fingerprint.backend_languages],
    ['Frontend frameworks', fingerprint.frontend_frameworks],
    ['CMS', fingerprint.cms],
  ].filter(([, v]) => v && v.length > 0) as [string, string[]][]

  if (rows.length === 0) return null

  return (
    <div className="mb-6 rounded border border-gray-200 bg-white p-4">
      <h3 className="mb-2 text-sm font-medium text-gray-700">Detected tech stack</h3>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
        {rows.map(([label, values]) => (
          <div key={label}>
            <dt className="text-xs text-gray-400">{label}</dt>
            <dd className="text-gray-700">{values!.join(', ')}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

export function SiteMapTab({ scanRun }: { scanRun: ScanRunDetail }) {
  const reconJob = scanRun.agent_jobs.find((j) => j.agent_type === 'recon')
  const siteMap = reconJob?.stats?.site_map as SiteMapData | undefined
  const fingerprint = (scanRun.tech_stack_fingerprint ?? undefined) as TechStackFingerprint | undefined

  const [paramFilter, setParamFilter] = useState('')

  if (!siteMap || (siteMap.endpoints.length === 0 && siteMap.forms.length === 0)) {
    return (
      <div className="rounded border border-gray-200 bg-white p-6 text-sm text-gray-500">
        No coverage data recorded for this scan run — either recon hasn't completed yet, or this scan
        predates site-map recording.
      </div>
    )
  }

  const parametersByUrl = new Map<string, string[]>()
  for (const p of siteMap.parameters) {
    if (paramFilter && !p.url.includes(paramFilter) && !p.name.includes(paramFilter)) continue
    const list = parametersByUrl.get(p.url) ?? []
    list.push(p.name)
    parametersByUrl.set(p.url, list)
  }

  return (
    <div>
      {fingerprint && <FingerprintCard fingerprint={fingerprint} />}

      <div className="mb-6">
        <h3 className="mb-2 text-sm font-medium text-gray-700">
          Discovered endpoints <span className="text-xs text-gray-400">({siteMap.endpoints.length})</span>
        </h3>
        <SiteMapTree endpoints={siteMap.endpoints} />
      </div>

      {siteMap.forms.length > 0 && (
        <div className="mb-6">
          <h3 className="mb-2 text-sm font-medium text-gray-700">
            Discovered forms <span className="text-xs text-gray-400">({siteMap.forms.length})</span>
          </h3>
          <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
            {siteMap.forms.map((form, i) => (
              <li key={`${form.action_url}-${i}`} className="px-3 py-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className="rounded border border-gray-300 bg-gray-50 px-1.5 py-0.5 font-mono font-medium text-gray-600">
                    {form.method}
                  </span>
                  <span className="break-all font-mono text-gray-700">{form.action_url}</span>
                </div>
                {form.fields.length > 0 && (
                  <div className="mt-1 text-gray-400">fields: {form.fields.join(', ')}</div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {siteMap.parameters.length > 0 && (
        <div className="mb-6">
          <div className="mb-2 flex items-center justify-between">
            <h3 className="text-sm font-medium text-gray-700">
              Discovered parameters <span className="text-xs text-gray-400">({siteMap.parameters.length})</span>
            </h3>
            <input
              value={paramFilter}
              onChange={(e) => setParamFilter(e.target.value)}
              placeholder="filter by url or name…"
              className="rounded border border-gray-300 px-2 py-1 text-xs focus:border-purple-500 focus:outline-none"
            />
          </div>
          <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
            {Array.from(parametersByUrl.entries()).map(([url, names]) => (
              <li key={url} className="px-3 py-2 text-xs">
                <div className="break-all font-mono text-gray-700">{url}</div>
                <div className="mt-1 text-gray-400">params: {names.join(', ')}</div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {siteMap.websocket_endpoints.length > 0 && (
        <div className="mb-6">
          <h3 className="mb-2 text-sm font-medium text-gray-700">
            Discovered WebSocket endpoints{' '}
            <span className="text-xs text-gray-400">({siteMap.websocket_endpoints.length})</span>
          </h3>
          <ul className="rounded border border-gray-200 bg-white">
            {siteMap.websocket_endpoints.map((ws) => (
              <li key={ws} className="break-all px-3 py-2 font-mono text-xs text-gray-700">
                {ws}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
