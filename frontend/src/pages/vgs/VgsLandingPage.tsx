import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '../../api/client'
import type { ProjectOut } from '../../api/types'

function ProjectRow({ project }: { project: ProjectOut }) {
  const [expanded, setExpanded] = useState(false)

  const { data: versions } = useQuery({
    queryKey: ['versions', project.id],
    queryFn: () => api.versions.list(project.id),
    enabled: expanded,
  })

  return (
    <li className="rounded border border-gray-200 bg-white shadow-sm">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between px-4 py-3 text-left"
      >
        <span className="font-medium text-gray-800">{project.name}</span>
        <span className="text-xs text-gray-400">{expanded ? '▲' : '▼'}</span>
      </button>
      {expanded && (
        <ul className="border-t border-gray-100 px-4 py-2">
          {(versions ?? []).map((v) => (
            <li key={v.id} className="flex items-center justify-between py-1.5">
              <span className="text-sm text-gray-600">{v.name}</span>
              <Link
                to={`/vgs/${v.id}`}
                className="rounded bg-purple-700 px-3 py-1 text-xs font-medium text-white hover:bg-purple-800"
              >
                Build report
              </Link>
            </li>
          ))}
          {versions && versions.length === 0 && <p className="py-1.5 text-sm text-gray-400">No versions yet.</p>}
        </ul>
      )}
    </li>
  )
}

export function VgsLandingPage() {
  const { data: projects, isLoading } = useQuery({
    queryKey: ['projects', false],
    queryFn: () => api.projects.list(false),
  })

  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="mb-1 text-2xl font-semibold">DVAReporter</h1>
      <p className="mb-6 text-sm text-gray-500">
        Build a vulnerability assessment report: pick a project and version, select vulnerabilities from the
        shared library or add custom ones, attach evidence, and generate a DOCX.
      </p>

      {isLoading && <p className="text-sm text-gray-400">Loading…</p>}

      <ul className="space-y-2">
        {(projects ?? []).map((project) => (
          <ProjectRow key={project.id} project={project} />
        ))}
        {projects && projects.length === 0 && <p className="text-sm text-gray-400">No projects yet.</p>}
      </ul>
    </div>
  )
}
