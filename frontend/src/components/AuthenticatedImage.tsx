import { useEffect, useState } from 'react'
import { fetchObjectBlobUrl } from '../api/client'

// Wraps an /objects/{key} evidence screenshot: the route requires a
// bearer token, which a plain <img src> can never send, so we fetch the
// bytes ourselves (see fetchObjectBlobUrl) and swap in a blob: URL.
export function AuthenticatedImage({
  objectKey,
  alt,
  className,
}: {
  objectKey: string
  alt: string
  className?: string
}) {
  const [url, setUrl] = useState<string | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let objectUrl: string | null = null
    let cancelled = false
    setFailed(false)
    setUrl(null)
    fetchObjectBlobUrl(objectKey).then((result) => {
      if (cancelled) return
      if (result === null) {
        setFailed(true)
        return
      }
      objectUrl = result
      setUrl(result)
    })
    return () => {
      cancelled = true
      if (objectUrl) URL.revokeObjectURL(objectUrl)
    }
  }, [objectKey])

  if (failed) {
    return <div className={`flex items-center justify-center bg-gray-100 text-xs text-gray-400 ${className ?? ''}`}>Screenshot unavailable</div>
  }
  if (!url) {
    return <div className={`flex items-center justify-center bg-gray-100 text-xs text-gray-400 ${className ?? ''}`}>Loading…</div>
  }
  return <img src={url} alt={alt} className={className} />
}
