import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'

export function OidcCallbackPage() {
  const { loginWithToken } = useAuth()
  const navigate = useNavigate()
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    // The backend's /auth/oidc/callback redirects here with the token
    // in a URL *fragment* (never sent to any server) rather than a
    // query string — see app/api/routes/oidc.py's oidc_callback for
    // why. window.location.hash is the only place this ever shows up.
    const params = new URLSearchParams(window.location.hash.replace(/^#/, ''))
    const token = params.get('access_token')

    if (!token) {
      setError('No token received from the identity provider.')
      return
    }

    loginWithToken(token)
      .then(() => {
        // Replace, not push -- the fragment (containing the token)
        // should never end up back in browser history.
        window.history.replaceState(null, '', '/')
        navigate('/', { replace: true })
      })
      .catch(() => setError('Failed to complete sign-in.'))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50">
      {error ? (
        <p className="rounded bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>
      ) : (
        <p className="text-gray-500">Signing you in…</p>
      )}
    </div>
  )
}
