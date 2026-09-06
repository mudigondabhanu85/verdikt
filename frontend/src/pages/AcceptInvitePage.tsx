import { useState, type FormEvent } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { api, ApiError } from '../api/client'

export function AcceptInvitePage() {
  const { loginWithToken } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!token) return
    setError(null)
    setSubmitting(true)
    try {
      const { access_token } = await api.users.acceptInvite({ invite_token: token, password })
      await loginWithToken(access_token)
      navigate('/')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not accept this invite')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50">
      <form onSubmit={handleSubmit} className="w-full max-w-sm rounded-lg border border-gray-200 bg-white p-8 shadow-sm">
        <h1 className="mb-6 text-xl font-semibold text-purple-700">Accept your invite</h1>

        {!token && (
          <p className="mb-4 rounded bg-red-50 px-3 py-2 text-sm text-red-700">
            This link is missing its invite token — ask whoever invited you to resend it.
          </p>
        )}
        {error && <p className="mb-4 rounded bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}

        <label className="mb-6 block text-sm">
          <span className="mb-1 block text-gray-600">Choose a password</span>
          <input
            type="password"
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none"
          />
        </label>
        <button
          type="submit"
          disabled={submitting || !token}
          className="w-full rounded bg-purple-700 px-3 py-2 text-sm font-medium text-white hover:bg-purple-800 disabled:opacity-50"
        >
          {submitting ? 'Setting up your account…' : 'Set password & sign in'}
        </button>
      </form>
    </div>
  )
}
