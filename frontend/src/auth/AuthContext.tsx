import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { api, clearToken, getToken, setToken } from '../api/client'
import type { UserOut } from '../api/types'

interface AuthContextValue {
  user: UserOut | null
  loading: boolean
  login: (email: string, password: string) => Promise<void>
  register: (orgName: string, email: string, password: string) => Promise<void>
  loginWithToken: (token: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserOut | null>(null)
  const [loading, setLoading] = useState(true)

  async function loadCurrentUser() {
    if (!getToken()) {
      setUser(null)
      setLoading(false)
      return
    }
    try {
      const me = await api.auth.me()
      setUser(me)
    } catch {
      clearToken()
      setUser(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadCurrentUser()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function login(email: string, password: string) {
    const { access_token } = await api.auth.login({ email, password })
    setToken(access_token)
    await loadCurrentUser()
  }

  async function register(orgName: string, email: string, password: string) {
    const { access_token } = await api.auth.register({ org_name: orgName, email, password })
    setToken(access_token)
    await loadCurrentUser()
  }

  // Used by OidcCallbackPage — the token was already issued by the
  // backend's OIDC callback redirect, so this just stores it and loads
  // the current user, without another POST /auth/login round-trip.
  async function loginWithToken(token: string) {
    setToken(token)
    await loadCurrentUser()
  }

  function logout() {
    clearToken()
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, register, loginWithToken, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}

// analyst/viewer can never create/delete engagement resources — the UI
// hides those controls rather than showing-then-403ing, mirroring the
// real matrix in app/auth/rbac.py (org_admin/project_lead: full CRUD;
// analyst: read + narrow creates; viewer: read-only).
export function canWrite(role: string | undefined): boolean {
  return role === 'org_admin' || role === 'project_lead'
}

// review_candidate and finding are the two resources analysts get
// "update" on (per the real matrix in app/auth/rbac.py) — promote/
// dismiss and mark-false-positive/risk-accepted/reopen should stay
// visible for them even though canWrite() above (org_admin/
// project_lead only) hides everything else. Finding delete is NOT
// covered by this — that stays canWrite()-gated, same as review.
export function canReview(role: string | undefined): boolean {
  return role !== 'viewer' && role !== undefined
}
