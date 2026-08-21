import { Link, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'

export function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  function handleLogout() {
    logout()
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-gray-50 text-gray-900">
      <header className="border-b border-gray-200 bg-white">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
          <Link to="/" className="text-lg font-semibold text-purple-700">
            Verdikt
          </Link>
          <nav className="flex items-center gap-6 text-sm">
            <Link to="/dashboard" className="text-gray-600 hover:text-gray-900">
              Dashboard
            </Link>
            <Link to="/" className="text-gray-600 hover:text-gray-900">
              Projects
            </Link>
            <Link to="/account" className="text-gray-600 hover:text-gray-900">
              Account
            </Link>
            {user && (
              <span className="flex items-center gap-3">
                <span className="text-gray-500">
                  {user.email} <span className="text-xs uppercase text-gray-400">({user.role})</span>
                </span>
                <button
                  onClick={handleLogout}
                  className="rounded border border-gray-300 px-2 py-1 text-xs text-gray-600 hover:bg-gray-100"
                >
                  Log out
                </button>
              </span>
            )}
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  )
}
