import { useEffect, useState } from 'react'
import { Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import Navbar from './components/Navbar.jsx'
import About from './pages/About.jsx'
import Home from './pages/Home.jsx'
import Login from './pages/Login.jsx'
import Play from './pages/Play.jsx'
import Signup from './pages/Signup.jsx'
import NotFound from './pages/NotFound.jsx'
import './App.css'

// Define the shared application layout, routes, and authentication state.
function App() {
  const navigate = useNavigate()

  // Store the authenticated user and track the initial session check.
  const [user, setUser] = useState(null)
  const [authLoading, setAuthLoading] = useState(true)
  const [authError, setAuthError] = useState('')

  // Restore the authenticated session when the application loads.
  useEffect(() => {
    const controller = new AbortController()

    async function checkSession() {
      try {
        const response = await fetch('/api/auth/me', {
          signal: controller.signal,
        })

        if (!response.ok) {
          throw new Error(`Session check failed: ${response.status}`)
        }

        const data = await response.json()

        if (!controller.signal.aborted) {
          setUser(data.user ?? null)
          setAuthError('')
        }
      } catch (error) {
        if (!controller.signal.aborted) {
          setAuthError('Could not verify your session.')
          console.error('Could not check the current session:', error)
        }
      } finally {
        if (!controller.signal.aborted) {
          setAuthLoading(false)
        }
      }
    }

    checkSession()

    // Cancel the pending request if the component unmounts.
    return () => controller.abort()
  }, [])

  // Update shared authentication state after successful login or signup.
  function handleAuthSuccess(authenticatedUser) {
    setUser(authenticatedUser)
    setAuthError('')
    navigate('/')
  }

  // End the session on the server before updating the interface.
  async function handleLogout() {
    const response = await fetch('/api/auth/logout', {
      method: 'POST',
    })

    if (!response.ok) {
      throw new Error(`Logout failed: ${response.status}`)
    }

    setUser(null)
    setAuthError('')
    navigate('/')
  }

  // Keep protected content hidden until the session check finishes.
  function requireAuth(element) {
    if (authLoading || authError) {
      return <p role="status">{authError || 'Checking session...'}</p>
    }

    return user ? element : <Navigate to="/login" replace />
  }

  return (
    <>
      {/* Keep navigation visible while the active page changes. */}
      <Navbar
        user={user}
        authLoading={authLoading}
        onLogout={handleLogout}
      />

      <main className="page">
        {/* Display authentication errors without assuming the user signed out. */}
        {authError && (
          <p className="message error" role="alert">
            {authError}
          </p>
        )}

        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/play" element={<Play />} />
          <Route path="/about" element={<About />} />

          <Route
            path="/signup"
            element={
              user ? (
                <Navigate to="/" replace />
              ) : (
                <Signup onAuthSuccess={handleAuthSuccess} />
              )
            }
          />

          <Route
            path="/login"
            element={
              user ? (
                <Navigate to="/" replace />
              ) : (
                <Login onAuthSuccess={handleAuthSuccess} />
              )
            }
          />

          {/* Apply requireAuth(...) when adding account-specific routes. */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
    </>
  )
}

export default App