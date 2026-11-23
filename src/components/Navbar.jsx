import { useState } from 'react'
import { NavLink } from 'react-router-dom'

// Provide persistent navigation and authentication controls.
function Navbar({ user, authLoading, onLogout }) {
  const [loggingOut, setLoggingOut] = useState(false)
  const [logoutError, setLogoutError] = useState('')

  // End the current session through the application's logout handler.
  async function handleLogout() {
    if (loggingOut) return

    setLoggingOut(true)
    setLogoutError('')

    try {
      await onLogout()
    } catch (error) {
      setLogoutError(
        error instanceof Error
          ? error.message
          : 'Could not sign out. Please try again.',
      )
    } finally {
      setLoggingOut(false)
    }
  }

  return (
    <header>
      {/* Link the application brand to the homepage. */}
      <NavLink className="brand" to="/" end>
        Quizzy
      </NavLink>

      {/* Keep primary navigation available regardless of authentication. */}
      <nav aria-label="Main navigation">
        <NavLink to="/" end>
          Home
        </NavLink>
        <NavLink to="/about">About</NavLink>

        {/* Preserve the team's Profile and Leaderboard navigation. */}
        <NavLink to="/profile">Profile</NavLink>
        <NavLink to="/leaderboard">Leaderboard</NavLink>

        {/* Display account controls after the initial session check. */}
        {!authLoading && (
          user ? (
            <>
              <span>{user.displayName}</span>

              <button
                type="button"
                onClick={handleLogout}
                disabled={loggingOut}
              >
                {loggingOut ? 'Signing Out...' : 'Logout'}
              </button>
            </>
          ) : (
            <>
              <NavLink to="/login">Login</NavLink>
              <NavLink to="/signup">Sign Up</NavLink>
            </>
          )
        )}
      </nav>

      {/* Report logout failures without hiding the signed-in user. */}
      {logoutError && (
        <p className="message error" role="alert">
          {logoutError}
        </p>
      )}
    </header>
  )
}

export default Navbar