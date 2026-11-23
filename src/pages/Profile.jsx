import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import '../styling/Profile.css'

// Display account information, quiz statistics, and recent attempts.
function Profile() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState(null)
  const [error, setError] = useState('')

  // Retrieve the current user and their saved quiz statistics.
  useEffect(() => {
    let active = true

    async function fetchUser() {
      try {
        const response = await fetch('/api/auth/me', {
          credentials: 'include',
        })

        if (!response.ok) {
          throw new Error('Failed to fetch user')
        }

        const data = await response.json()

        if (!active) return

        setUser(data.user ?? null)

        if (!data.user) return

        const statsResponse = await fetch('/api/me/stats', {
          credentials: 'include',
        })

        if (!statsResponse.ok) {
          throw new Error('Failed to fetch quiz statistics')
        }

        const statsData = await statsResponse.json()

        if (active) {
          setStats(statsData)
        }
      } catch (requestError) {
        if (active) {
          console.error(requestError)
          setError(
            requestError instanceof Error
              ? requestError.message
              : 'Could not load your profile.',
          )
        }
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    fetchUser()

    return () => {
      active = false
    }
  }, [])

  // Display request status before rendering account information.
  if (loading) {
    return <p className="message" role="status">Loading profile...</p>
  }

  if (!user) {
    return (
      <section className="profile-panel profile-guest">
        <h1>Player Profile</h1>
        <p>You are not logged in.</p>

        <div className="profile-actions">
          <Link to="/login" className="button">Log In</Link>
          <Link to="/signup" className="link-button">Sign Up</Link>
        </div>

        {error && (
          <p className="message error" role="alert">{error}</p>
        )}
      </section>
    )
  }

  return (
    <div className="profile">
      {/* Player information. */}
      <section className="profile-panel profile-intro">
        <h1>Welcome, {user.displayName}</h1>
        <p>Email: {user.email}</p>
      </section>

      {/* Display statistics errors without hiding the player profile. */}
      {error && (
        <p className="message error" role="alert">{error}</p>
      )}

      {stats && (
        <>
          {/* Summarize the player's quiz performance. */}
          <section className="profile-panel">
            <h2>Quiz Statistics</h2>

            <div className="profile-stats">
              <div className="profile-stat">
                <span className="profile-stat-label">Quizzes Taken</span>
                <strong>{stats.attempts}</strong>
              </div>

              <div className="profile-stat">
                <span className="profile-stat-label">Correct Answers</span>
                <strong>{stats.correctAnswers}</strong>
              </div>

              <div className="profile-stat">
                <span className="profile-stat-label">Total Questions</span>
                <strong>{stats.totalQuestions}</strong>
              </div>

              <div className="profile-stat">
                <span className="profile-stat-label">Accuracy</span>
                <strong>{stats.accuracyPercent}%</strong>
              </div>
            </div>
          </section>

          {/* Show recent quiz attempts saved in the database. */}
          <section className="profile-panel">
            <h2>Recent Quiz Attempts</h2>

            {stats.recentAttempts.length === 0 ? (
              <p>You haven't attempted any quizzes yet.</p>
            ) : (
              <div className="profile-attempts">
                {stats.recentAttempts.map((attempt) => (
                  <article
                    className="profile-attempt"
                    key={attempt.attemptId}
                  >
                    <h3>{attempt.questionSetTitle}</h3>

                    <div className="profile-attempt-details">
                      <span>
                        Score: <strong>{attempt.score} / {attempt.totalQuestions}</strong>
                      </span>

                      <span>
                        Accuracy: <strong>{attempt.accuracyPercent}%</strong>
                      </span>

                      <span>
                        Completed: {new Date(attempt.completedAt).toLocaleString()}
                      </span>
                    </div>
                  </article>
                ))}
              </div>
            )}
          </section>
        </>
      )}
    </div>
  )
}

export default Profile