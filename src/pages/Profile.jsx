import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import "../styling/Profile.css"

function Profile() {
    const [user, setUser] = useState(null)
    const [loading, setLoading] = useState(true)
    const [stats, setStats] = useState(null)
    const [error,setError] = useState('')

     useEffect(() => {
    async function fetchUser() {
      try {
        const response = await fetch('/api/auth/me', {
          credentials: 'include',
        })

        if (!response.ok) {
          throw new Error('Failed to fetch user')
        }

        const data = await response.json()

        setUser(data.user)

        if (!data.user) return

        const statsResponse = await fetch('/api/me/stats', {
          credentials: 'include',
        })

        if (!statsResponse.ok) {
          throw new Error('Failed to fetch quiz statistics')
        }

        const statsData = await statsResponse.json()

        setStats(statsData)

      } catch (error) {
        console.error(error)
        setError(error.message)
      } finally {
        setLoading(false)
      }
    }

    fetchUser()
  }, [])



    if (loading) return <p style={{color:'white'}}>Loading Profile...</p>

    if (!user) return (
    <div> 
        <p>You are not logged in.</p>
        <Link to="/signup" className="link-button">Sign Up</Link>
         <Link to="/login" className="link-button">Log In</Link>
    </div>
    )
    return (
        //<> can be used instead of <div>. it groups the child elements together since return can only take a single html input
        <>
            <div className="container">
              <h1>Welcome, {user.displayName}</h1>
              <p>Email: {user.email}</p>
            </div>
       {error && (
        <p style={{ color: 'red' }}>{error}</p>
      )}

      {stats && (
        <>
          
          <div className="container">
            <h2 className="title">Quiz Statistics</h2>

            <div className="grid">
              <div>
                <p>Quizzes Taken</p>
                <p className="stat">{stats.attempts}</p>
              </div>

              <div>
                <p>Correct Answers</p>
                <p className="stat">{stats.correctAnswers}</p>
              </div>

              <div>
                <p>Total Questions</p>
                <p className="stat">{stats.totalQuestions}</p>
              </div>

              <div>
                <p>Accuracy</p>
                <p className="stat">
                  {stats.accuracyPercent}%
                </p>
              </div>
            </div>
          </div>

          
          <div className="container">
            <h2 className="title">Recent Quiz Attempts</h2>

            {stats.recentAttempts.length == 0 ? (
              <p>You haven't attempted any quizzes yet.</p>
            ) : (
              stats.recentAttempts.map((attempt) => (
                <div key={attempt.attemptId}  className="attempt">
                  <h3>{attempt.questionSetTitle}</h3>

                  <p>
                    Score: {attempt.score} / {attempt.totalQuestions}
                  </p>

                  <p>
                    Accuracy: {attempt.accuracyPercent}%
                  </p>

                  <p>
                    Completed: {
                      new Date(attempt.completedAt).toLocaleString()
                    }
                  </p>
                </div>
              ))
            )}
          </div>
        </>
      )}
    </>
  )
}

export default Profile
