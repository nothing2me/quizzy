import { useEffect, useState } from 'react'
import '../styling/Leaderboard.css'

// Display player rankings for the selected question set.
function Leaderboard({ setId }) {
  const [entries, setEntries] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  // Retrieve the highest-ranked quiz attempts from the API.
  useEffect(() => {
    let active = true

    async function fetchLeaderboard() {
      setLoading(true)
      setError('')

      try {
        const response = await fetch(
          `/api/leaderboard?setId=${encodeURIComponent(setId)}&limit=10`,
        )

        if (!response.ok) {
          throw new Error('Failed to load leaderboard.')
        }

        const data = await response.json()

        if (active) {
          setEntries(data.entries)
        }
      } catch (requestError) {
        if (active) {
          setError(
            requestError instanceof Error
              ? requestError.message
              : 'Could not load leaderboard.',
          )
        }
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    if (setId) {
      fetchLeaderboard()
    } else {
      setLoading(false)
    }

    return () => {
      active = false
    }
  }, [setId])

  return (
    <section className="leaderboard">
      <h1>Leaderboard</h1>
      <p className="leaderboard-description">
        See how players rank based on their quiz scores.
      </p>

      {loading ? (
        <p className="message" role="status">
          Loading leaderboard...
        </p>
      ) : error ? (
        <p className="message error" role="alert">
          {error}
        </p>
      ) : entries.length === 0 ? (
        <p className="leaderboard-empty">
          No leaderboard entries yet.
        </p>
      ) : (
        <div className="leaderboard-scroll">
          <div className="leaderboard-table">
            <div className="leaderboard-header">
              <span>Rank</span>
              <span>Player</span>
              <span>Score</span>
              <span>Accuracy</span>
            </div>

            {entries.map((player) => (
              <div
                className={`leaderboard-row${player.rank === 1 ? ' leaderboard-first' : ''}`}
                key={player.rank}
              >
                <span className="leaderboard-rank">
                  #{player.rank}
                </span>

                <span className="leaderboard-player">
                  {player.displayName}
                </span>

                <span>
                  {player.score} / {player.totalQuestions}
                </span>

                <span>
                  {player.accuracyPercent}%
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  )
}

export default Leaderboard