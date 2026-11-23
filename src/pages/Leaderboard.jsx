
import { useEffect, useState } from 'react';
import "../styling/Leaderboard.css"
function Leaderboard({ setId }) {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    async function fetchLeaderboard() {
      try {
        setLoading(true);
        setError('');

        const response = await fetch(
          `/api/leaderboard?setId=${encodeURIComponent(setId)}&limit=10`
        );

        if (!response.ok) {
          throw new Error('Failed to load leaderboard.');
        }

        const data = await response.json();

        setEntries(data.entries);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    if (setId) {
      fetchLeaderboard();
    }
  }, [setId]);

  if (loading) {
    return <p style={{color:'white'}}>Loading leaderboard...</p>;
  }

  if (error) {
    return <p>{error}</p>;
  }

  if (entries.length === 0) {
    return <p>No leaderboard entries yet.</p>;
  }

  return (
    <div className="leaderboard">
      <h2>Leaderboard</h2>

      <div className="leaderboard-header">
        <span>Rank</span>
        <span>Player</span>
        <span>Score</span>
        <span>Accuracy</span>
      </div>

      {entries.map((player) => (
        <div className="leaderboard-row" key={player.rank}>
          <span>#{player.rank}</span>

          <span>{player.displayName}</span>

          <span>
            {player.score}/{player.totalQuestions}
          </span>

          <span>{player.accuracyPercent}%</span>
        </div>
      ))}
    </div>
  );
}

export default Leaderboard;