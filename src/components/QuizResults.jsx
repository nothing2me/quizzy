import { Link } from 'react-router-dom'

// Display the player's final results and provide options to replay or exit.
function QuizResults({ score, totalQuestions, onPlayAgain }) {
  let accuracy = 0

  // Calculate accuracy as a rounded percentage, avoiding division by zero.
  if (totalQuestions > 0) {
    accuracy = Math.round((score / totalQuestions) * 100)
  }

  // Determine how many questions were not answered correctly.
  const missed = totalQuestions - score

  return (
    <section className="game">
      <h1>Quiz Complete!</h1>

      <div>
        <p>Score: {score} / {totalQuestions}</p>
        <p>Accuracy: {accuracy}%</p>
        <p>Questions Missed: {missed}</p>
      </div>

      <button type="button" onClick={onPlayAgain}>
        Play Again
      </button>

      <Link to="/">Home</Link>
    </section>
  )
}

export default QuizResults