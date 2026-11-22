import { Link } from 'react-router-dom'

function QuizResults({ score, totalQuestions, onPlayAgain }) {
  let accuracy = 0

  if (totalQuestions > 0) {
    accuracy = Math.round((score / totalQuestions) * 100)
  }

  const missed = totalQuestions - score

  return (
    <section className="game">
      <h1>Quiz Complete!</h1>

      <div>
        <p>Score: {score} / {totalQuestions}</p>
        <p>Accuracy: {accuracy}%</p>
        <p>Questions Missed: {missed}</p>
      </div>

      <button className="button" type="button" onClick={onPlayAgain}>
        Play Again
      </button>

      <Link className="button" to="/">Home</Link>
    </section>
  )
}

export default QuizResults