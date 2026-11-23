import { Link } from 'react-router-dom'

// Display final quiz results and review missed questions from saved attempts.
function QuizResults({
  score,
  totalQuestions,
  onPlayAgain,
  attemptResult,
  saveError,
  questions,
}) {
  let accuracy = 0

  // Calculate accuracy as a rounded percentage, avoiding division by zero.
  if (totalQuestions > 0) {
    accuracy = Math.round((score / totalQuestions) * 100)
  }

  // Count questions that were answered incorrectly or left unanswered.
  const missed = totalQuestions - score

  // Use the server's answer review when a completed attempt was saved.
  let missedAnswers = []

  if (attemptResult && Array.isArray(attemptResult.answers)) {
    missedAnswers = attemptResult.answers.filter((answer) => !answer.isCorrect)
  }

  return (
    <section className="game">
      <h1>Quiz Complete!</h1>

      <div>
        <p>Score: {score} / {totalQuestions}</p>
        <p>Accuracy: {accuracy}%</p>
        <p>Questions Missed: {missed}</p>
      </div>

      {/* Display missed questions using the server's answer review. */}
      {missedAnswers.length > 0 && (
        <div>
          <h2>Missed Questions</h2>

          {missedAnswers.map((answer) => {
            const question = questions.find(
              (item) => item.id === answer.questionId,
            )

            if (!question) return null

            const selectedChoice = question.choices.find(
              (choice) => choice.id === answer.selectedChoiceId,
            )

            const correctChoice = question.choices.find(
              (choice) => choice.id === answer.correctChoiceId,
            )

            return (
              <div key={answer.questionId}>
                <p>{question.prompt}</p>
                <p>
                  Your answer: {selectedChoice ? selectedChoice.text : 'No answer'}
                </p>
                <p>
                  Correct answer: {correctChoice ? correctChoice.text : 'Unavailable'}
                </p>
              </div>
            )
          })}
        </div>
      )}

      {/* Explain when an attempt could not be saved. */}
      {saveError && (
        <p className="message" role="status">
          {saveError}
        </p>
      )}

      {saveError === 'Sign in to save your score.' && (
        <Link className="button" to="/login">
          Sign In
        </Link>
      )}

      <button className="button" type="button" onClick={onPlayAgain}>
        Play Again
      </button>

      <Link className="button" to="/">
        Home
      </Link>
    </section>
  )
}

export default QuizResults