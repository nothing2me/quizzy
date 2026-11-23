import { Link } from 'react-router-dom'

function QuizResults({ score, totalQuestions, onPlayAgain, attemptResult, saveError, questions }) {
  let accuracy = 0

  if (totalQuestions > 0) {
    accuracy = Math.round((score / totalQuestions) * 100)
  }

  const missed = totalQuestions - score
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

      {missedAnswers.length > 0 && (
        <div>
          <h2>Missed Questions</h2>
          {missedAnswers.map((answer) => {
            const question = questions.find((item) => item.id === answer.questionId)

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
                <p>Your answer: {selectedChoice ? selectedChoice.text : 'No answer'}</p>
                <p>Correct answer: {correctChoice ? correctChoice.text : 'Unavailable'}</p>
              </div>
            )
          })}
        </div>
      )}

      {saveError && (
        <p className="message" role="status">{saveError}</p>
      )}

      {saveError === 'Sign in to save your score.' && (
        <Link className="button" to="/login">Sign In</Link>
      )}

      <button className="button" type="button" onClick={onPlayAgain}>
        Play Again
      </button>

      <Link className="button" to="/">Home</Link>
    </section>
  )
}

export default QuizResults