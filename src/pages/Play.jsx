import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import QuizResults from '../components/QuizResults'

const QUESTION_TIME = 20

function Play() {
  const [questions, setQuestions] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [questionIndex, setQuestionIndex] = useState(0)
  const [score, setScore] = useState(0)
  const [timeLeft, setTimeLeft] = useState(QUESTION_TIME)
  const [selectedChoiceId, setSelectedChoiceId] = useState(null)
  const [status, setStatus] = useState('playing')
  const [lastAnswerCorrect, setLastAnswerCorrect] = useState(null)
  const [answerError, setAnswerError] = useState('')

  useEffect(() => {
    const controller = new AbortController()

    async function loadQuestions() {
      try {
        const response = await fetch(
          '/api/question-sets/corpus-cc/questions',
          { signal: controller.signal },
        )

        if (!response.ok) {
          throw new Error(`Request failed with status ${response.status}`)
        }

        const data = await response.json()

        const validQuestions =
          data &&
          Array.isArray(data.questions) &&
          data.questions.every((question) =>
            question &&
            typeof question.id === 'string' &&
            typeof question.prompt === 'string' &&
            Array.isArray(question.choices) &&
            question.choices.length === 4 &&
            question.choices.every(
              (choice) =>
                typeof choice.id === 'string' &&
                typeof choice.text === 'string',
            ),
          )

        if (!validQuestions) {
          throw new Error('Questions data is missing.')
        }

        setQuestions(data.questions)
      } catch (requestError) {
        if (!controller.signal.aborted) {
          setError(
            requestError instanceof Error
              ? requestError.message
              : 'An unexpected error occurred.',
          )
        }
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false)
        }
      }
    }

    loadQuestions()
    return () => controller.abort()
  }, [])

  const question = questions[questionIndex]

  useEffect(() => {
    if (loading || error || !question || status !== 'playing') {
      return undefined
    }

    if (timeLeft === 0) {
      return undefined
    }

    const timerId = window.setTimeout(() => {
      setTimeLeft((remaining) => Math.max(remaining - 1, 0))
    }, 1000)

    return () => window.clearTimeout(timerId)
  }, [loading, error, question, status, timeLeft])

  async function chooseAnswer(choiceId) {
    if (status !== 'playing' || timeLeft === 0) return

    setStatus('submitting')
    setAnswerError('')

    try {
      const response = await fetch(
        `/api/questions/${encodeURIComponent(question.id)}/answers`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ choiceId }),
        },
      )

      if (!response.ok) {
        throw new Error(`Answer request failed with status ${response.status}`)
      }

      const result = await response.json()

      if (typeof result.isCorrect !== 'boolean') {
        throw new Error('The API returned an invalid answer result.')
      }

      setSelectedChoiceId(choiceId)
      setLastAnswerCorrect(result.isCorrect)

      if (result.isCorrect) {
        setScore((currentScore) => currentScore + 1)
      }

      setStatus('answered')
    } catch (requestError) {
      setAnswerError(
        requestError instanceof Error
          ? requestError.message
          : 'Could not submit your answer.',
      )
      setStatus('playing')
    }
  }

  function goToNextQuestion() {
    setQuestionIndex((index) => index + 1)
    setSelectedChoiceId(null)
    setTimeLeft(QUESTION_TIME)
    setStatus('playing')
    setLastAnswerCorrect(null)
    setAnswerError('')
  }

  function restartGame() {
    setQuestionIndex(0)
    setScore(0)
    setSelectedChoiceId(null)
    setTimeLeft(QUESTION_TIME)
    setStatus('playing')
    setLastAnswerCorrect(null)
    setAnswerError('')
  }

  if (loading) {
    return <p className="message" role="status">Loading questions...</p>
  }

  if (error) {
    return (
      <section>
        <p className="message error" role="alert">
          Could not load questions: {error}
        </p>
        <Link to="/">Back Home</Link>
      </section>
    )
  }

  if (questions.length === 0) {
    return <p>No questions are available yet.</p>
  }
  
  if (!question) {
    return (
      <QuizResults
        score={score}
        totalQuestions={questions.length}
        onPlayAgain={restartGame}
      />
    )
  }

  const displayStatus =
    status === 'playing' && timeLeft === 0 ? 'timedOut' : status
  const canContinue =
    displayStatus === 'answered' || displayStatus === 'timedOut'

  return (
    <section className="game">
      <h1>Question {questionIndex + 1} of {questions.length}</h1>
      <p className="timer" role="timer">Time left: {timeLeft}s</p>
      <h2>{question.prompt}</h2>

      <div className="choices">
        {question.choices.map((choice) => {
          const isSelected = choice.id === selectedChoiceId
          const classNames = [
            'choice',
            isSelected && lastAnswerCorrect ? 'correct' : '',
            isSelected && lastAnswerCorrect === false ? 'incorrect' : '',
          ].filter(Boolean).join(' ')

          return (
            <button
              className={classNames}
              type="button"
              key={choice.id}
              onClick={() => chooseAnswer(choice.id)}
              disabled={displayStatus !== 'playing'}
            >
              {choice.text}
            </button>
          )
        })}
      </div>

      {displayStatus === 'submitting' && (
        <p role="status">Checking answer...</p>
      )}

      {answerError && (
        <p className="message error" role="alert">{answerError}</p>
      )}

      {displayStatus === 'answered' && (
        <p role="status">
          {lastAnswerCorrect ? 'Correct!' : 'Not quite.'}
        </p>
      )}

      {displayStatus === 'timedOut' && <p role="status">Time is up!</p>}

      {canContinue && (
        <button type="button" onClick={goToNextQuestion}>
          {questionIndex === questions.length - 1 ? 'See Results' : 'Next'}
        </button>
      )}

      <p>Score: {score}</p>
    </section>
  )
}

export default Play