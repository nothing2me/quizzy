import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import QuizResults from '../components/QuizResults'

// Time allowed for each question, in seconds.
const QUESTION_TIME = 20

function Play() {
  // Track quiz data, loading state, and request errors.
  const [questions, setQuestions] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  // Track the player's progress, score, and completed answers.
  const [questionIndex, setQuestionIndex] = useState(0)
  const [score, setScore] = useState(0)
  const [answers, setAnswers] = useState([])
  const [attemptResult, setAttemptResult] = useState(null)
  const [saveError, setSaveError] = useState('')
  const [isSaving, setIsSaving] = useState(false)
  const [timeLeft, setTimeLeft] = useState(QUESTION_TIME)

  // Track answer selection, submission status, and validation feedback.
  const [selectedChoiceId, setSelectedChoiceId] = useState(null)
  const [status, setStatus] = useState('playing')
  const [lastAnswerCorrect, setLastAnswerCorrect] = useState(null)
  const [answerError, setAnswerError] = useState('')

  // Retrieve the question set when the gameplay component mounts.
  useEffect(() => {
    // Allow pending requests to be canceled if the component unmounts.
    const controller = new AbortController()

    async function loadQuestions() {
      try {
        const response = await fetch(
          '/api/question-sets/corpus-cc/questions',
          { signal: controller.signal },
        )

        // Reject unsuccessful HTTP responses before processing the data.
        if (!response.ok) {
          throw new Error(`Request failed with status ${response.status}`)
        }

        const data = await response.json()

        // Verify the API response contains questions with four valid choices.
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
        // Ignore errors caused by intentionally canceling the request.
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

    // Cancel the request during cleanup to avoid stale state updates.
    return () => controller.abort()
  }, [])

  // Identify the current question using the player's progress index.
  const question = questions[questionIndex]

  // Count down once per second while a question is active.
  useEffect(() => {
    // Pause the timer during loading, errors, or answer submission.
    if (loading || error || !question || status !== 'playing') {
      return undefined
    }

    if (timeLeft === 0) {
      return undefined
    }

    const timerId = window.setTimeout(() => {
      // Prevent the countdown from dropping below zero.
      setTimeLeft((remaining) => Math.max(remaining - 1, 0))
    }, 1000)

    // Clear the previous timeout when dependencies change or on unmount.
    return () => window.clearTimeout(timerId)
  }, [loading, error, question, status, timeLeft])

  // Submit the player's selected answer for server-side validation.
  async function chooseAnswer(choiceId) {
    // Prevent submissions after answering or after time expires.
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

      // Require a Boolean result before updating the player's score.
      if (typeof result.isCorrect !== 'boolean') {
        throw new Error('The API returned an invalid answer result.')
      }

      setSelectedChoiceId(choiceId)
      setLastAnswerCorrect(result.isCorrect)

      // Record each answer for submission when the quiz is completed.
      setAnswers((currentAnswers) => [
        ...currentAnswers,
        { questionId: question.id, choiceId: choiceId },
      ])

      // Update the score after the backend confirms a correct answer.
      if (result.isCorrect) {
        setScore((currentScore) => currentScore + 1)
      }

      setStatus('answered')
    } catch (requestError) {
      // Display the submission error and allow another attempt.
      setAnswerError(
        requestError instanceof Error
          ? requestError.message
          : 'Could not submit your answer.',
      )
      setStatus('playing')
    }
  }

  // Advance the quiz and save the completed attempt after the final question.
  async function goToNextQuestion() {
    if (isSaving) return

    let completedAnswers = answers

    // Record unanswered questions with a null choice when time expires.
    if (timeLeft === 0 && status === 'playing') {
      completedAnswers = [
        ...answers,
        { questionId: question.id, choiceId: null },
      ]

      setAnswers(completedAnswers)
    }

    // Submit the complete attempt for server-side scoring and storage.
    if (questionIndex === questions.length - 1) {
      setIsSaving(true)
      setSaveError('')

      try {
        const response = await fetch('/api/attempts', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            questionSetId: 'corpus-cc',
            answers: completedAnswers,
          }),
        })

        if (response.status === 401) {
          setSaveError('Sign in to save your score.')
        } else if (!response.ok) {
          throw new Error(`Could not save results: ${response.status}`)
        } else {
          const result = await response.json()
          setAttemptResult(result)
        }
      } catch (requestError) {
        setSaveError(
          requestError instanceof Error
            ? requestError.message
            : 'Could not save your results.',
        )
      } finally {
        setIsSaving(false)
      }
    }

    // Reset question-specific state before continuing.
    setQuestionIndex((index) => index + 1)
    setSelectedChoiceId(null)
    setTimeLeft(QUESTION_TIME)
    setStatus('playing')
    setLastAnswerCorrect(null)
    setAnswerError('')
  }

  // Reset the quiz so the player can replay the loaded question set.
  function restartGame() {
    setQuestionIndex(0)
    setScore(0)
    setAnswers([])
    setAttemptResult(null)
    setSaveError('')
    setIsSaving(false)
    setSelectedChoiceId(null)
    setTimeLeft(QUESTION_TIME)
    setStatus('playing')
    setLastAnswerCorrect(null)
    setAnswerError('')
  }

  // Render the appropriate screen before displaying active gameplay.
  if (loading) {
    return <p className="message" role="status">Loading questions...</p>
  }

  if (error) {
    return (
      <section className="background">
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

  // Reaching the end of the question array completes the quiz.
  if (!question) {
    return (
      <QuizResults
        score={score}
        totalQuestions={questions.length}
        onPlayAgain={restartGame}
        attemptResult={attemptResult}
        saveError={saveError}
        questions={questions}
        answers={answers}
      />
    )
  }

  // Derive timeout status without storing redundant state.
  const displayStatus =
    status === 'playing' && timeLeft === 0 ? 'timedOut' : status

  // Allow progression only after an answer is checked or time expires.
  const canContinue =
    displayStatus === 'answered' || displayStatus === 'timedOut'

  return (
    <section className="game">
      <h1>Question {questionIndex + 1} of {questions.length}</h1>
      <p className="timer" role="timer">Time left: {timeLeft}s</p>
      <h2>{question.prompt}</h2>

      <div className="choices">
        {question.choices.map((choice) => {
          // Apply feedback styling only to the player's selected choice.
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

      {/* Provide accessible feedback for answer submission and results. */}
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
        <button
          className="button"
          type="button"
          onClick={goToNextQuestion}
          disabled={isSaving}
        >
          {isSaving
            ? 'Saving Results...'
            : questionIndex === questions.length - 1
              ? 'See Results'
              : 'Next'}
        </button>
      )}

      <p>Score: {score}</p>
    </section>
  )
}

export default Play