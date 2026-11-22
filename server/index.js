import express from 'express'
import session from 'express-session'
import connectPgSimple from 'connect-pg-simple'
import { pool } from './db.js'

const app = express()
const port = Number(process.env.PORT) || 3001
const PgSession = connectPgSimple(session)

function httpError(status, message) {
  const error = new Error(message)
  error.status = status
  return error
}

app.use(express.json({ limit: '32kb' }))

if (!process.env.SESSION_SECRET) {
  throw new Error('SESSION_SECRET is required.')
}

app.use(session({
  store: new PgSession({
    pool,
    createTableIfMissing: true,
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  },
}))

app.get('/api/health', async (_req, res, next) => {
  try {
    await pool.query('SELECT 1')
    res.json({ status: 'ok', database: 'connected' })
  } catch (error) {
    next(error)
  }
})

app.get('/api/question-sets', async (_req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT id, title FROM question_sets ORDER BY title',
    )
    res.json({ questionSets: result.rows })
  } catch (error) {
    next(error)
  }
})

app.get('/api/question-sets/:setId/questions', async (req, res, next) => {
  try {
    const setResult = await pool.query(
      'SELECT id, title FROM question_sets WHERE id = $1',
      [req.params.setId],
    )

    if (setResult.rowCount === 0) {
      return res.status(404).json({ error: 'Question set not found.' })
    }

    const questionResult = await pool.query(
      `SELECT
         q.id AS question_id,
         q.prompt,
         q.position AS question_position,
         c.id AS choice_id,
         c.text AS choice_text,
         c.position AS choice_position
       FROM questions q
       JOIN answer_choices c ON c.question_id = q.id
       WHERE q.question_set_id = $1
       ORDER BY q.position, c.position`,
      [req.params.setId],
    )

    const questionsById = new Map()

    for (const row of questionResult.rows) {
      if (!questionsById.has(row.question_id)) {
        questionsById.set(row.question_id, {
          id: row.question_id,
          prompt: row.prompt,
          choices: [],
        })
      }

      questionsById.get(row.question_id).choices.push({
        id: row.choice_id,
        text: row.choice_text,
      })
    }

    res.json({
      questionSet: setResult.rows[0],
      questions: [...questionsById.values()],
    })
  } catch (error) {
    next(error)
  }
})

app.post('/api/questions/:questionId/answers', async (req, res, next) => {
  try {
    const { choiceId } = req.body ?? {}

    if (typeof choiceId !== 'string' || choiceId.length === 0) {
      return res.status(400).json({
        error: 'choiceId must be a non-empty string.',
      })
    }

    const result = await pool.query(
      `SELECT is_correct
       FROM answer_choices
       WHERE question_id = $1 AND id = $2`,
      [req.params.questionId, choiceId],
    )

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Question or choice not found.' })
    }

    res.json({ isCorrect: result.rows[0].is_correct })
  } catch (error) {
    next(error)
  }
})

app.post('/api/attempts', async (req, res, next) => {
  const userId = req.session?.userId
  if (!userId) {
    return res.status(401).json({ error: 'Sign in to save a quiz attempt.' })
  }

  const { questionSetId, answers } = req.body ?? {}
  const validAnswers =
    Array.isArray(answers) &&
    answers.length > 0 &&
    answers.every(
      (answer) =>
        answer &&
        typeof answer.questionId === 'string' &&
        answer.questionId.length > 0 &&
        (answer.choiceId === null ||
          (typeof answer.choiceId === 'string' &&
            answer.choiceId.length > 0)),
    )

  if (
    typeof questionSetId !== 'string' ||
    questionSetId.length === 0 ||
    !validAnswers
  ) {
    return res.status(400).json({
      error:
        'questionSetId and an answers array with questionId and choiceId values are required.',
    })
  }

  const answersByQuestion = new Map()
  for (const answer of answers) {
    if (answersByQuestion.has(answer.questionId)) {
      return res.status(400).json({ error: 'Duplicate question answers are not allowed.' })
    }
    answersByQuestion.set(answer.questionId, answer.choiceId)
  }

  const client = await pool.connect()
  let transactionStarted = false

  try {
    await client.query('BEGIN')
    transactionStarted = true

    const setResult = await client.query(
      'SELECT id FROM question_sets WHERE id = $1',
      [questionSetId],
    )

    if (setResult.rowCount === 0) {
      throw httpError(404, 'Question set not found.')
    }

    const questionResult = await client.query(
      `SELECT
         q.id AS question_id,
         c.id AS choice_id,
         c.is_correct
       FROM questions q
       LEFT JOIN answer_choices c ON c.question_id = q.id
       WHERE q.question_set_id = $1
       ORDER BY q.position, c.position`,
      [questionSetId],
    )

    const questionsById = new Map()
    for (const row of questionResult.rows) {
      if (!questionsById.has(row.question_id)) {
        questionsById.set(row.question_id, {
          choices: new Set(),
          correctChoiceIds: [],
        })
      }

      if (row.choice_id) {
        const question = questionsById.get(row.question_id)
        question.choices.add(row.choice_id)
        if (row.is_correct) {
          question.correctChoiceIds.push(row.choice_id)
        }
      }
    }

    if (questionsById.size === 0) {
      throw httpError(422, 'This question set has no questions.')
    }

    if (
      answersByQuestion.size !== questionsById.size ||
      [...answersByQuestion.keys()].some(
        (questionId) => !questionsById.has(questionId),
      )
    ) {
      throw httpError(
        400,
        'Submit exactly one answer for every question in the set.',
      )
    }

    const reviewedAnswers = []
    for (const [questionId, choiceId] of answersByQuestion) {
      const question = questionsById.get(questionId)

      if (question.correctChoiceIds.length !== 1) {
        throw new Error(
          `Question ${questionId} must have exactly one correct choice.`,
        )
      }

      if (choiceId !== null && !question.choices.has(choiceId)) {
        throw httpError(
          400,
          `Choice ${choiceId} does not belong to question ${questionId}.`,
        )
      }

      const correctChoiceId = question.correctChoiceIds[0]
      reviewedAnswers.push({
        questionId,
        selectedChoiceId: choiceId,
        correctChoiceId,
        isCorrect: choiceId === correctChoiceId,
      })
    }

    const score = reviewedAnswers.filter((answer) => answer.isCorrect).length
    const attemptResult = await client.query(
      `INSERT INTO quiz_attempts
         (user_id, question_set_id, score, total_questions)
       VALUES ($1, $2, $3, $4)
       RETURNING id`,
      [userId, questionSetId, score, reviewedAnswers.length],
    )
    const attemptId = attemptResult.rows[0].id

    for (const answer of reviewedAnswers) {
      await client.query(
        `INSERT INTO attempt_answers
           (attempt_id, question_id, selected_choice_id, correct_choice_id)
         VALUES ($1, $2, $3, $4)`,
        [
          attemptId,
          answer.questionId,
          answer.selectedChoiceId,
          answer.correctChoiceId,
        ],
      )
    }

    await client.query('COMMIT')
    transactionStarted = false

    res.status(201).json({
      attemptId,
      score,
      totalQuestions: reviewedAnswers.length,
      accuracy: Math.round((score / reviewedAnswers.length) * 100),
      answers: reviewedAnswers,
    })
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query('ROLLBACK')
      } catch (rollbackError) {
        return next(rollbackError)
      }
    }
    return next(error)
  } finally {
    client.release()
  }
})

app.use((error, _req, res, _next) => {
  console.error(error)
  const status = Number.isInteger(error.status) ? error.status : 500
  const message = status < 500 ? error.message : 'Internal server error.'
  res.status(status).json({ error: message })
})

app.listen(port, () => {
  console.log(`Quizzy API listening on http://localhost:${port}`)
})