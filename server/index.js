import express from 'express'
import session from 'express-session'
import connectPgSimple from 'connect-pg-simple'
import bcrypt from 'bcryptjs'
import { pool } from './db.js'

const app = express()
const port = Number(process.env.PORT) || 3001
const PgSession = connectPgSimple(session)

function httpError(status, message) {
  const error = new Error(message)
  error.status = status
  return error
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) {
        reject(error)
      } else {
        resolve()
      }
    })
  })
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((error) => {
      if (error) {
        reject(error)
      } else {
        resolve()
      }
    })
  })
}

function destroySession(req) {
  return new Promise((resolve, reject) => {
    req.session.destroy((error) => {
      if (error) {
        reject(error)
      } else {
        resolve()
      }
    })
  })
}

function clearSessionCookie(res) {
  res.clearCookie('connect.sid', {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  })
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    displayName: user.display_name,
  }
}

// Parse incoming JSON request bodies with a 32 KB size limit.
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

app.get('/api/auth/me', async (req, res, next) => {
  if (!req.session.userId) {
    return res.json({ user: null })
  }

  try {
    const result = await pool.query(
      'SELECT id, email, display_name FROM users WHERE id = $1',
      [req.session.userId],
    )

    if (result.rowCount === 0) {
      await destroySession(req)
      clearSessionCookie(res)
      return res.json({ user: null })
    }

    res.json({ user: publicUser(result.rows[0]) })
  } catch (error) {
    next(error)
  }
})

app.post('/api/auth/register', async (req, res, next) => {
  const { email: submittedEmail, displayName: submittedDisplayName, password } =
    req.body ?? {}
  const email =
    typeof submittedEmail === 'string'
      ? submittedEmail.trim().toLowerCase()
      : ''
  const displayName =
    typeof submittedDisplayName === 'string'
      ? submittedDisplayName.trim()
      : ''

  if (
    !email ||
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    !displayName ||
    displayName.length > 40 ||
    typeof password !== 'string' ||
    password.length < 8 ||
    Buffer.byteLength(password, 'utf8') > 72
  ) {
    return res.status(400).json({
      error:
        'Provide a valid email, a display name of 1-40 characters, and a password of 8-72 bytes.',
    })
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12)
    const result = await pool.query(
      `INSERT INTO users (email, display_name, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, email, display_name`,
      [email, displayName, passwordHash],
    )
    const user = result.rows[0]

    await regenerateSession(req)
    req.session.userId = user.id
    await saveSession(req)

    res.status(201).json({ user: publicUser(user) })
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({
        error: 'An account with that email already exists.',
      })
    }
    next(error)
  }
})

app.post('/api/auth/login', async (req, res, next) => {
  const { email: submittedEmail, password } = req.body ?? {}
  const email =
    typeof submittedEmail === 'string'
      ? submittedEmail.trim().toLowerCase()
      : ''

  if (
    !email ||
    email.length > 254 ||
    typeof password !== 'string' ||
    Buffer.byteLength(password, 'utf8') > 72
  ) {
    return res.status(400).json({
      error: 'Provide a valid email and password.',
    })
  }

  try {
    const result = await pool.query(
      `SELECT id, email, display_name, password_hash
       FROM users
       WHERE email = $1`,
      [email],
    )
    const user = result.rows[0]

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid email or password.' })
    }

    await regenerateSession(req)
    req.session.userId = user.id
    await saveSession(req)

    res.json({ user: publicUser(user) })
  } catch (error) {
    next(error)
  }
})

app.post('/api/auth/logout', async (req, res, next) => {
  try {
    await destroySession(req)
    clearSessionCookie(res)
    res.status(204).end()
  } catch (error) {
    next(error)
  }
})

app.get('/api/health', async (_req, res, next) => {
  try {
    await pool.query('SELECT 1')
    res.json({ status: 'ok', database: 'connected' })
  } catch (error) {
    next(error)
  }
})

// Retrieve the available question sets from the database.
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

// Retrieve a question set with its questions and answer choices.
app.get('/api/question-sets/:setId/questions', async (req, res, next) => {
  try {
    const setResult = await pool.query(
      'SELECT id, title FROM question_sets WHERE id = $1',
      [req.params.setId],
    )

    if (setResult.rowCount === 0) {
      return res.status(404).json({ error: 'Question set not found.' })
    }

    // Exclude correct-answer indicators from the client-facing query.
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

    // Group joined database rows into questions with nested choices.
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

// Validate a submitted answer without storing the player's response.
app.post('/api/questions/:questionId/answers', async (req, res, next) => {
  try {
    const { choiceId } = req.body ?? {}

    if (typeof choiceId !== 'string' || choiceId.length === 0) {
      return res.status(400).json({
        error: 'choiceId must be a non-empty string.',
      })
    }

    // Use parameterized SQL to safely handle client-provided identifiers.
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

app.get('/api/me/stats', async (req, res, next) => {
  const userId = req.session?.userId
  if (!userId) {
    return res.status(401).json({ error: 'Sign in to view your stats.' })
  }

  try {
    const statsResult = await pool.query(
      `SELECT
         COUNT(*)::int AS attempts,
         COALESCE(SUM(score), 0)::int AS correct_answers,
         COALESCE(SUM(total_questions), 0)::int AS total_questions,
         COALESCE(
           ROUND(
             100.0 * SUM(score) / NULLIF(SUM(total_questions), 0),
             1
           ),
           0
         )::float AS accuracy_percent
       FROM quiz_attempts
       WHERE user_id = $1`,
      [userId],
    )

    const recentResult = await pool.query(
      `SELECT
         qa.id,
         qa.question_set_id,
         qs.title AS question_set_title,
         qa.score,
         qa.total_questions,
         ROUND(100.0 * qa.score / qa.total_questions, 1)::float
           AS accuracy_percent,
         qa.completed_at
       FROM quiz_attempts qa
       JOIN question_sets qs ON qs.id = qa.question_set_id
       WHERE qa.user_id = $1
       ORDER BY qa.completed_at DESC
       LIMIT 10`,
      [userId],
    )

    const stats = statsResult.rows[0]

    res.json({
      attempts: stats.attempts,
      correctAnswers: stats.correct_answers,
      totalQuestions: stats.total_questions,
      accuracyPercent: stats.accuracy_percent,
      recentAttempts: recentResult.rows.map((row) => ({
        attemptId: row.id,
        questionSetId: row.question_set_id,
        questionSetTitle: row.question_set_title,
        score: row.score,
        totalQuestions: row.total_questions,
        accuracyPercent: row.accuracy_percent,
        completedAt: row.completed_at,
      })),
    })
  } catch (error) {
    next(error)
  }
})

app.get('/api/leaderboard', async (req, res, next) => {
  const { setId, limit: rawLimit = '20' } = req.query
  const limit = Number(rawLimit)

  if (typeof setId !== 'string' || setId.length === 0) {
    return res.status(400).json({ error: 'setId is required.' })
  }

  if (
    typeof rawLimit !== 'string' ||
    !Number.isInteger(limit) ||
    limit < 1 ||
    limit > 100
  ) {
    return res.status(400).json({ error: 'limit must be between 1 and 100.' })
  }

  try {
    const setResult = await pool.query(
      'SELECT id FROM question_sets WHERE id = $1',
      [setId],
    )

    if (setResult.rowCount === 0) {
      return res.status(404).json({ error: 'Question set not found.' })
    }

    const result = await pool.query(
      `WITH best_attempts AS (
         SELECT DISTINCT ON (qa.user_id)
           qa.user_id,
           u.display_name,
           qa.score,
           qa.total_questions,
           qa.completed_at
         FROM quiz_attempts qa
         JOIN users u ON u.id = qa.user_id
         WHERE qa.question_set_id = $1
         ORDER BY
           qa.user_id,
           qa.score::numeric / qa.total_questions DESC,
           qa.score DESC,
           qa.completed_at ASC
       )
       SELECT
         ROW_NUMBER() OVER (
           ORDER BY
             score::numeric / total_questions DESC,
             score DESC,
             completed_at ASC,
             display_name ASC
         )::int AS rank,
         display_name,
         score,
         total_questions,
         ROUND(100.0 * score / total_questions, 1)::float
           AS accuracy_percent,
         completed_at
       FROM best_attempts
       ORDER BY
         score::numeric / total_questions DESC,
         score DESC,
         completed_at ASC,
         display_name ASC
       LIMIT $2`,
      [setId, limit],
    )

    res.json({
      setId,
      entries: result.rows.map((row) => ({
        rank: row.rank,
        displayName: row.display_name,
        score: row.score,
        totalQuestions: row.total_questions,
        accuracyPercent: row.accuracy_percent,
        completedAt: row.completed_at,
      })),
    })
  } catch (error) {
    next(error)
  }
})

app.use((error, _req, res, _next) => {
  console.error(error)
  const status = Number.isInteger(error.status) ? error.status : 500
  const message = status < 500 ? error.message : 'Internal server error.'
  res.status(status).json({ error: message })
})

// Start the API server using the configured port or the default.
app.listen(port, () => {
  console.log(`Quizzy API listening on http://localhost:${port}`)
})