import express from 'express'
import { pool } from './db.js'

const app = express()
const port = Number(process.env.PORT) || 3001

// Parse incoming JSON request bodies with a 32 KB size limit.
app.use(express.json({ limit: '32kb' }))

// Verify that the API is running and PostgreSQL is accessible.
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

// Handle forwarded errors while hiding internal details from clients.
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