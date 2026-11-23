-- A question set groups related trivia questions.
CREATE TABLE IF NOT EXISTS question_sets (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL
);

-- Cascade deletes keep questions from outliving their parent set.
CREATE TABLE IF NOT EXISTS questions (
  id TEXT PRIMARY KEY,
  question_set_id TEXT NOT NULL
    REFERENCES question_sets(id) ON DELETE CASCADE,
  prompt TEXT NOT NULL,
  position INTEGER NOT NULL,
  UNIQUE (question_set_id, position)
);

-- Each choice belongs to one questions; is_correct is checked server-side.
CREATE TABLE IF NOT EXISTS answer_choices (
  id TEXT PRIMARY KEY,
  question_id TEXT NOT NULL
    REFERENCES questions(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  is_correct BOOLEAN NOT NULL DEFAULT FALSE,
  position INTEGER NOT NULL,
  UNIQUE (question_id, position)
);

CREATE TABLE IF NOT EXISTS users (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS quiz_attempts (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  question_set_id TEXT NOT NULL REFERENCES question_sets(id),
  score INTEGER NOT NULL CHECK (score >= 0),
  total_questions INTEGER NOT NULL CHECK (total_questions > 0),
  completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (score <= total_questions)
);

CREATE TABLE IF NOT EXISTS attempt_answers (
  attempt_id BIGINT NOT NULL REFERENCES quiz_attempts(id) ON DELETE CASCADE,
  question_id TEXT NOT NULL REFERENCES questions(id),
  selected_choice_id TEXT REFERENCES answer_choices(id),
  correct_choice_id TEXT NOT NULL REFERENCES answer_choices(id),
  PRIMARY KEY (attempt_id, question_id)
);

CREATE INDEX IF NOT EXISTS quiz_attempts_user_completed_idx
  ON quiz_attempts (user_id, completed_at DESC);

CREATE INDEX IF NOT EXISTS quiz_attempts_leaderboard_idx
  ON quiz_attempts (score DESC, completed_at ASC);