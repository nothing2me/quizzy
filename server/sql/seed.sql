-- Create or update the question set used by the Quizzy application.
INSERT INTO question_sets (id, title)
VALUES ('corpus-cc', 'Corpus Christi and TAMU-CC')
ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title;

-- Insert the initial questions, updating existing records when IDs match.
INSERT INTO questions (id, question_set_id, prompt, position)
VALUES
  ('q1', 'corpus-cc', 'Which body of water borders Corpus Christi?', 1),
  ('q2', 'corpus-cc', 'What is Texas A&M University-Corpus Christi''s nickname?', 2)
ON CONFLICT (id) DO UPDATE SET
  question_set_id = EXCLUDED.question_set_id,
  prompt = EXCLUDED.prompt,
  position = EXCLUDED.position;

-- Insert four answer choices per question, including correctness and display order.
INSERT INTO answer_choices (id, question_id, text, is_correct, position)
VALUES
  ('q1-a', 'q1', 'Gulf of Mexico', TRUE, 1),
  ('q1-b', 'q1', 'Pacific Ocean', FALSE, 2),
  ('q1-c', 'q1', 'Atlantic Ocean', FALSE, 3),
  ('q1-d', 'q1', 'Lake Superior', FALSE, 4),
  ('q2-a', 'q2', 'The Islanders', TRUE, 1),
  ('q2-b', 'q2', 'The Longhorns', FALSE, 2),
  ('q2-c', 'q2', 'The Roadrunners', FALSE, 3),
  ('q2-d', 'q2', 'The Owls', FALSE, 4)
ON CONFLICT (id) DO UPDATE SET
  question_id = EXCLUDED.question_id,
  text = EXCLUDED.text,
  is_correct = EXCLUDED.is_correct,
  position = EXCLUDED.position;