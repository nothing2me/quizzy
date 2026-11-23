-- Create or update the question set used by the Quizzy application.
INSERT INTO question_sets (id, title)
VALUES ('corpus-cc', 'Corpus Christi and TAMU-CC')
ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title;

-- Insert the initial questions, updating existing records when IDs match.
INSERT INTO questions (id, question_set_id, prompt, position)
VALUES
  ('q1', 'corpus-cc', 'Which body of water borders Corpus Christi?', 1),
  ('q2', 'corpus-cc', 'What is Texas A&M University-Corpus Christi''s nickname?', 2),
  ('q3', 'corpus-cc', 'Which historic aircraft carrier is a museum in Corpus Christi?', 3),
  ('q4', 'corpus-cc', 'Which Corpus Christi attraction focuses on marine life?', 4),
  ('q5', 'corpus-cc', 'What is the name of Corpus Christi''s minor league baseball team?', 5),
  ('q6', 'corpus-cc', 'What is the nickname of the USS Lexington?', 6),
  ('q7', 'corpus-cc', 'What is TAMU-CC''s mascot called?', 7)
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
  ('q2-d', 'q2', 'The Owls', FALSE, 4),
  ('q3-a', 'q3', 'USS Lexington', TRUE, 1),
  ('q3-b', 'q3', 'USS Midway', FALSE, 2),
  ('q3-c', 'q3', 'USS Intrepid', FALSE, 3),
  ('q3-d', 'q3', 'USS Texas', FALSE, 4),
  ('q4-a', 'q4', 'Texas State Aquarium', TRUE, 1),
  ('q4-b', 'q4', 'Dallas World Aquarium', FALSE, 2),
  ('q4-c', 'q4', 'Moody Gardens', FALSE, 3),
  ('q4-d', 'q4', 'Houston Zoo', FALSE, 4),
  ('q5-a', 'q5', 'The Hooks', TRUE, 1),
  ('q5-b', 'q5', 'The Missions', FALSE, 2),
  ('q5-c', 'q5', 'The Express', FALSE, 3),
  ('q5-d', 'q5', 'The RoughRiders', FALSE, 4),
  ('q6-a', 'q6', 'The Blue Ghost', TRUE, 1),
  ('q6-b', 'q6', 'Old Ironsides', FALSE, 2),
  ('q6-c', 'q6', 'The Mighty Mo', FALSE, 3),
  ('q6-d', 'q6', 'The Big E', FALSE, 4),
  ('q7-a', 'q7', 'Izzy the Islander', TRUE, 1),
  ('q7-b', 'q7', 'Bevo', FALSE, 2),
  ('q7-c', 'q7', 'Reveille', FALSE, 3),
  ('q7-d', 'q7', 'Rowdy', FALSE, 4)
ON CONFLICT (id) DO UPDATE SET
  question_id = EXCLUDED.question_id,
  text = EXCLUDED.text,
  is_correct = EXCLUDED.is_correct,
  position = EXCLUDED.position;