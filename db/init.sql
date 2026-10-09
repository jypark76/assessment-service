-- In plain English: this file sets up the knowledge service's own database.
-- It runs once, when the database is first created. It makes the table that
-- stores approved grading examples, makes it fast to search, and creates a
-- limited login the service uses so it can read and add examples but never
-- change or delete them.

-- Turn on the "vector" add-on (pgvector). It lets the database store a list of
-- numbers describing a piece of text and find the closest matches.
CREATE EXTENSION IF NOT EXISTS vector;

-- The one table in this database: every approved grading example.
CREATE TABLE IF NOT EXISTS examples (
  -- A unique ID for this example, made automatically.
  example_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Which assignment it belongs to. This is only a reference to the assessment
  -- service's assignment. There is deliberately no link between the two
  -- databases, so each service stays independent.
  assignment_id uuid NOT NULL,

  -- The student's work, the grade it received and why. No student name is
  -- stored on purpose, to keep personal data out of this service.
  student_work  text NOT NULL,
  grade         text NOT NULL,
  reasoning     text NOT NULL,

  -- 384 numbers describing what the student's work is about. Two pieces of
  -- work on similar topics get similar numbers, which is how "find similar
  -- examples" works. 384 matches the embedding model the service uses.
  embedding     vector(384) NOT NULL,

  -- When the example was saved.
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- Speeds up "list the examples for this assignment".
CREATE INDEX IF NOT EXISTS examples_assignment_id_idx
  ON examples (assignment_id);

-- Speeds up "find the examples closest to this text". Cosine distance compares
-- the direction of two number lists, which suits text embeddings.
CREATE INDEX IF NOT EXISTS examples_embedding_idx
  ON examples USING hnsw (embedding vector_cosine_ops);

-- The limited login the service connects with. It is created WITHOUT a
-- password here, because this file lives in a public repo. The password is set
-- separately by hand when the database is run, and is never written into any
-- file.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'knowledge_app') THEN
    CREATE ROLE knowledge_app LOGIN;
  END IF;
END
$$;

-- What that login is allowed to do: look at the table and add rows. It is NOT
-- given UPDATE or DELETE, so approved examples can never be edited or removed
-- through the service, even if the service has a bug.
GRANT USAGE ON SCHEMA public TO knowledge_app;
GRANT SELECT, INSERT ON examples TO knowledge_app;
