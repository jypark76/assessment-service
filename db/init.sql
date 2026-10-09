-- In plain English: this file sets up the assessment service's own database.
-- It runs once, when the database is first created. It creates the limited login
-- the service connects with, then the two tables that hold assignments and
-- student submissions, and finally says what that login may do with them.

-- The limited login the service connects with. It is created WITHOUT a
-- password here, because this file lives in a public repo. The password is set
-- separately when the database starts (see k8s/overlays/local/set-app-password.sh)
-- and is never written into any file.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'assessment_app') THEN
    CREATE ROLE assessment_app LOGIN;
  END IF;
END
$$;

-- Lets that login look inside the database's main folder (the "public schema").
-- It is NOT allowed to create anything there, so the service cannot add tables
-- or change the database's structure even if it has a bug.
GRANT USAGE ON SCHEMA public TO assessment_app;

-- Turns on Postgres's bundled "pgcrypto" add-on, which provides the SHA-256 hashing
-- used by the guard on the submissions table. This file runs as the database's setup
-- account, which is allowed to do this. The service's limited login gets no extra
-- rights from it.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Table 1: assignments. One row per assignment an instructor sets up.
-- ---------------------------------------------------------------------------
CREATE TABLE assignments (
  assignment_id       uuid PRIMARY KEY,
  -- Every assignment names its instructor, so it can never be left without an owner.
  instructor_username text NOT NULL CHECK (char_length(btrim(instructor_username)) >= 1),
  -- 1 to 200 characters once the spaces at either end are trimmed. Uniqueness is
  -- enforced by the index below, which ignores capital letters and outer spaces.
  title               text NOT NULL
                      CHECK (char_length(btrim(title)) BETWEEN 1 AND 200),
  -- The instructions the grader works from. It must not be blank.
  rubric              text NOT NULL CHECK (char_length(btrim(rubric)) >= 1),
  created_at          timestamptz NOT NULL DEFAULT now()
);

-- Titles are unique across the whole system, the way a person would read them:
-- "Essay 1", "Essay 1 " and "essay 1" count as the same title.
CREATE UNIQUE INDEX assignments_title_unique
  ON assignments (lower(btrim(title)));

-- ---------------------------------------------------------------------------
-- Table 2: submissions. One row per VERSION of a submission, never updated.
-- Version 1 is the student's work. Every grade, rejection or approval after
-- that is a NEW row with the next version number, so the full history stays.
-- ---------------------------------------------------------------------------
CREATE TABLE submissions (
  submission_id     uuid NOT NULL,
  version           integer NOT NULL CHECK (version >= 1),
  assignment_id     uuid NOT NULL REFERENCES assignments (assignment_id),
  status            text NOT NULL
                    CHECK (status IN ('submitted', 'graded', 'rejected', 'approved')),
  -- What the student handed in. Every version repeats it (see the guard below).
  student_name      text NOT NULL CHECK (char_length(btrim(student_name)) BETWEEN 1 AND 200),
  submission_text   text NOT NULL
                    CHECK (char_length(btrim(submission_text)) >= 1
                           AND char_length(submission_text) <= 20000),
  -- The grade and reasoning, and the review that followed.
  ai_grade          text CHECK (char_length(btrim(ai_grade)) BETWEEN 1 AND 20),
  ai_reasoning      text CHECK (char_length(btrim(ai_reasoning)) >= 1),
  reviewer_username text CHECK (char_length(btrim(reviewer_username)) >= 1),
  feedback          text CHECK (char_length(btrim(feedback)) >= 1),
  created_at        timestamptz NOT NULL DEFAULT now(),

  -- One row per version number of a submission.
  PRIMARY KEY (submission_id, version),

  -- Version 1 is always "submitted", and no later version is.
  CONSTRAINT version_one_is_submitted CHECK ((version = 1) = (status = 'submitted')),

  -- Each status must carry exactly the fields it needs.
  CONSTRAINT status_carries_its_fields CHECK (
    CASE status
      WHEN 'submitted' THEN ai_grade IS NULL AND ai_reasoning IS NULL
                            AND reviewer_username IS NULL AND feedback IS NULL
      WHEN 'graded'    THEN ai_grade IS NOT NULL AND ai_reasoning IS NOT NULL
                            AND reviewer_username IS NULL AND feedback IS NULL
      WHEN 'rejected'  THEN ai_grade IS NOT NULL AND ai_reasoning IS NOT NULL
                            AND reviewer_username IS NOT NULL AND feedback IS NOT NULL
      WHEN 'approved'  THEN ai_grade IS NOT NULL AND ai_reasoning IS NOT NULL
                            AND reviewer_username IS NOT NULL
    END
  ),

  -- THE GUARD. A fingerprint (hash) of the assignment, the student's name and the
  -- essay. A hash is used because Postgres cannot index a long essay directly, and
  -- essays here can be 20,000 characters. It is SHA-256, because the older MD5 can be
  -- forged on purpose. The length of the name goes in as well, so two different name
  -- and essay splits can never produce the same fingerprint.
  content_hash      text GENERATED ALWAYS AS (
                      encode(digest(
                        assignment_id::text || '|' || char_length(student_name)::text
                        || '|' || student_name || '|' || submission_text, 'sha256'), 'hex')
                    ) STORED,

  -- Every version points back at version 1 and must carry the same fingerprint.
  -- So nobody can change the name, essay or assignment in a later version.
  first_version     integer NOT NULL DEFAULT 1 CHECK (first_version = 1),
  CONSTRAINT same_work_as_version_one
    FOREIGN KEY (submission_id, first_version, content_hash)
    REFERENCES submissions (submission_id, version, content_hash),

  -- The target the guard points at.
  CONSTRAINT version_and_fingerprint_are_unique UNIQUE (submission_id, version, content_hash)
);

-- At most one approval per submission. Rejections and re-grades can repeat.
CREATE UNIQUE INDEX one_approval_per_submission
  ON submissions (submission_id) WHERE status = 'approved';

-- ---------------------------------------------------------------------------
-- What the service's login may do: read rows and add rows. It may NOT change
-- or delete them, and it may not empty a table. History only ever grows.
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT ON assignments, submissions TO assessment_app;
