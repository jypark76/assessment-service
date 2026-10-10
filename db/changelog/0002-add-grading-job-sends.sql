--liquibase formatted sql

--changeset denny:0002-add-grading-job-sends
-- In plain English: a new table that remembers which grading jobs have already been sent to
-- the grader through Kafka. A submission can need grading more than once (an instructor can
-- reject a grade and ask for a new one), so a job is identified by the submission AND the
-- version that is waiting for a grade. The job sender looks for submissions whose newest
-- version is waiting for a grade and is NOT in this table, sends a job, and adds a row here
-- only after Kafka confirms it arrived. Anything not confirmed is simply sent again.
--
-- Rows are only ever added: the service's login may read and add, never change or delete,
-- like every other table here. There is no foreign key: submissions has one row per VERSION,
-- so the ID alone does not identify a row there.
CREATE TABLE grading_job_sends (
  submission_id uuid NOT NULL,
  version       integer NOT NULL CHECK (version >= 1),
  sent_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (submission_id, version)
);

GRANT SELECT, INSERT ON grading_job_sends TO assessment_app;
--rollback DROP TABLE grading_job_sends;
