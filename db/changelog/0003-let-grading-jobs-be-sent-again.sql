--liquibase formatted sql

--changeset denny:0003-let-grading-jobs-be-sent-again
-- In plain English: lets the same grading job be recorded more than once, each time with its
-- own time. Recording a job as sent only proves Kafka received it. The grader may later set it
-- aside as unreadable, or Kafka may drop it after its 7 days, and the submission would then
-- wait for a grade forever. With one row per attempt, the job sender can see that a job was
-- sent a long time ago and nobody answered, send it again, and stop after a few attempts so a
-- job that can never succeed is left for a person instead of being sent for ever.
--
-- Still only ever added to: the service's login may read and add, never change or delete.
ALTER TABLE grading_job_sends DROP CONSTRAINT grading_job_sends_pkey;
ALTER TABLE grading_job_sends ADD PRIMARY KEY (submission_id, version, sent_at);
--rollback ALTER TABLE grading_job_sends DROP CONSTRAINT grading_job_sends_pkey;
--rollback ALTER TABLE grading_job_sends ADD PRIMARY KEY (submission_id, version);
