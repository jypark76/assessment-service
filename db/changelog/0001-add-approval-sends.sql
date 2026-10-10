--liquibase formatted sql

--changeset denny:0001-add-approval-sends
-- In plain English: a new table that remembers which approved submissions have already
-- been sent on to the knowledge service through Kafka. The sender looks for approved
-- submissions that are NOT in this table yet, sends them, and adds a row here only after
-- Kafka confirms it arrived. A submission missing from this table is simply sent again, so
-- nothing is lost if Kafka or the sender has a bad moment.
--
-- Rows are only ever added: the service's login may read and add, never change or delete,
-- like every other table here. The submission ID is the key, so one submission is recorded
-- once. There is no foreign key: submissions has one row per VERSION, so the ID alone does
-- not identify a row there.
CREATE TABLE approval_sends (
  submission_id uuid PRIMARY KEY,
  sent_at       timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT ON approval_sends TO assessment_app;
--rollback DROP TABLE approval_sends;
