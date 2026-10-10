# In plain English: the job sender. When a submission is waiting for a grade, the grader
# has to be told. This program does that by publishing a message on the Kafka topic
# "grading-jobs". The message format is the shared contract in
# platform/contracts/grading-jobs.md.
#
# It works exactly like the approved-example sender (app/sender.py), and shares its sending
# loop: the database is the to-do list. Each round it asks "which submissions have a newest
# version that is waiting for a grade and has no job sent yet?", publishes a job for each,
# and adds a row to grading_job_sends ONLY after Kafka confirms it arrived. Anything not
# confirmed is still waiting and goes out again next round. A job delivered twice is harmless:
# the first grade recorded for a version wins, and the assessment service refuses the others.
#
# A submission is waiting for a grade when its newest version is "submitted" (a first
# submission) or "rejected" (an instructor sent it back). A job is identified by the
# submission AND that version, so a second rejection creates a second job. On a rejection
# the job carries the instructor's feedback, or the grader would see the same input as last
# time and repeat itself. The student's name and the reviewer's name are never sent.
#
# Nothing the student wrote is ever logged. Logs carry submission IDs and counts only.
import logging
import os
import signal
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.assignments import RUBRIC_MAX
from app.db import connect
from app.reviews import FEEDBACK_MAX
from app.sender import producer_settings, run
from app.submissions import TEXT_MAX
from app.text_rules import long_text

TOPIC = "grading-jobs"

# The grader's limits, from the table in the contract. The message is checked against them
# before it is sent, so a job the grader would refuse is never published.
MESSAGE_LIMITS = {"rubric": 10_000, "student_work": 20_000, "feedback": 10_000}

log = logging.getLogger("assessment-job-sender")


# In plain English: the rules for one job, straight from the contract. Extra fields are
# refused. The three texts are kept exactly as written (no trimming), must not be blank, and
# must fit their limit. Feedback is optional: it is left out of a first-time job.
class GradingJobMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1, le=1)
    submission_id: uuid.UUID
    based_on_version: int = Field(ge=1)
    assignment_id: uuid.UUID
    rubric: str
    student_work: str
    feedback: str | None = None

    @field_validator("rubric")
    @classmethod
    def rubric_rules(cls, value):
        return long_text(value, MESSAGE_LIMITS["rubric"])

    @field_validator("student_work")
    @classmethod
    def work_rules(cls, value):
        return long_text(value, MESSAGE_LIMITS["student_work"])

    @field_validator("feedback")
    @classmethod
    def feedback_rules(cls, value):
        return None if value is None else long_text(value, MESSAGE_LIMITS["feedback"])


# In plain English: turns one waiting submission version into the key and value of a Kafka
# message. The key is the submission ID as text. It raises ValueError if the row would break
# the contract (which the limits should make impossible). The error is not allowed to carry
# the student's text, so the caller logs only the ID.
def build_message(row):
    submission_id, version, assignment_id, rubric, submission_text, feedback = row
    message = GradingJobMessage(
        submission_id=submission_id,
        based_on_version=version,
        assignment_id=assignment_id,
        rubric=rubric,
        student_work=submission_text,
        feedback=feedback,
    )
    return str(submission_id).encode("utf-8"), message.model_dump_json(exclude_none=True).encode("utf-8")


# In plain English: a job is identified by the submission and the version waiting for a grade.
def identify(row):
    return (row[0], row[1])


# In plain English: the submissions whose NEWEST version is waiting for a grade and has no job
# sent yet, oldest first, leaving out the (submission, version) pairs in "skip". Each row has
# what the job needs: the submission and version, the assignment and its rubric, the work, and
# the instructor's feedback (empty on a first submission). Reads only. DISTINCT ON picks the
# newest version of each submission.
def fetch_waiting(limit, skip=()):
    skip_ids = [pair[0] for pair in skip]
    skip_versions = [pair[1] for pair in skip]
    with connect() as connection:
        return connection.execute(
            "SELECT s.submission_id, s.version, s.assignment_id, a.rubric, s.submission_text, s.feedback "
            "FROM (SELECT DISTINCT ON (submission_id) * FROM submissions "
            "      ORDER BY submission_id, version DESC) s "
            "JOIN assignments a ON a.assignment_id = s.assignment_id "
            "WHERE s.status IN ('submitted', 'rejected') "
            "AND NOT EXISTS (SELECT 1 FROM grading_job_sends g "
            "                WHERE g.submission_id = s.submission_id AND g.version = s.version) "
            "AND NOT EXISTS (SELECT 1 FROM unnest(%s::uuid[], %s::int[]) AS k(id, v) "
            "                WHERE k.id = s.submission_id AND k.v = s.version) "
            "ORDER BY s.created_at, s.submission_id LIMIT %s",
            (skip_ids, skip_versions, limit),
        ).fetchall()


# In plain English: notes that Kafka confirmed this job. Adding it twice is harmless.
def record_job_sent(identity):
    submission_id, version = identity
    with connect() as connection:
        connection.execute(
            "INSERT INTO grading_job_sends (submission_id, version) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (submission_id, version),
        )


# In plain English: starts the real job sender. It stops cleanly when Kubernetes asks it to
# (SIGTERM), after finishing the round in hand.
def main():
    from confluent_kafka import Producer

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    producer = Producer(producer_settings(os.environ))
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(True))
    signal.signal(signal.SIGINT, lambda *_: stopping.append(True))
    run(
        producer,
        fetch_waiting,
        record_job_sent,
        should_stop=lambda: bool(stopping),
        topic=TOPIC,
        build=build_message,
        identify=identify,
    )


if __name__ == "__main__":
    main()
