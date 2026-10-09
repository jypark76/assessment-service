# In plain English: this file holds everything about recording a grade. A grade is never
# written onto an existing row. It is added as a NEW version of the submission with the
# status "graded", so the full history is kept. The file has the rules a new grade must
# follow and the one thing the service can do with it: record it safely, even if the same
# request arrives twice or two workers race on the same submission.
from uuid import UUID

import psycopg
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator

from app.db import connect
from app.text_rules import long_text, trimmed

GRADE_MAX = 20
REASONING_MAX = 10_000


# In plain English: raised when there is no submission with the given ID.
class SubmissionNotFound(Exception):
    pass


# In plain English: raised when the submission is no longer at the version the grader
# says it graded, or that version already has a different grade.
class SubmissionMovedOn(Exception):
    pass


# In plain English: raised when the submission is not waiting for a grade. It is either
# already graded and waiting for an instructor, or already approved, which is final.
class NotWaitingForGrade(Exception):
    pass


# In plain English: what a grader must send. "based_on_version" is the version of the
# submission it graded. That makes a retry safe: the service can tell "this grade is
# already saved" from "someone else got there first". Anything extra is refused. The
# grade is trimmed and at most 20 characters. The reasoning is stored exactly as written,
# but it cannot be blank or longer than 10,000 characters. The version must be a real whole
# number, so text that only looks like one is refused.
class NewGrade(BaseModel):
    model_config = ConfigDict(extra="forbid")

    based_on_version: StrictInt = Field(ge=1)
    ai_grade: str
    ai_reasoning: str

    @field_validator("ai_grade")
    @classmethod
    def grade_rules(cls, value):
        return trimmed(value, GRADE_MAX)

    @field_validator("ai_reasoning")
    @classmethod
    def reasoning_rules(cls, value):
        return long_text(value, REASONING_MAX)


# In plain English: turns a stored row into the reply a caller sees.
def _reply(submission_id, row):
    version, status, ai_grade, ai_reasoning, created_at = row
    return {
        "submission_id": submission_id,
        "version": version,
        "status": status,
        "ai_grade": ai_grade,
        "ai_reasoning": ai_reasoning,
        "created_at": created_at,
    }


# In plain English: one attempt at recording the grade. It reads the submission's history
# and then decides, in this order:
#   1. no history at all: the submission does not exist;
#   2. the next version is already this very grade: it is a retry, so return it;
#   3. the latest version is not the one the grader graded: it has moved on;
#   4. the latest version is not waiting for a grade: refuse;
#   5. otherwise add the next version as "graded", copying the student's work from
#      version 1 so the database's guard on the submitted work holds.
# Returns the reply and True if a row was added, False if it was a retry.
def _try_record(submission_id, grade):
    with connect() as connection:
        history = connection.execute(
            "SELECT version, status, ai_grade, ai_reasoning, created_at "
            "FROM submissions WHERE submission_id = %s ORDER BY version",
            (submission_id,),
        ).fetchall()
        if not history:
            raise SubmissionNotFound()

        next_version = grade.based_on_version + 1
        for row in history:
            version, status, ai_grade, ai_reasoning, _ = row
            if (
                version == next_version
                and status == "graded"
                and ai_grade == grade.ai_grade
                and ai_reasoning == grade.ai_reasoning
            ):
                return _reply(submission_id, row), False

        latest_version, latest_status = history[-1][0], history[-1][1]
        if latest_version != grade.based_on_version:
            raise SubmissionMovedOn()
        if latest_status not in ("submitted", "rejected"):
            raise NotWaitingForGrade()

        row = connection.execute(
            "INSERT INTO submissions (submission_id, version, assignment_id, status, "
            "student_name, submission_text, ai_grade, ai_reasoning) "
            "SELECT submission_id, %s::integer, assignment_id, 'graded', student_name, "
            "submission_text, %s::text, %s::text "
            "FROM submissions WHERE submission_id = %s AND version = 1 "
            "RETURNING version, status, ai_grade, ai_reasoning, created_at",
            (next_version, grade.ai_grade, grade.ai_reasoning, submission_id),
        ).fetchone()
    return _reply(submission_id, row), True


# In plain English: records a grade as the next version of a submission. If another
# worker takes the same version number at the same moment, the database refuses the
# second one, and this looks again from the start. The second look then finds either the
# same grade (a retry) or a submission that has moved on, and answers accordingly.
def record_grade(submission_id: UUID, grade: NewGrade):
    for _ in range(2):
        try:
            return _try_record(submission_id, grade)
        except psycopg.errors.UniqueViolation:
            continue
    raise SubmissionMovedOn()
