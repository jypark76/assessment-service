# In plain English: this file holds everything about an instructor's review. A review is
# never written onto an existing row. It is added as a NEW version of the submission with
# the status "approved" or "rejected", copying the grade it is about, so the full history
# stays. The file has the rules a new review must follow and the one thing the service can
# do with it: record it safely, even if the same request arrives twice or two reviewers
# race on the same submission.
from typing import Literal
from uuid import UUID

import psycopg
from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationInfo, field_validator

from app.db import connect
from app.grades import SubmissionMovedOn, SubmissionNotFound
from app.text_rules import long_text, trimmed

REVIEWER_MAX = 100
FEEDBACK_MAX = 10_000

# In plain English: which status each decision creates.
STATUS_FOR = {"approve": "approved", "reject": "rejected"}


# In plain English: raised when the submission is not waiting for a review. Only a
# submission whose latest version is a grade can be reviewed. A new one has no grade yet,
# a rejected one needs a new grade first, and an approved one is final.
class NotWaitingForReview(Exception):
    pass


# In plain English: what a reviewer must send. "based_on_version" is the version of the
# grade being reviewed, which makes a retry safe. The decision is "approve" or "reject".
# A rejection must say why (feedback, stored exactly as written, not blank, at most
# 10,000 characters). An approval takes no feedback. Anything extra is refused. The
# reviewer name is trimmed and at most 100 characters. It is a name the caller claims,
# not a proven identity, because the service has no authentication yet.
class NewReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    based_on_version: StrictInt = Field(ge=1)
    decision: Literal["approve", "reject"]
    reviewer_username: str
    # The feedback rule depends on the decision, so it is checked even when the caller
    # leaves the feedback out (validate_default). The decision is declared above so it is
    # already checked by the time this runs.
    feedback: str | None = Field(default=None, validate_default=True)

    @field_validator("reviewer_username")
    @classmethod
    def reviewer_rules(cls, value):
        return trimmed(value, REVIEWER_MAX)

    @field_validator("feedback")
    @classmethod
    def feedback_rules(cls, value, info: ValidationInfo):
        decision = info.data.get("decision")
        if decision == "reject":
            if value is None:
                raise ValueError("Feedback is required when rejecting")
            return long_text(value, FEEDBACK_MAX)
        if decision == "approve" and value is not None:
            raise ValueError("Feedback is only allowed when rejecting")
        return value


# In plain English: turns a stored row into the reply a caller sees.
def _reply(submission_id, row):
    version, status, ai_grade, ai_reasoning, reviewer_username, feedback, created_at = row
    return {
        "submission_id": submission_id,
        "version": version,
        "status": status,
        "ai_grade": ai_grade,
        "ai_reasoning": ai_reasoning,
        "reviewer_username": reviewer_username,
        "feedback": feedback,
        "created_at": created_at,
    }


# In plain English: one attempt at recording the review. It reads the submission's history
# and then decides, in this order:
#   1. no history at all: the submission does not exist;
#   2. the next version is already this very review: it is a retry, so return it;
#   3. the latest version is not the one being reviewed: it has moved on;
#   4. the latest version is not a grade waiting for review: refuse;
#   5. otherwise add the next version, copying the student's work and the grade from the
#      version being reviewed, so the database's guard on the submitted work holds.
# Returns the reply and True if a row was added, False if it was a retry.
def _try_record(submission_id, review):
    wanted_status = STATUS_FOR[review.decision]
    with connect() as connection:
        history = connection.execute(
            "SELECT version, status, ai_grade, ai_reasoning, reviewer_username, feedback, "
            "created_at FROM submissions WHERE submission_id = %s ORDER BY version",
            (submission_id,),
        ).fetchall()
        if not history:
            raise SubmissionNotFound()

        next_version = review.based_on_version + 1
        for row in history:
            version, status, _, _, reviewer_username, feedback, _ = row
            if (
                version == next_version
                and status == wanted_status
                and reviewer_username == review.reviewer_username
                and feedback == review.feedback
            ):
                return _reply(submission_id, row), False

        latest_version, latest_status = history[-1][0], history[-1][1]
        if latest_version != review.based_on_version:
            raise SubmissionMovedOn()
        if latest_status != "graded":
            raise NotWaitingForReview()

        row = connection.execute(
            "INSERT INTO submissions (submission_id, version, assignment_id, status, "
            "student_name, submission_text, ai_grade, ai_reasoning, reviewer_username, "
            "feedback) "
            "SELECT submission_id, %s::integer, assignment_id, %s::text, student_name, "
            "submission_text, ai_grade, ai_reasoning, %s::text, %s::text "
            "FROM submissions WHERE submission_id = %s AND version = %s "
            "RETURNING version, status, ai_grade, ai_reasoning, reviewer_username, "
            "feedback, created_at",
            (
                next_version,
                wanted_status,
                review.reviewer_username,
                review.feedback,
                submission_id,
                review.based_on_version,
            ),
        ).fetchone()
    return _reply(submission_id, row), True


# In plain English: records a review as the next version of a submission. If another
# reviewer takes the same version number at the same moment, the database refuses the
# second one, and this looks again from the start. The second look then finds either the
# same review (a retry) or a submission that has moved on, and answers accordingly.
def record_review(submission_id: UUID, review: NewReview):
    for _ in range(2):
        try:
            return _try_record(submission_id, review)
        except psycopg.errors.UniqueViolation:
            continue
    raise SubmissionMovedOn()
