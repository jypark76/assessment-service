# In plain English: this file holds everything about submissions. A submission is a
# student's work, stored as versions. This step only handles version 1, the work itself.
# Grades and reviews will add the later versions. The file has the rules a new submission
# must follow, and the two things the service can do with them: save one (safely, even if
# the same request arrives twice) and read one back with its history.
from uuid import UUID

import psycopg
from pydantic import BaseModel, ConfigDict, field_validator

from app.db import connect
from app.text_rules import long_text, trimmed

NAME_MAX = 200
TEXT_MAX = 20_000


# In plain English: raised when the assignment a submission points at does not exist.
class AssignmentNotFound(Exception):
    pass


# In plain English: raised when a submission ID is already used by a submission with
# different content. The same content is a harmless retry, and is not an error.
class IdUsedForOtherContent(Exception):
    pass


# In plain English: what a caller must send to submit work. The caller picks the
# submission ID. That ID doubles as the request ID, so sending the same request twice
# (a double click, or a retry after a timeout) is recognised and creates nothing new.
# Anything extra is refused. The name is trimmed. The essay is stored exactly as
# written, but it cannot be blank or longer than 20,000 characters.
class NewSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    submission_id: UUID
    assignment_id: UUID
    student_name: str
    submission_text: str

    @field_validator("student_name")
    @classmethod
    def name_rules(cls, value):
        return trimmed(value, NAME_MAX)

    @field_validator("submission_text")
    @classmethod
    def text_rules(cls, value):
        return long_text(value, TEXT_MAX)


# In plain English: turns a version 1 row into the reply a caller sees.
def _version_one(row):
    submission_id, assignment_id, student_name, submission_text, version, status, created_at = row
    return {
        "submission_id": submission_id,
        "assignment_id": assignment_id,
        "student_name": student_name,
        "submission_text": submission_text,
        "version": version,
        "status": status,
        "created_at": created_at,
    }


VERSION_ONE_COLUMNS = (
    "submission_id, assignment_id, student_name, submission_text, version, status, created_at"
)


# In plain English: reads version 1 of a submission, or returns None if there is none.
def _read_version_one(submission_id):
    with connect() as connection:
        row = connection.execute(
            f"SELECT {VERSION_ONE_COLUMNS} FROM submissions "
            "WHERE submission_id = %s AND version = 1",
            (submission_id,),
        ).fetchone()
    return _version_one(row) if row else None


# In plain English: saves a submission as version 1 and returns it together with True.
# If the ID was already used, it compares what is stored with what was just sent. The
# same content means this is a retry, so it returns the stored submission with False and
# saves nothing. Different content raises IdUsedForOtherContent, and the stored
# submission is left untouched. If the assignment does not exist it raises
# AssignmentNotFound and saves nothing.
def create_submission(new):
    try:
        with connect() as connection:
            row = connection.execute(
                "INSERT INTO submissions (submission_id, version, assignment_id, status, "
                "student_name, submission_text) VALUES (%s, 1, %s, 'submitted', %s, %s) "
                f"RETURNING {VERSION_ONE_COLUMNS}",
                (new.submission_id, new.assignment_id, new.student_name, new.submission_text),
            ).fetchone()
        return _version_one(row), True
    except psycopg.errors.ForeignKeyViolation:
        raise AssignmentNotFound() from None
    except psycopg.errors.UniqueViolation:
        pass

    stored = _read_version_one(new.submission_id)
    same_content = (
        stored is not None
        and stored["assignment_id"] == new.assignment_id
        and stored["student_name"] == new.student_name
        and stored["submission_text"] == new.submission_text
    )
    if not same_content:
        raise IdUsedForOtherContent()
    return stored, False


# In plain English: lists the submissions whose LATEST version has the given status,
# oldest first, so it works as a queue. A submission counts under a status only while
# that status is its newest version, so a graded submission leaves the "graded" list the
# moment it is approved or rejected. It can be narrowed to one assignment. Each item has
# the IDs, the version, the grade and the time, but not the student's name or essay,
# which are read one submission at a time.
def list_submissions(status: str, assignment_id, limit: int):
    conditions = [
        "s.status = %s",
        "NOT EXISTS (SELECT 1 FROM submissions newer "
        "WHERE newer.submission_id = s.submission_id AND newer.version > s.version)",
    ]
    params = [status]
    if assignment_id is not None:
        conditions.append("s.assignment_id = %s")
        params.append(assignment_id)
    params.append(limit)
    with connect() as connection:
        rows = connection.execute(
            "SELECT s.submission_id, s.assignment_id, s.version, s.status, s.ai_grade, "
            "s.created_at FROM submissions s WHERE " + " AND ".join(conditions) +
            " ORDER BY s.created_at, s.submission_id LIMIT %s",
            params,
        ).fetchall()
    return [
        {
            "submission_id": submission_id,
            "assignment_id": assignment_id,
            "version": version,
            "status": status,
            "ai_grade": ai_grade,
            "created_at": created_at,
        }
        for submission_id, assignment_id, version, status, ai_grade, created_at in rows
    ]


# In plain English: reads a submission with its full history, oldest version first. The
# student's work is shown once at the top, because every version repeats it. Returns
# None if there is no submission with that ID.
def get_submission(submission_id: UUID):
    with connect() as connection:
        rows = connection.execute(
            "SELECT assignment_id, student_name, submission_text, version, status, "
            "ai_grade, ai_reasoning, reviewer_username, feedback, created_at "
            "FROM submissions WHERE submission_id = %s ORDER BY version",
            (submission_id,),
        ).fetchall()
    if not rows:
        return None
    assignment_id, student_name, submission_text = rows[0][:3]
    return {
        "submission_id": submission_id,
        "assignment_id": assignment_id,
        "student_name": student_name,
        "submission_text": submission_text,
        "history": [
            {
                "version": version,
                "status": status,
                "ai_grade": ai_grade,
                "ai_reasoning": ai_reasoning,
                "reviewer_username": reviewer_username,
                "feedback": feedback,
                "created_at": created_at,
            }
            for (_, _, _, version, status, ai_grade, ai_reasoning,
                 reviewer_username, feedback, created_at) in rows
        ],
    }
