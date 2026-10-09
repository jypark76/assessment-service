# In plain English: this file holds everything about assignments. It has the rules a new
# assignment must follow, and the three things the service can do with them: add one,
# read one, and list the newest ones. The routes in main.py are thin and call these.
from uuid import UUID, uuid4

import psycopg
from pydantic import BaseModel, ConfigDict, field_validator

from app.db import connect
from app.text_rules import must_be_storable_text, trimmed

INSTRUCTOR_MAX = 100
TITLE_MAX = 200
RUBRIC_MAX = 10_000


# In plain English: raised when the title is already in use. The route turns it into a
# plain "conflict" reply.
class TitleInUse(Exception):
    pass


# In plain English: what a caller must send to create an assignment. Anything extra is
# refused, so a misspelled field is caught instead of silently ignored. The title and
# instructor name are trimmed. The rubric is stored exactly as written, but it cannot
# be blank or longer than 10,000 characters.
class NewAssignment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instructor_username: str
    title: str
    rubric: str

    @field_validator("instructor_username")
    @classmethod
    def instructor_rules(cls, value):
        return trimmed(value, INSTRUCTOR_MAX)

    @field_validator("title")
    @classmethod
    def title_rules(cls, value):
        return trimmed(value, TITLE_MAX)

    @field_validator("rubric")
    @classmethod
    def rubric_rules(cls, value):
        must_be_storable_text(value)
        if not value.strip() or len(value) > RUBRIC_MAX:
            raise ValueError(f"Must be 1 to {RUBRIC_MAX} characters and not blank")
        return value


# In plain English: turns one database row into the reply a caller sees.
def _full(row):
    assignment_id, instructor_username, title, rubric, created_at = row
    return {
        "assignment_id": assignment_id,
        "instructor_username": instructor_username,
        "title": title,
        "rubric": rubric,
        "created_at": created_at,
    }


# In plain English: saves a new assignment under a fresh ID and returns it. If the
# title is already in use (the database compares it without capital letters or outer
# spaces), it raises TitleInUse and saves nothing.
def create_assignment(new):
    try:
        with connect() as connection:
            row = connection.execute(
                "INSERT INTO assignments (assignment_id, instructor_username, title, rubric) "
                "VALUES (%s, %s, %s, %s) "
                "RETURNING assignment_id, instructor_username, title, rubric, created_at",
                (uuid4(), new.instructor_username, new.title, new.rubric),
            ).fetchone()
    except psycopg.errors.UniqueViolation:
        raise TitleInUse() from None
    return _full(row)


# In plain English: reads one assignment, rubric included. Returns None if there is no
# assignment with that ID.
def get_assignment(assignment_id: UUID):
    with connect() as connection:
        row = connection.execute(
            "SELECT assignment_id, instructor_username, title, rubric, created_at "
            "FROM assignments WHERE assignment_id = %s",
            (assignment_id,),
        ).fetchone()
    return _full(row) if row else None


# In plain English: lists the newest assignments first, up to the limit. The rubric is
# left out because it can be long, and a list only needs enough to pick one.
def list_assignments(limit: int):
    with connect() as connection:
        rows = connection.execute(
            "SELECT assignment_id, instructor_username, title, created_at "
            "FROM assignments ORDER BY created_at DESC, assignment_id DESC LIMIT %s",
            (limit,),
        ).fetchall()
    return [
        {
            "assignment_id": assignment_id,
            "instructor_username": instructor_username,
            "title": title,
            "created_at": created_at,
        }
        for assignment_id, instructor_username, title, created_at in rows
    ]
