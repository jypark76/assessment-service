# In plain English: this file holds everything about saving and listing graded
# examples. First come the "shapes" of the data we accept (with strict rules, so
# bad input is turned away at the door). Then come two functions that talk to
# the database: one that saves an example and one that lists them.
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from app.db import connect
from app.embeddings import embed_text


# In plain English: refuses text that Postgres cannot store. A null character
# (the invisible character with code zero) would make the database driver fail,
# and that used to come back as a 503 "try again later" that a client retries
# forever. Rejecting it here turns it into a proper 422 "bad input". Text that
# cannot be written out as UTF-8 is refused for the same reason. The messages are
# fixed wording and never quote the text.
def _must_be_storable_text(value):
    if "\x00" in value:
        raise ValueError("Text must not contain null characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Text must be valid Unicode")
    return value


# In plain English: the rules for a request to save a new example. Every field
# is required and must be plain text of a sensible size. "forbid" means any
# extra field someone sneaks in is rejected instead of silently ignored.
class NewExample(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    assignment_id: UUID
    student_work: str = Field(min_length=1, max_length=20000)
    grade: str = Field(min_length=1, max_length=100)
    reasoning: str = Field(min_length=1, max_length=5000)

    # Apply the storable-text check to all three text fields.
    _check_text = field_validator("student_work", "grade", "reasoning")(_must_be_storable_text)


# In plain English: the rules for a "find similar examples" request. We need the
# assignment to look inside, the text to compare, and optionally how many
# matches to return (1 to 10, default 3). Extra fields are rejected.
class SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    assignment_id: UUID
    query_text: str = Field(min_length=1, max_length=20000)
    limit: int = Field(default=3, ge=1, le=10)

    # Off unless the caller turns it on. When on, an assignment with no examples of its
    # own may borrow similar examples from every other assignment. It must be a real
    # true or false, so a word or number that only looks like true cannot switch it on.
    fallback_to_all: StrictBool = False

    # The text to compare gets the same storable-text check.
    _check_text = field_validator("query_text")(_must_be_storable_text)


# In plain English: turns the 384 numbers into the text form the database
# understands, like "[0.1,0.2,...]". The database then reads it as a vector.
def _vector_text(numbers):
    return "[" + ",".join(str(number) for number in numbers) + "]"


# In plain English: saves one new example. It first works out the 384 meaning
# numbers from the student's work, then adds ONE new row. It never changes or
# removes existing rows. The values are handed over separately from the SQL
# (the %s spots), so nothing typed by a user can ever become part of the SQL
# command itself. Returns the id of the new row.
def save_example(example):
    embedding = _vector_text(embed_text(example.student_work))
    with connect() as connection:
        row = connection.execute(
            "INSERT INTO examples "
            "(assignment_id, student_work, grade, reasoning, embedding) "
            "VALUES (%s, %s, %s, %s, %s::vector) RETURNING example_id",
            (
                example.assignment_id,
                example.student_work,
                example.grade,
                example.reasoning,
                embedding,
            ),
        ).fetchone()
    return str(row[0])


# In plain English: lists the saved examples for one assignment, newest first,
# up to 100. The 384 meaning numbers are left out because callers have no use
# for them. This only reads; it changes nothing.
def list_examples(assignment_id):
    with connect() as connection:
        rows = connection.execute(
            "SELECT example_id, assignment_id, student_work, grade, reasoning, "
            "created_at FROM examples WHERE assignment_id = %s "
            "ORDER BY created_at DESC LIMIT 100",
            (assignment_id,),
        ).fetchall()
    return [
        {
            "example_id": str(row[0]),
            "assignment_id": str(row[1]),
            "student_work": row[2],
            "grade": row[3],
            "reasoning": row[4],
            "created_at": row[5].isoformat(),
        }
        for row in rows
    ]


# In plain English: finds the saved examples whose MEANING is closest to the given
# text. It turns the text into 384 numbers, then lets the database rank saved
# examples by how close their numbers are ("cosine distance", using the fast
# index). Each result gets a similarity score: 1 means practically identical, lower
# means less alike. This only reads; it changes nothing.
#
# Where it looks depends on one quick question: "does this assignment have any
# examples of its own?"
#   - Yes: it searches ONLY inside that assignment. Its own examples always win, even
#     if another assignment holds one that sounds closer. Results are flagged
#     same_assignment = true.
#   - No, and the caller asked to borrow (fallback_to_all = true): it searches across
#     ALL assignments, so a brand-new assignment still gets something to learn from.
#     Results are flagged same_assignment = false and carry their own assignment_id, so
#     the grader can say they came from a different assignment.
#   - No, and the caller did not ask to borrow: it returns nothing, so a typo or a
#     made-up ID does not read other assignments' work by accident. This guards
#     against accidents, not against a caller who wants the data: the flag travels in
#     the same unauthenticated request, so such a caller can simply set it. The
#     service cannot tell a real new assignment from a made-up ID, because the
#     assessment service owns the list of assignments, so the CALLER says when
#     borrowing is wanted. Real protection needs authentication, or a check that the
#     assignment exists.
#
# The fast index only looks at about 40 candidates from ALL assignments and filters
# afterwards, so a small assignment surrounded by closer rows from other assignments
# could come back with too few results. The first statement switches on pgvector's
# "keep looking until enough rows pass the filter" mode (iterative scan) for this
# one transaction. That fixes the common case. It still stops after pgvector's scan
# limit (hnsw.max_scan_tuples, 20000 rows by default), so a small assignment hidden
# behind tens of thousands of closer rows from other assignments could still come
# back short. If that ever matters: raise the limit, rank inside one assignment
# exactly (filter first, then sort), or split the table by assignment.
def search_examples(request):
    embedding = _vector_text(embed_text(request.query_text))
    with connect() as connection:
        connection.execute("SET LOCAL hnsw.iterative_scan = strict_order")
        has_examples = connection.execute(
            "SELECT EXISTS (SELECT 1 FROM examples WHERE assignment_id = %s)",
            (request.assignment_id,),
        ).fetchone()[0]
        if has_examples:
            rows = connection.execute(
                "SELECT example_id, assignment_id, student_work, grade, reasoning, "
                "1 - (embedding <=> %s::vector) AS similarity "
                "FROM examples WHERE assignment_id = %s "
                "ORDER BY embedding <=> %s::vector LIMIT %s",
                (embedding, request.assignment_id, embedding, request.limit),
            ).fetchall()
        elif request.fallback_to_all:
            rows = connection.execute(
                "SELECT example_id, assignment_id, student_work, grade, reasoning, "
                "1 - (embedding <=> %s::vector) AS similarity "
                "FROM examples "
                "ORDER BY embedding <=> %s::vector LIMIT %s",
                (embedding, embedding, request.limit),
            ).fetchall()
        else:
            rows = []
    return [
        {
            "example_id": str(row[0]),
            "assignment_id": str(row[1]),
            "same_assignment": has_examples,
            "student_work": row[2],
            "grade": row[3],
            "reasoning": row[4],
            "similarity": round(float(row[5]), 4),
        }
        for row in rows
    ]
