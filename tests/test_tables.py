# In plain English: these tests check the two tables and their rules against a real
# Postgres, as the service's own limited login. They cover three things:
#   1. a normal history goes in: an assignment, then a submission that is graded,
#      rejected, graded again and approved, each step a NEW row;
#   2. every rule is enforced by the database itself, not by code that could be
#      skipped: unique titles, the fields each status must carry, one approval per
#      submission, one row per version, and every version repeating the name, text and
#      assignment of version 1;
#   3. the login can only READ and ADD: changing or deleting rows is refused.
#
# Every refusal is paired with a control: the same step done correctly must work. So a
# refusal can only mean "the rule works", never "the table is missing".
import uuid

import psycopg
import pytest

from app.db import connect

pytestmark = pytest.mark.usefixtures("require_test_database")


def new_id():
    return uuid.uuid4()


# In plain English: runs one statement on its own connection. If it succeeds the change
# is saved. If it is refused, the connection is rolled back and closed, so one refusal
# never spoils the next step.
def run(sql, params=()):
    with connect() as connection:
        connection.execute(sql, params)


# In plain English: runs one query and returns its rows.
def rows(sql, params=()):
    with connect() as connection:
        return connection.execute(sql, params).fetchall()


# In plain English: adds an assignment and returns its ID. Titles must be unique, so
# each one gets a random title unless the test passes one. An empty title counts as
# "passed", so a test can check that it is refused.
def add_assignment(title=None, rubric="Grade for clarity and evidence."):
    assignment_id = new_id()
    run(
        "INSERT INTO assignments (assignment_id, instructor_username, title, rubric) "
        "VALUES (%s, %s, %s, %s)",
        (assignment_id, "instructor1",
         title if title is not None else f"Essay {assignment_id}", rubric),
    )
    return assignment_id


# In plain English: adds one version row of a submission. Every column a status might
# need can be passed in, and everything else stays empty.
def add_version(submission_id, version, assignment_id, status, name="Alex",
                text="The essay text.", grade=None, reasoning=None,
                reviewer=None, feedback=None):
    run(
        "INSERT INTO submissions (submission_id, version, assignment_id, status, "
        "student_name, submission_text, ai_grade, ai_reasoning, reviewer_username, feedback) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (submission_id, version, assignment_id, status, name, text,
         grade, reasoning, reviewer, feedback),
    )


# In plain English: starts a submission (version 1) and returns its ID.
def start_submission(assignment_id, **details):
    submission_id = new_id()
    add_version(submission_id, 1, assignment_id, "submitted", **details)
    return submission_id


# In plain English: a graded version, with the grade and reasoning filled in.
def add_graded(submission_id, version, assignment_id, **details):
    add_version(submission_id, version, assignment_id, "graded",
                grade="B", reasoning="Clear but short.", **details)


# ---------------------------------------------------------------------------
# 1. A normal history goes in
# ---------------------------------------------------------------------------


# In plain English: the whole life of a submission, one new row per step, then read back
# in order. Review rows carry the grade and reasoning they are reviewing, so the newest
# row is a complete picture of the submission.
def test_a_full_history_goes_in_and_reads_back_in_order():
    assignment_id = add_assignment()
    submission_id = start_submission(assignment_id)
    add_graded(submission_id, 2, assignment_id)
    add_version(submission_id, 3, assignment_id, "rejected", grade="B",
                reasoning="Clear but short.", reviewer="instructor1", feedback="Tighten the thesis.")
    add_graded(submission_id, 4, assignment_id)
    add_version(submission_id, 5, assignment_id, "approved", grade="B",
                reasoning="Clear but short.", reviewer="instructor1")

    history = rows(
        "SELECT version, status FROM submissions WHERE submission_id = %s ORDER BY version",
        (submission_id,),
    )
    assert history == [(1, "submitted"), (2, "graded"), (3, "rejected"), (4, "graded"), (5, "approved")]


# ---------------------------------------------------------------------------
# 2. The rules the database enforces
# ---------------------------------------------------------------------------


# In plain English: titles are unique across the whole system. The second use of a title
# is refused, even from a different instructor's request.
def test_a_duplicate_assignment_title_is_refused():
    title = f"Unique title {new_id()}"
    add_assignment(title=title)

    with pytest.raises(psycopg.errors.UniqueViolation):
        add_assignment(title=title)


# In plain English: a title must be between 1 and 200 characters once spaces are trimmed,
# and the rubric must not be blank. The boundary of 200 is accepted as the control.
def test_title_and_rubric_limits():
    # A random start keeps the title unique on every run, because the login cannot
    # delete rows left behind by an earlier run.
    add_assignment(title=(str(new_id()) + "t" * 200)[:200])

    for bad_title in ("", "   ", "t" * 201):
        with pytest.raises(psycopg.errors.CheckViolation):
            add_assignment(title=bad_title)
    with pytest.raises(psycopg.errors.CheckViolation):
        add_assignment(rubric="   ")


# In plain English: a submission must belong to a real assignment.
def test_a_submission_needs_a_real_assignment():
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        start_submission(new_id())


# In plain English: version 1 is always "submitted" and later versions never are. Each
# refusal has its control: the correct row goes in.
def test_version_one_is_submitted_and_later_versions_are_not():
    assignment_id = add_assignment()
    submission_id = start_submission(assignment_id)
    add_graded(submission_id, 2, assignment_id)

    other = new_id()
    with pytest.raises(psycopg.errors.CheckViolation):
        add_version(other, 1, assignment_id, "graded", grade="B", reasoning="x")
    with pytest.raises(psycopg.errors.CheckViolation):
        add_version(submission_id, 3, assignment_id, "submitted")


# In plain English: each status must carry exactly the fields it needs. A graded row
# needs a grade and reasoning, a rejected row needs a reviewer and feedback, an approved
# row needs a reviewer, and a submitted row carries none of them. Every wrong row is
# refused, and the matching correct row (the control) is accepted.
def test_each_status_must_carry_its_own_fields():
    assignment_id = add_assignment()

    def fresh():
        submission_id = start_submission(assignment_id)
        add_graded(submission_id, 2, assignment_id)
        return submission_id

    # controls: the correct rejected and approved rows go in
    add_version(fresh(), 3, assignment_id, "rejected", grade="B", reasoning="x",
                reviewer="instructor1", feedback="Needs work.")
    add_version(fresh(), 3, assignment_id, "approved", grade="B", reasoning="x",
                reviewer="instructor1")

    # a graded row without a grade
    with pytest.raises(psycopg.errors.CheckViolation):
        add_version(fresh(), 3, assignment_id, "graded", grade=None, reasoning="x")
    # a rejected row without feedback
    with pytest.raises(psycopg.errors.CheckViolation):
        add_version(fresh(), 3, assignment_id, "rejected", grade="B", reasoning="x",
                    reviewer="instructor1", feedback=None)
    # an approved row without a reviewer
    with pytest.raises(psycopg.errors.CheckViolation):
        add_version(fresh(), 3, assignment_id, "approved", grade="B", reasoning="x", reviewer=None)
    # a submitted row that already carries a grade
    with pytest.raises(psycopg.errors.CheckViolation):
        add_version(new_id(), 1, assignment_id, "submitted", grade="A", reasoning="x")


# In plain English: a submission has one row per version number. Reusing a number is
# refused.
def test_a_version_number_cannot_be_reused():
    assignment_id = add_assignment()
    submission_id = start_submission(assignment_id)
    add_graded(submission_id, 2, assignment_id)

    with pytest.raises(psycopg.errors.UniqueViolation):
        add_graded(submission_id, 2, assignment_id)


# In plain English: at most one approved row per submission. The first approval goes
# in (the control) and a second one is refused.
def test_only_one_approval_per_submission():
    assignment_id = add_assignment()
    submission_id = start_submission(assignment_id)
    add_graded(submission_id, 2, assignment_id)
    add_version(submission_id, 3, assignment_id, "approved", grade="B", reasoning="x",
                reviewer="instructor1")

    with pytest.raises(psycopg.errors.UniqueViolation):
        add_version(submission_id, 4, assignment_id, "approved", grade="B", reasoning="x",
                    reviewer="instructor2")


# In plain English: the guard. Every later version must repeat the student's name, the
# text and the assignment of version 1, so nobody can quietly change what was graded.
# The control is a version 2 with the original values, which goes in. Then a changed
# text, a changed name and a changed assignment are each refused.
def test_a_later_version_cannot_change_what_was_submitted():
    assignment_id = add_assignment()
    other_assignment = add_assignment()
    submission_id = start_submission(assignment_id, name="Alex", text="The original essay.")

    add_graded(submission_id, 2, assignment_id, name="Alex", text="The original essay.")

    with pytest.raises(psycopg.errors.IntegrityError):
        add_graded(submission_id, 3, assignment_id, name="Alex", text="A different essay.")
    with pytest.raises(psycopg.errors.IntegrityError):
        add_graded(submission_id, 3, assignment_id, name="Blake", text="The original essay.")
    with pytest.raises(psycopg.errors.IntegrityError):
        add_graded(submission_id, 3, other_assignment, name="Alex", text="The original essay.")


# In plain English: a long essay still works. The guard must handle text far longer than
# a database index normally allows, so this stores a 20,000 character submission and a
# matching version 2. It also checks the text length limits: blank text is refused.
def test_a_twenty_thousand_character_essay_works_and_blank_text_does_not():
    assignment_id = add_assignment()
    long_text = "word " * 4000
    submission_id = start_submission(assignment_id, text=long_text)
    add_graded(submission_id, 2, assignment_id, text=long_text)

    with pytest.raises(psycopg.errors.CheckViolation):
        start_submission(assignment_id, text="   ")


# ---------------------------------------------------------------------------
# 3. The login can only read and add
# ---------------------------------------------------------------------------


# In plain English: reading works (the control), and changing or deleting rows is refused
# on both tables, as is emptying them.
def test_the_login_cannot_change_or_delete_rows():
    assignment_id = add_assignment()
    submission_id = start_submission(assignment_id)
    assert rows("SELECT title FROM assignments WHERE assignment_id = %s", (assignment_id,))
    assert rows("SELECT status FROM submissions WHERE submission_id = %s", (submission_id,))

    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        run("UPDATE assignments SET rubric = 'changed' WHERE assignment_id = %s", (assignment_id,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        run("DELETE FROM assignments WHERE assignment_id = %s", (assignment_id,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        run("UPDATE submissions SET student_name = 'changed' WHERE submission_id = %s", (submission_id,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        run("DELETE FROM submissions WHERE submission_id = %s", (submission_id,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        run("TRUNCATE submissions")
