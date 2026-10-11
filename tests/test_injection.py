# In plain English: tests that feed text built to attack a database through every place this service
# takes text, and check that it is treated as plain text. The text is stored and read back exactly,
# never run as SQL. These tests need a real database (guarded like the other database tests).
#
# Why they exist: the code passes values to the database separately from the SQL (the %s spots),
# which is what stops SQL injection. Reading the code shows that today, but nothing would fail if a
# later change glued text into a SQL command. These tests would. They are the proof for the
# OWASP A05 Injection items in the coverage map.
import uuid

import pytest
from fastapi.testclient import TestClient

from app.db import connect
from app.main import app
from conftest import AUTH_HEADERS

pytestmark = pytest.mark.usefixtures("require_test_database")

client = TestClient(app, headers=AUTH_HEADERS)

# Text that would break or take over a SQL command if it were glued into one, plus the characters
# the database driver itself treats as placeholders (%s, %(name)s) and Python format fields.
HOSTILE = [
    "'; DROP TABLE submissions; --",
    "x' OR '1'='1",
    '" OR ""="',
    "'); DELETE FROM assignments; --",
    "Robert'); DROP TABLE assignments;--",
    "\\'; SELECT pg_sleep(5); --",
    "100% sure %s %(name)s %d",
    "{0} {student_name} {VERSION_ONE_COLUMNS} ${1}",
    "$$ ; DROP TABLE submissions ; $$",
    "’ OR ʼ1ʼ=ʼ1",
    "a\nb\r\nc'; --",
]
# The grade may be at most 20 characters, so it gets short versions of the same tricks.
HOSTILE_SHORT = ["'; DROP TABLE x;--", "x' OR '1'='1", "' OR 1=1 --", "%s %(a)s {0}", "\\'; --", "$$;DROP$$"]


def tables_exist():
    with connect() as connection:
        return all(
            connection.execute("SELECT to_regclass(%s)", (f"public.{name}",)).fetchone()[0] is not None
            for name in ("assignments", "submissions")
        )


def count(table):
    with connect() as connection:
        return connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # table name is a fixed word below


def make_assignment(**change):
    body = {"instructor_username": "instructor1", "title": f"Essay {uuid.uuid4()}", "rubric": "Grade it."}
    body.update(change)
    return client.post("/assignments", json=body)


def make_submission(assignment_id, **change):
    body = {"submission_id": str(uuid.uuid4()), "assignment_id": assignment_id, "student_name": "Alex", "submission_text": "My essay."}
    body.update(change)
    return client.post("/submissions", json=body), body["submission_id"]


# In plain English: every hostile text goes in through every text field of the whole cycle
# (assignment, submission, grade, review), comes back exactly as sent and is never run.
# The control: the same cycle with plain text works, so a refusal would mean something other than
# the hostile text broke it.
def test_hostile_text_goes_through_the_whole_cycle_and_is_read_back_exactly():
    control = make_assignment()
    assert control.status_code == 201
    for index, payload in enumerate(HOSTILE):
        short = HOSTILE_SHORT[index % len(HOSTILE_SHORT)]
        made = make_assignment(instructor_username=payload, title=f"{payload} {uuid.uuid4()}", rubric=payload)
        assert made.status_code == 201, (payload, made.text)
        assignment_id = made.json()["assignment_id"]
        read = client.get(f"/assignments/{assignment_id}").json()
        assert read["rubric"] == payload and read["instructor_username"] == payload.strip()

        reply, submission_id = make_submission(assignment_id, student_name=payload, submission_text=payload)
        assert reply.status_code == 201, (payload, reply.text)

        graded = client.post(
            f"/submissions/{submission_id}/grades",
            json={"based_on_version": 1, "ai_grade": short, "ai_reasoning": payload},
        )
        assert graded.status_code == 201, (short, payload, graded.text)

        reviewed = client.post(
            f"/submissions/{submission_id}/reviews",
            json={"based_on_version": 2, "decision": "reject", "reviewer_username": payload, "feedback": payload},
        )
        assert reviewed.status_code == 201, (payload, reviewed.text)

        found = client.get(f"/submissions/{submission_id}").json()
        assert found["student_name"] == payload.strip() and found["submission_text"] == payload
        assert [v["status"] for v in found["history"]] == ["submitted", "graded", "rejected"]
        assert found["history"][1]["ai_grade"] == short.strip() and found["history"][1]["ai_reasoning"] == payload
        assert found["history"][2]["reviewer_username"] == payload.strip() and found["history"][2]["feedback"] == payload
    assert tables_exist()


# In plain English: text that looks like a command did not run. Both tables are still there, the
# earlier rows are still there, and nothing was deleted.
def test_destructive_looking_text_does_not_destroy_anything():
    keeper = make_assignment(title=f"Keeper {uuid.uuid4()}").json()["assignment_id"]
    assert make_submission(keeper, submission_text="Keep me.")[0].status_code == 201
    before = (count("assignments"), count("submissions"))
    for payload in HOSTILE:
        assignment_id = make_assignment(title=f"{payload} {uuid.uuid4()}", rubric=payload).json()["assignment_id"]
        assert make_submission(assignment_id, student_name=payload, submission_text=payload)[0].status_code == 201
    assert tables_exist()
    after = (count("assignments"), count("submissions"))
    assert after == (before[0] + len(HOSTILE), before[1] + len(HOSTILE))


# In plain English: a "title already used" check compares the real text. An "always true" trick as a
# title is just a title: a second assignment with a different title is not blocked, and the same
# title is refused as a normal 409.
def test_a_trick_title_is_just_a_title():
    title = f"x' OR '1'='1 {uuid.uuid4()}"
    assert make_assignment(title=title).status_code == 201
    assert make_assignment(title=title).status_code == 409
    assert make_assignment(title=f"{title} other").status_code == 201


# In plain English: a list filter cannot be widened. A hostile status or limit is refused as bad input,
# and a list for one assignment never shows another assignment's submissions.
def test_hostile_filters_are_refused_and_lists_do_not_widen():
    holder = make_assignment().json()["assignment_id"]
    other = make_assignment().json()["assignment_id"]
    assert make_submission(holder, student_name="x' OR '1'='1", submission_text="x' OR '1'='1")[0].status_code == 201
    mine = client.get("/submissions", params={"status": "submitted", "assignment_id": other})
    assert mine.status_code == 200 and mine.json() == []
    for params in (
        {"status": "submitted' OR '1'='1"},
        {"status": "submitted; DROP TABLE submissions"},
        {"status": "submitted", "assignment_id": f"{other}' OR '1'='1"},
        {"status": "submitted", "limit": "1 OR 1=1"},
    ):
        reply = client.get("/submissions", params=params)
        assert reply.status_code == 422, params
        assert "DROP TABLE" not in reply.text and "OR '1'" not in reply.text
    assert client.get("/assignments", params={"limit": "1; DROP TABLE assignments"}).status_code == 422
    assert tables_exist()


# In plain English: every place that must be a real ID refuses anything else (a 422 that never repeats
# what was sent), so a command cannot be smuggled in through a path, a body or a query.
@pytest.mark.parametrize("payload", ["11111111-1111-1111-1111-111111111111' OR '1'='1", "'; DROP TABLE submissions; --", "1 OR 1=1"])
def test_ids_that_are_not_real_uuids_are_refused_without_being_repeated(payload):
    replies = [
        client.get(f"/assignments/{payload}"),
        client.get(f"/submissions/{payload}"),
        client.post(f"/submissions/{payload}/grades", json={"based_on_version": 1, "ai_grade": "A", "ai_reasoning": "r"}),
        client.post(f"/submissions/{payload}/reviews", json={"based_on_version": 2, "decision": "approve", "reviewer_username": "r"}),
        client.post("/submissions", json={"submission_id": payload, "assignment_id": payload, "student_name": "A", "submission_text": "t"}),
    ]
    for reply in replies:
        assert reply.status_code in (404, 422), (reply.status_code, reply.request.url)
        assert "DROP TABLE" not in reply.text and "OR '1'" not in reply.text
    assert tables_exist()
