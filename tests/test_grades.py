# In plain English: these tests check the route that records a grade, from the outside,
# against the real app and a real Postgres. Recording a grade adds a NEW version row to
# a submission with the status "graded". Nothing is ever edited. The tests cover:
#   1. a grade goes in as the next version and shows up in the history;
#   2. a retry (same version graded, same grade) is harmless, and a different grade for
#      a version that already has one is refused, so two workers can never both win;
#   3. only a submission that is waiting for a grade can be graded: a new one, or one an
#      instructor rejected. One already graded, or approved, is refused;
#   4. unknown submissions and out-of-date versions are refused;
#   5. bad input is refused with the field and the reason, and never the value sent;
#   6. the route accepts nothing but POST.
#
# The API cannot create "rejected" or "approved" rows yet (the instructor's review comes
# in a later step), so the tests that need them add those rows straight into the test
# database, the same way tests/test_tables.py does.
#
# Every refusal is paired with a control: the same request done correctly must work.
# Bad values carry the marker SECRET-MARKER, and no reply may ever contain it.
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.db import connect
from app.main import app

pytestmark = pytest.mark.usefixtures("require_test_database")

client = TestClient(app)

JSON_HEADERS = {"Content-Type": "application/json"}
NOT_WAITING = {"problem": "This submission is not waiting for a grade"}
MOVED_ON = {"problem": "This submission has changed since that version"}


# In plain English: creates a real assignment and a submission (version 1) through the
# API and returns the submission ID, so there is something to grade.
def new_submission():
    assignment = client.post(
        "/assignments",
        json={
            "instructor_username": "instructor1",
            "title": f"Essay {uuid.uuid4()}",
            "rubric": "Grade for clarity and evidence.",
        },
    )
    assert assignment.status_code == 201
    submission_id = str(uuid.uuid4())
    created = client.post(
        "/submissions",
        json={
            "submission_id": submission_id,
            "assignment_id": assignment.json()["assignment_id"],
            "student_name": "Alex",
            "submission_text": "The original essay.",
        },
    )
    assert created.status_code == 201
    return submission_id


# In plain English: a correct grade body. Tests change single fields.
def grade_body(**changes):
    body = {"based_on_version": 1, "ai_grade": "B", "ai_reasoning": "Clear but short."}
    body.update(changes)
    return body


def post_grade(submission_id, **changes):
    return client.post(f"/submissions/{submission_id}/grades", json=grade_body(**changes))


def history_of(submission_id):
    return client.get(f"/submissions/{submission_id}").json()["history"]


# In plain English: the names of the fields a refusal points at, in order.
def fields_of(response):
    return [problem["field"] for problem in response.json()["problems"]]


# In plain English: adds a version row straight into the database, the way an
# instructor's review will later. It copies the student's work from version 1, so the
# database's guard is satisfied. This is only for setting up a state the API cannot reach
# yet.
def seed_version(submission_id, version, status, reviewer=None, feedback=None):
    with connect() as connection:
        connection.execute(
            "INSERT INTO submissions (submission_id, version, assignment_id, status, "
            "student_name, submission_text, ai_grade, ai_reasoning, reviewer_username, feedback) "
            "SELECT submission_id, %s, assignment_id, %s, student_name, submission_text, "
            "'B', 'Seeded for the test.', %s, %s "
            "FROM submissions WHERE submission_id = %s AND version = 1",
            (version, status, reviewer, feedback, submission_id),
        )


# ---------------------------------------------------------------------------
# 1. A grade goes in
# ---------------------------------------------------------------------------


# In plain English: a grade goes in as version 2 with the status "graded", and the
# history shows both versions in order. Version 1 keeps no grade, and the student's work
# at the top of the submission is unchanged.
def test_a_grade_goes_in_as_the_next_version():
    submission_id = new_submission()

    response = post_grade(submission_id)
    assert response.status_code == 201
    data = response.json()
    assert data["submission_id"] == submission_id
    assert data["version"] == 2
    assert data["status"] == "graded"
    assert data["ai_grade"] == "B"
    assert data["ai_reasoning"] == "Clear but short."
    assert data["created_at"]

    work = client.get(f"/submissions/{submission_id}").json()
    assert work["student_name"] == "Alex"
    assert work["submission_text"] == "The original essay."
    history = work["history"]
    assert [(entry["version"], entry["status"]) for entry in history] == [(1, "submitted"), (2, "graded")]
    assert history[0]["ai_grade"] is None
    assert history[1]["ai_grade"] == "B"
    assert history[1]["ai_reasoning"] == "Clear but short."


# ---------------------------------------------------------------------------
# 2. Retries and clashes
# ---------------------------------------------------------------------------


# In plain English: sending the same grade again for the same version (a worker that
# crashed after saving and tries again) returns the saved grade with a 200 and adds
# nothing. The retry has the grade with spaces around it, which counts as the same. The
# first send is the control and answers 201.
def test_a_retry_returns_the_saved_grade_and_adds_nothing():
    submission_id = new_submission()
    first = post_grade(submission_id)
    assert first.status_code == 201

    retry = post_grade(submission_id, ai_grade=" B ")
    assert retry.status_code == 200
    assert retry.json() == first.json()
    assert len(history_of(submission_id)) == 2


# In plain English: a different grade for a version that already has one is refused and
# changes nothing. This is what stops two workers on the same submission from both
# winning. The first grade is the control.
def test_a_different_grade_for_an_already_graded_version_is_refused():
    submission_id = new_submission()
    assert post_grade(submission_id).status_code == 201

    for change in ({"ai_grade": "A"}, {"ai_reasoning": "SECRET-MARKER a different view."}):
        response = post_grade(submission_id, **change)
        assert response.status_code == 409, change
        assert response.json() == MOVED_ON
        assert "SECRET-MARKER" not in response.text

    history = history_of(submission_id)
    assert len(history) == 2
    assert history[1]["ai_grade"] == "B"
    assert history[1]["ai_reasoning"] == "Clear but short."


# ---------------------------------------------------------------------------
# 3. Which states can be graded
# ---------------------------------------------------------------------------


# In plain English: a submission that has a grade and is waiting for review cannot be
# graded again, and neither can an approved one, because approval is final. The reply is
# fixed wording and nothing is added. The first grade is the control.
def test_a_graded_or_approved_submission_cannot_be_graded():
    waiting = new_submission()
    assert post_grade(waiting).status_code == 201
    response = post_grade(waiting, based_on_version=2, ai_grade="A")
    assert response.status_code == 409
    assert response.json() == NOT_WAITING
    assert len(history_of(waiting)) == 2

    approved = new_submission()
    assert post_grade(approved).status_code == 201
    seed_version(approved, 3, "approved", reviewer="instructor1")
    response = post_grade(approved, based_on_version=3, ai_grade="A")
    assert response.status_code == 409
    assert response.json() == NOT_WAITING
    assert len(history_of(approved)) == 3


# In plain English: after an instructor rejects a grade, the submission can be graded
# again. That gives the cycle submitted, graded, rejected, graded.
def test_a_rejected_submission_can_be_graded_again():
    submission_id = new_submission()
    assert post_grade(submission_id).status_code == 201
    seed_version(submission_id, 3, "rejected", reviewer="instructor1", feedback="Tighten the thesis.")

    response = post_grade(submission_id, based_on_version=3, ai_grade="A", ai_reasoning="Better.")
    assert response.status_code == 201
    assert response.json()["version"] == 4
    assert [entry["status"] for entry in history_of(submission_id)] == [
        "submitted", "graded", "rejected", "graded",
    ]


# ---------------------------------------------------------------------------
# 4. Not found and out of date
# ---------------------------------------------------------------------------


# In plain English: grading a submission nobody created gives "not found" and the reply
# does not repeat the ID. Grading a version that does not exist yet gives the "changed"
# answer and adds nothing. A correct grade is the control and works.
def test_unknown_submissions_and_out_of_date_versions_are_refused():
    assert post_grade(new_submission()).status_code == 201

    unknown = str(uuid.uuid4())
    response = post_grade(unknown)
    assert response.status_code == 404
    assert response.json() == {"problem": "Submission not found"}
    assert unknown not in response.text

    submission_id = new_submission()
    response = post_grade(submission_id, based_on_version=5)
    assert response.status_code == 409
    assert response.json() == MOVED_ON
    assert len(history_of(submission_id)) == 1


# ---------------------------------------------------------------------------
# 5. Bad input
# ---------------------------------------------------------------------------


# In plain English: each bad request is refused with 422 naming only the field. The
# marker inside the bad value must never come back, and neither may the name of an
# invented field. The bad requests go to a fresh submission, so if a rule were missing
# the request would reach the database and the history would change. A correct request
# on another submission is the control.
def test_bad_input_names_the_field_and_never_the_value():
    assert post_grade(new_submission()).status_code == 201

    submission_id = new_submission()
    cases = [
        ({"ai_grade": "   "}, "body.ai_grade"),
        ({"ai_grade": "SECRET-MARKER-" + "g" * 20}, "body.ai_grade"),
        ({"ai_grade": 5}, "body.ai_grade"),
        ({"ai_reasoning": "   "}, "body.ai_reasoning"),
        ({"ai_reasoning": "SECRET-MARKER-" + "x" * 10_000}, "body.ai_reasoning"),
        ({"based_on_version": 0}, "body.based_on_version"),
        ({"based_on_version": "SECRET-MARKER"}, "body.based_on_version"),
    ]
    for change, expected_field in cases:
        response = post_grade(submission_id, **change)
        assert response.status_code == 422, change
        assert fields_of(response) == [expected_field]
        assert "SECRET-MARKER" not in response.text

    missing = grade_body()
    del missing["ai_grade"]
    response = client.post(f"/submissions/{submission_id}/grades", json=missing)
    assert response.status_code == 422
    assert fields_of(response) == ["body.ai_grade"]

    invented = grade_body()
    invented["SECRET-MARKER-12345"] = "x"
    response = client.post(f"/submissions/{submission_id}/grades", json=invented)
    assert response.status_code == 422
    assert fields_of(response) == ["body"]
    assert "SECRET-MARKER" not in response.text

    garbage = client.post("/submissions/SECRET-MARKER-12345/grades", json=grade_body())
    assert garbage.status_code == 422
    assert "SECRET-MARKER" not in garbage.text

    assert len(history_of(submission_id)) == 1


# In plain English: the limits are exact. A 20 character grade and a 10,000 character
# reasoning are accepted, which shows the refusals above come from the limits and not
# from something else.
def test_the_limits_are_exact():
    response = post_grade(new_submission(), ai_grade="g" * 20, ai_reasoning="r" * 10_000)
    assert response.status_code == 201


# In plain English: text the database cannot store is refused as bad input, not left to
# fail inside the database as a 500. That means a null character and a lone surrogate
# (half of a pair, which cannot be written out as UTF-8). Both are tried in the grade and
# the reasoning. The reply names the field only and never repeats the text. The body is
# sent as escaped JSON text so the test client never has to encode the bad characters
# itself. A request with clean text first is the control.
def test_text_the_database_cannot_store_is_refused_in_both_text_fields():
    assert post_grade(new_submission()).status_code == 201

    submission_id = new_submission()
    for field in ("ai_grade", "ai_reasoning"):
        for bad_text in ("SECRET-MARKER\u0000abc", "SECRET-MARKER\ud800abc"):
            response = client.post(
                f"/submissions/{submission_id}/grades",
                content=json.dumps(grade_body(**{field: bad_text})),
                headers=JSON_HEADERS,
            )
            assert response.status_code == 422, (field, bad_text)
            assert fields_of(response) == [f"body.{field}"]
            assert "SECRET-MARKER" not in response.text


# ---------------------------------------------------------------------------
# 6. Nothing but POST
# ---------------------------------------------------------------------------


# In plain English: the grades route only accepts POST. Reading, replacing, patching and
# deleting are all turned away with "method not allowed". A POST is the control and works.
def test_the_grades_route_accepts_nothing_but_post():
    submission_id = new_submission()
    assert post_grade(submission_id).status_code == 201
    url = f"/submissions/{submission_id}/grades"

    assert client.get(url).status_code == 405
    assert client.put(url, json=grade_body()).status_code == 405
    assert client.patch(url, json=grade_body()).status_code == 405
    assert client.delete(url).status_code == 405
