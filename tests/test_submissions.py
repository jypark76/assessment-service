# In plain English: these tests check the submission routes of the service from the
# outside, the way a caller would use them, against the real app and a real Postgres.
# A submission here is only version 1, the student's work. Grades and reviews come in
# later steps and will add more versions. The tests cover:
#   1. sending a submission in and reading it back, with its history;
#   2. a retry with the same ID is harmless, and the same ID with different content is
#      refused, so a double click can never create two submissions or change one;
#   3. an unknown assignment or submission gives "not found";
#   4. bad input is refused with the field and the reason, and never the value sent;
#   5. duplicates are allowed under different IDs (two students, or one student twice);
#   6. the API has no way to change or remove a submission.
#
# Every refusal is paired with a control: the same request done correctly must work.
# Bad values carry the marker SECRET-MARKER, and no reply may ever contain it.
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app

pytestmark = pytest.mark.usefixtures("require_test_database")

client = TestClient(app)

JSON_HEADERS = {"Content-Type": "application/json"}


# In plain English: creates a real assignment through the API and returns its ID, so a
# submission has something to belong to.
def new_assignment():
    response = client.post(
        "/assignments",
        json={
            "instructor_username": "instructor1",
            "title": f"Essay {uuid.uuid4()}",
            "rubric": "Grade for clarity and evidence.",
        },
    )
    assert response.status_code == 201
    return response.json()["assignment_id"]


# In plain English: a correct submission body. The caller picks the submission ID, which
# is also the request ID that makes a retry harmless. Tests change single fields.
def good_body(for_assignment, **changes):
    body = {
        "submission_id": str(uuid.uuid4()),
        "assignment_id": for_assignment,
        "student_name": "Alex",
        "submission_text": "The original essay.",
    }
    body.update(changes)
    return body


def submit(body):
    return client.post("/submissions", json=body)


# In plain English: the names of the fields a refusal points at, in order.
def fields_of(response):
    return [problem["field"] for problem in response.json()["problems"]]


# ---------------------------------------------------------------------------
# 1. Send in and read back
# ---------------------------------------------------------------------------


# In plain English: a submission goes in as version 1 with the status "submitted", and
# reading it back shows the student's work and a history with exactly that one entry.
# The grade and review fields in the history are empty because nothing has graded it.
def test_submit_then_read_back():
    assignment_id = new_assignment()
    body = good_body(assignment_id)

    created = submit(body)
    assert created.status_code == 201
    data = created.json()
    assert data["submission_id"] == body["submission_id"]
    assert data["assignment_id"] == assignment_id
    assert data["student_name"] == "Alex"
    assert data["submission_text"] == "The original essay."
    assert data["version"] == 1
    assert data["status"] == "submitted"
    assert data["created_at"]

    fetched = client.get(f"/submissions/{body['submission_id']}")
    assert fetched.status_code == 200
    work = fetched.json()
    assert work["submission_id"] == body["submission_id"]
    assert work["assignment_id"] == assignment_id
    assert work["student_name"] == "Alex"
    assert work["submission_text"] == "The original essay."
    assert len(work["history"]) == 1
    first = work["history"][0]
    assert first["version"] == 1
    assert first["status"] == "submitted"
    assert first["created_at"]
    for empty in ("ai_grade", "ai_reasoning", "reviewer_username", "feedback"):
        assert first[empty] is None


# ---------------------------------------------------------------------------
# 2. Retries and clashes
# ---------------------------------------------------------------------------


# In plain English: sending the same submission again (a double click, or a retry after a
# timeout) returns the original with a 200 and creates nothing new. The retry here has
# the name without the spaces the first had, which counts as the same content. The first
# send is the control and answers 201.
def test_a_retry_with_the_same_id_and_content_returns_the_original():
    assignment_id = new_assignment()
    body = good_body(assignment_id, student_name="  Alex  ")

    first = submit(body)
    assert first.status_code == 201

    retry = submit({**body, "student_name": "Alex"})
    assert retry.status_code == 200
    assert retry.json() == first.json()

    fetched = client.get(f"/submissions/{body['submission_id']}")
    assert len(fetched.json()["history"]) == 1


# In plain English: the same ID with different content is refused with fixed wording that
# repeats none of it, and the original stays exactly as it was. A changed essay, a
# changed name and a changed assignment are each tried. The first send is the control.
def test_the_same_id_with_different_content_is_refused_and_changes_nothing():
    assignment_id = new_assignment()
    other_assignment = new_assignment()
    body = good_body(assignment_id)
    assert submit(body).status_code == 201

    changes = [
        {"submission_text": "SECRET-MARKER a different essay."},
        {"student_name": "SECRET-MARKER Blake"},
        {"assignment_id": other_assignment},
    ]
    for change in changes:
        response = submit({**body, **change})
        assert response.status_code == 409, change
        assert response.json() == {
            "problem": "This submission ID is already used for different content"
        }
        assert "SECRET-MARKER" not in response.text
        assert other_assignment not in response.text

    fetched = client.get(f"/submissions/{body['submission_id']}").json()
    assert fetched["assignment_id"] == assignment_id
    assert fetched["student_name"] == "Alex"
    assert fetched["submission_text"] == "The original essay."
    assert len(fetched["history"]) == 1


# ---------------------------------------------------------------------------
# 3. Not found
# ---------------------------------------------------------------------------


# In plain English: a submission for an assignment nobody created is refused with "not
# found", the reply does not repeat the assignment ID, and nothing is stored. The same
# submission for a real assignment is the control and works.
def test_a_submission_for_an_unknown_assignment_is_not_found():
    assert submit(good_body(new_assignment())).status_code == 201

    unknown = str(uuid.uuid4())
    body = good_body(unknown)
    response = submit(body)
    assert response.status_code == 404
    assert response.json() == {"problem": "Assignment not found"}
    assert unknown not in response.text

    assert client.get(f"/submissions/{body['submission_id']}").status_code == 404


# In plain English: reading a submission nobody created gives "not found" and the reply
# does not repeat the ID. An ID that is not a UUID at all is refused as bad input. A real
# submission is the control and works.
def test_reading_an_unknown_submission_is_not_found():
    body = good_body(new_assignment())
    assert submit(body).status_code == 201
    assert client.get(f"/submissions/{body['submission_id']}").status_code == 200

    unknown = str(uuid.uuid4())
    response = client.get(f"/submissions/{unknown}")
    assert response.status_code == 404
    assert unknown not in response.text

    garbage = client.get("/submissions/SECRET-MARKER-12345")
    assert garbage.status_code == 422
    assert "SECRET-MARKER" not in garbage.text


# ---------------------------------------------------------------------------
# 4. Bad input
# ---------------------------------------------------------------------------


# In plain English: each bad request is refused with 422 naming only the field. The
# marker inside the bad value must never come back, and neither may the name of an
# invented field. The correct request first is the control and works.
def test_bad_input_names_the_field_and_never_the_value():
    assignment_id = new_assignment()
    assert submit(good_body(assignment_id)).status_code == 201

    cases = [
        ({"student_name": "   "}, "body.student_name"),
        ({"student_name": "SECRET-MARKER-" + "n" * 200}, "body.student_name"),
        ({"student_name": 12345}, "body.student_name"),
        ({"submission_text": "   "}, "body.submission_text"),
        ({"submission_text": "SECRET-MARKER-" + "x" * 20_000}, "body.submission_text"),
        ({"submission_text": 12345}, "body.submission_text"),
        ({"submission_id": "SECRET-MARKER-12345"}, "body.submission_id"),
        ({"assignment_id": "SECRET-MARKER-12345"}, "body.assignment_id"),
    ]
    for change, expected_field in cases:
        response = submit(good_body(assignment_id, **change))
        assert response.status_code == 422, change
        assert fields_of(response) == [expected_field]
        assert "SECRET-MARKER" not in response.text

    missing = good_body(assignment_id)
    del missing["submission_id"]
    response = submit(missing)
    assert response.status_code == 422
    assert fields_of(response) == ["body.submission_id"]

    invented = good_body(assignment_id)
    invented["SECRET-MARKER-12345"] = "x"
    response = submit(invented)
    assert response.status_code == 422
    assert fields_of(response) == ["body"]
    assert "SECRET-MARKER" not in response.text


# In plain English: the limits are exact. A 200 character name and a 20,000 character
# essay are accepted, which shows the refusals above come from the limits and not from
# something else.
def test_the_limits_are_exact():
    body = good_body(
        new_assignment(),
        student_name="n" * 200,
        submission_text="word " * 4000,
    )
    assert submit(body).status_code == 201


# In plain English: text the database cannot store is refused as bad input, not left to
# fail inside the database as a 500. That means a null character and a lone surrogate
# (half of a pair, which cannot be written out as UTF-8). Both are tried in the name and
# the essay. The reply names the field only and never repeats the text. The request body
# is sent as escaped JSON text so the test client never has to encode the bad
# characters itself. A request with clean text first is the control.
def test_text_the_database_cannot_store_is_refused_in_both_text_fields():
    assignment_id = new_assignment()
    assert submit(good_body(assignment_id)).status_code == 201

    for field in ("student_name", "submission_text"):
        for bad_text in ("SECRET-MARKER\u0000abc", "SECRET-MARKER\ud800abc"):
            body = good_body(assignment_id, **{field: bad_text})
            response = client.post("/submissions", content=json.dumps(body), headers=JSON_HEADERS)
            assert response.status_code == 422, (field, bad_text)
            assert fields_of(response) == [f"body.{field}"]
            assert "SECRET-MARKER" not in response.text


# ---------------------------------------------------------------------------
# 5. Duplicates are allowed under different IDs
# ---------------------------------------------------------------------------


# In plain English: the same ID is how the service recognises a retry. Different IDs are
# different submissions, even for the same assignment, the same student and the same
# essay. All of them go in and can be read back.
def test_different_ids_are_different_submissions_even_with_identical_content():
    assignment_id = new_assignment()
    bodies = [
        good_body(assignment_id, student_name="Alex"),
        good_body(assignment_id, student_name="Blake"),
        good_body(assignment_id, student_name="Alex"),
    ]
    for body in bodies:
        assert submit(body).status_code == 201
    for body in bodies:
        assert client.get(f"/submissions/{body['submission_id']}").status_code == 200


# ---------------------------------------------------------------------------
# 6. No way to change or remove
# ---------------------------------------------------------------------------


# In plain English: the API offers no way to change or delete a submission. Reading it
# works (the control), and every attempt to change or remove it is turned away with
# "method not allowed".
def test_there_is_no_way_to_change_or_remove_a_submission():
    body = good_body(new_assignment())
    assert submit(body).status_code == 201
    url = f"/submissions/{body['submission_id']}"
    assert client.get(url).status_code == 200

    assert client.put(url, json=body).status_code == 405
    assert client.patch(url, json={"student_name": "x"}).status_code == 405
    assert client.delete(url).status_code == 405
