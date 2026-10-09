# In plain English: these tests check the instructor's review, from the outside, against
# the real app and a real Postgres. A review is a NEW version row on a submission whose
# AI grade is waiting: "approved" or "rejected". Nothing is ever edited. They also check
# the list of submissions by status, which is how the instructor finds what is waiting.
# The tests cover:
#   1. approving, and the whole cycle: submitted, graded, rejected, graded, approved;
#   2. a retry is harmless, and a different decision for a version that already has one
#      is refused, so two reviewers can never both win;
#   3. only a submission that is waiting for review (graded) can be reviewed;
#   4. unknown submissions and out-of-date versions are refused;
#   5. bad input is refused with the field and the reason, and never the value sent;
#   6. the review route accepts nothing but POST;
#   7. the list by status, oldest first, without student names or essays.
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
NOT_WAITING = {"problem": "This submission is not waiting for review"}
MOVED_ON = {"problem": "This submission has changed since that version"}


# In plain English: creates a real assignment through the API and returns its ID.
def new_assignment_id():
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


# In plain English: submits a student's work (version 1) through the API and returns the
# submission ID. A new assignment is made unless the test passes one in.
def new_submission(assignment_id=None):
    assignment_id = assignment_id or new_assignment_id()
    submission_id = str(uuid.uuid4())
    created = client.post(
        "/submissions",
        json={
            "submission_id": submission_id,
            "assignment_id": assignment_id,
            "student_name": "Alex",
            "submission_text": "The original essay.",
        },
    )
    assert created.status_code == 201
    return submission_id


# In plain English: records an AI grade through the API, as the grader will. The grade
# defaults to a B and goes in after the version the test names (version 1 by default).
def grade(submission_id, based_on_version=1, ai_grade="B"):
    response = client.post(
        f"/submissions/{submission_id}/grades",
        json={
            "based_on_version": based_on_version,
            "ai_grade": ai_grade,
            "ai_reasoning": "Clear but short.",
        },
    )
    assert response.status_code == 201
    return response


# In plain English: a submission that has been graded and is waiting for review, at
# version 2.
def graded_submission(assignment_id=None):
    submission_id = new_submission(assignment_id)
    grade(submission_id)
    return submission_id


# In plain English: a correct approval body. Tests change single fields.
def review_body(**changes):
    body = {
        "based_on_version": 2,
        "decision": "approve",
        "reviewer_username": "instructor1",
    }
    body.update(changes)
    return body


def review(submission_id, **changes):
    return client.post(f"/submissions/{submission_id}/reviews", json=review_body(**changes))


def history_of(submission_id):
    return client.get(f"/submissions/{submission_id}").json()["history"]


def statuses_of(submission_id):
    return [entry["status"] for entry in history_of(submission_id)]


# In plain English: the names of the fields a refusal points at, in order.
def fields_of(response):
    return [problem["field"] for problem in response.json()["problems"]]


# ---------------------------------------------------------------------------
# 1. Approve, and the whole cycle
# ---------------------------------------------------------------------------


# In plain English: an approval goes in as version 3 with the status "approved". It copies
# the grade and reasoning it approved and names the reviewer. An approval has no feedback.
def test_an_approval_goes_in_as_the_next_version():
    submission_id = graded_submission()

    response = review(submission_id)
    assert response.status_code == 201
    data = response.json()
    assert data["submission_id"] == submission_id
    assert data["version"] == 3
    assert data["status"] == "approved"
    assert data["ai_grade"] == "B"
    assert data["ai_reasoning"] == "Clear but short."
    assert data["reviewer_username"] == "instructor1"
    assert data["feedback"] is None
    assert data["created_at"]

    assert statuses_of(submission_id) == ["submitted", "graded", "approved"]


# In plain English: the full cycle works end to end through the API: submitted, graded,
# rejected with feedback, graded again, then approved. Every step is a new row, and the
# rejection copies the grade it rejected while the approval copies the new one.
def test_the_whole_cycle_through_the_api():
    submission_id = graded_submission()

    rejected = review(
        submission_id, decision="reject", feedback="Tighten the thesis."
    )
    assert rejected.status_code == 201
    assert rejected.json()["version"] == 3
    assert rejected.json()["status"] == "rejected"
    assert rejected.json()["feedback"] == "Tighten the thesis."
    assert rejected.json()["ai_grade"] == "B"

    grade(submission_id, based_on_version=3, ai_grade="A")

    approved = review(submission_id, based_on_version=4)
    assert approved.status_code == 201
    assert approved.json()["version"] == 5
    assert approved.json()["ai_grade"] == "A"

    assert statuses_of(submission_id) == [
        "submitted", "graded", "rejected", "graded", "approved",
    ]


# ---------------------------------------------------------------------------
# 2. Retries and clashes
# ---------------------------------------------------------------------------


# In plain English: sending the same review again (a retry after a timeout) returns the
# saved review with a 200 and adds nothing. This is checked for an approval and for a
# rejection. The first send of each is the control and answers 201.
def test_a_retry_returns_the_saved_review_and_adds_nothing():
    approved = graded_submission()
    first = review(approved)
    assert first.status_code == 201
    retry = review(approved)
    assert retry.status_code == 200
    assert retry.json() == first.json()
    assert len(history_of(approved)) == 3

    rejected = graded_submission()
    first = review(rejected, decision="reject", feedback="Tighten the thesis.")
    assert first.status_code == 201
    retry = review(rejected, decision="reject", feedback="Tighten the thesis.")
    assert retry.status_code == 200
    assert retry.json() == first.json()
    assert len(history_of(rejected)) == 3


# In plain English: a different decision, a different reviewer or different feedback for a
# version that already has a review is refused and changes nothing. This is what stops two
# reviewers on the same submission from both winning. The first approval is the control.
def test_a_different_review_for_an_already_reviewed_version_is_refused():
    submission_id = graded_submission()
    assert review(submission_id).status_code == 201

    others = [
        {"decision": "reject", "feedback": "SECRET-MARKER send it back."},
        {"reviewer_username": "instructor2"},
    ]
    for change in others:
        response = review(submission_id, **change)
        assert response.status_code == 409, change
        assert response.json() == MOVED_ON
        assert "SECRET-MARKER" not in response.text

    history = history_of(submission_id)
    assert len(history) == 3
    assert history[2]["status"] == "approved"
    assert history[2]["reviewer_username"] == "instructor1"


# ---------------------------------------------------------------------------
# 3. Which states can be reviewed
# ---------------------------------------------------------------------------


# In plain English: only a submission whose latest version is "graded" can be reviewed.
# A new submission with no grade, one already rejected (it needs a new grade first) and
# one already approved (final) are each refused with fixed wording, and nothing is added.
# A graded submission is the control and works.
def test_only_a_graded_submission_can_be_reviewed():
    assert review(graded_submission()).status_code == 201

    ungraded = new_submission()
    response = review(ungraded, based_on_version=1)
    assert response.status_code == 409
    assert response.json() == NOT_WAITING
    assert len(history_of(ungraded)) == 1

    rejected = graded_submission()
    assert review(rejected, decision="reject", feedback="Needs work.").status_code == 201
    response = review(rejected, based_on_version=3)
    assert response.status_code == 409
    assert response.json() == NOT_WAITING
    assert len(history_of(rejected)) == 3

    approved = graded_submission()
    assert review(approved).status_code == 201
    response = review(approved, based_on_version=3, decision="reject", feedback="Too late.")
    assert response.status_code == 409
    assert response.json() == NOT_WAITING
    assert len(history_of(approved)) == 3


# ---------------------------------------------------------------------------
# 4. Not found and out of date
# ---------------------------------------------------------------------------


# In plain English: reviewing a submission nobody created gives "not found" and the reply
# does not repeat the ID. Reviewing a version that does not exist yet gives the "changed"
# answer and adds nothing. A correct review is the control and works.
def test_unknown_submissions_and_out_of_date_versions_are_refused():
    assert review(graded_submission()).status_code == 201

    unknown = str(uuid.uuid4())
    response = review(unknown)
    assert response.status_code == 404
    assert response.json() == {"problem": "Submission not found"}
    assert unknown not in response.text

    submission_id = graded_submission()
    response = review(submission_id, based_on_version=5)
    assert response.status_code == 409
    assert response.json() == MOVED_ON
    assert len(history_of(submission_id)) == 2


# ---------------------------------------------------------------------------
# 5. Bad input
# ---------------------------------------------------------------------------


# In plain English: each bad request is refused with 422 naming only the field. The marker
# inside the bad value must never come back, and neither may the name of an invented
# field. The bad requests go to a fresh graded submission, so if a rule were missing the
# request would reach the database and the history would change. A correct request on
# another submission is the control.
def test_bad_input_names_the_field_and_never_the_value():
    assert review(graded_submission()).status_code == 201

    submission_id = graded_submission()
    cases = [
        ({"decision": "SECRET-MARKER"}, "body.decision"),
        ({"decision": 5}, "body.decision"),
        ({"reviewer_username": "   "}, "body.reviewer_username"),
        ({"reviewer_username": "SECRET-MARKER-" + "r" * 100}, "body.reviewer_username"),
        ({"decision": "reject"}, "body.feedback"),
        ({"decision": "reject", "feedback": "   "}, "body.feedback"),
        ({"decision": "reject", "feedback": "SECRET-MARKER-" + "x" * 10_000}, "body.feedback"),
        ({"decision": "approve", "feedback": "SECRET-MARKER"}, "body.feedback"),
        ({"based_on_version": 0}, "body.based_on_version"),
        ({"based_on_version": "SECRET-MARKER"}, "body.based_on_version"),
    ]
    for change, expected_field in cases:
        response = review(submission_id, **change)
        assert response.status_code == 422, change
        assert fields_of(response) == [expected_field]
        assert "SECRET-MARKER" not in response.text

    missing = review_body()
    del missing["decision"]
    response = client.post(f"/submissions/{submission_id}/reviews", json=missing)
    assert response.status_code == 422
    assert fields_of(response) == ["body.decision"]

    invented = review_body()
    invented["SECRET-MARKER-12345"] = "x"
    response = client.post(f"/submissions/{submission_id}/reviews", json=invented)
    assert response.status_code == 422
    assert fields_of(response) == ["body"]
    assert "SECRET-MARKER" not in response.text

    garbage = client.post("/submissions/SECRET-MARKER-12345/reviews", json=review_body())
    assert garbage.status_code == 422
    assert "SECRET-MARKER" not in garbage.text

    assert len(history_of(submission_id)) == 2


# In plain English: the limits are exact. A 100 character reviewer name and 10,000
# characters of feedback are accepted, which shows the refusals above come from the limits
# and not from something else.
def test_the_limits_are_exact():
    response = review(
        graded_submission(),
        decision="reject",
        reviewer_username="r" * 100,
        feedback="f" * 10_000,
    )
    assert response.status_code == 201


# In plain English: text the database cannot store is refused as bad input, not left to
# fail inside the database as a 500. That means a null character and a lone surrogate
# (half of a pair, which cannot be written out as UTF-8). Both are tried in the reviewer
# name and the feedback. The reply names the field only and never repeats the text. The
# body is sent as escaped JSON text so the test client never has to encode the bad
# characters itself. A request with clean text first is the control.
def test_text_the_database_cannot_store_is_refused_in_both_text_fields():
    assert review(graded_submission(), decision="reject", feedback="Needs work.").status_code == 201

    submission_id = graded_submission()
    for field in ("reviewer_username", "feedback"):
        for bad_text in ("SECRET-MARKER\u0000abc", "SECRET-MARKER\ud800abc"):
            changes = {"decision": "reject", "feedback": "Needs work.", field: bad_text}
            body = review_body(**changes)
            response = client.post(
                f"/submissions/{submission_id}/reviews",
                content=json.dumps(body),
                headers=JSON_HEADERS,
            )
            assert response.status_code == 422, (field, bad_text)
            assert fields_of(response) == [f"body.{field}"]
            assert "SECRET-MARKER" not in response.text

    assert len(history_of(submission_id)) == 2


# ---------------------------------------------------------------------------
# 6. Nothing but POST
# ---------------------------------------------------------------------------


# In plain English: the reviews route only accepts POST. Reading, replacing, patching and
# deleting are all turned away with "method not allowed". A POST is the control and works.
def test_the_reviews_route_accepts_nothing_but_post():
    submission_id = graded_submission()
    assert review(submission_id).status_code == 201
    url = f"/submissions/{submission_id}/reviews"

    assert client.get(url).status_code == 405
    assert client.put(url, json=review_body()).status_code == 405
    assert client.patch(url, json=review_body()).status_code == 405
    assert client.delete(url).status_code == 405


# ---------------------------------------------------------------------------
# 7. The list by status
# ---------------------------------------------------------------------------


# In plain English: the list shows the submissions whose LATEST version has the asked-for
# status, oldest first, so it works as a queue. Five submissions in one fresh assignment
# are put into five different states, and each status finds exactly the right ones. The
# list leaves out the student's name and essay, which are read one at a time instead.
# Filtering by the fresh assignment keeps the answer exact, because the test database
# keeps rows from earlier runs.
def test_the_list_finds_submissions_by_their_latest_status():
    assignment_id = new_assignment_id()
    only_submitted = new_submission(assignment_id)
    first_waiting = graded_submission(assignment_id)
    rejected = graded_submission(assignment_id)
    assert review(rejected, decision="reject", feedback="Needs work.").status_code == 201
    approved = graded_submission(assignment_id)
    assert review(approved).status_code == 201
    second_waiting = graded_submission(assignment_id)

    def ids_with(status, **extra):
        response = client.get(
            "/submissions",
            params={"status": status, "assignment_id": assignment_id, **extra},
        )
        assert response.status_code == 200
        return [item["submission_id"] for item in response.json()]

    assert ids_with("submitted") == [only_submitted]
    assert ids_with("graded") == [first_waiting, second_waiting]
    assert ids_with("rejected") == [rejected]
    assert ids_with("approved") == [approved]
    assert ids_with("graded", limit=1) == [first_waiting]

    waiting = client.get(
        "/submissions", params={"status": "graded", "assignment_id": assignment_id}
    ).json()
    item = waiting[0]
    assert item["assignment_id"] == assignment_id
    assert item["version"] == 2
    assert item["status"] == "graded"
    assert item["ai_grade"] == "B"
    assert item["created_at"]
    assert "student_name" not in item
    assert "submission_text" not in item


# In plain English: the list needs a real status, and the limit must be 1 to 100. A bad
# assignment ID is refused too. Each refusal names the place only and never repeats what
# was sent. A correct request is the control and works.
def test_bad_list_requests_are_refused_without_repeating_them():
    assert client.get("/submissions", params={"status": "graded", "limit": 100}).status_code == 200

    missing = client.get("/submissions")
    assert missing.status_code == 422
    assert fields_of(missing) == ["query.status"]

    bad_status = client.get("/submissions", params={"status": "SECRET-MARKER"})
    assert bad_status.status_code == 422
    assert fields_of(bad_status) == ["query.status"]
    assert "SECRET-MARKER" not in bad_status.text

    for bad_limit in ("0", "101", "abc"):
        response = client.get("/submissions", params={"status": "graded", "limit": bad_limit})
        assert response.status_code == 422
        assert fields_of(response) == ["query.limit"]

    bad_assignment = client.get(
        "/submissions", params={"status": "graded", "assignment_id": "SECRET-MARKER-12345"}
    )
    assert bad_assignment.status_code == 422
    assert fields_of(bad_assignment) == ["query.assignment_id"]
    assert "SECRET-MARKER" not in bad_assignment.text
