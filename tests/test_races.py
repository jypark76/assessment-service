# In plain English: these tests check what happens when two workers (or two reviewers) act
# on the same submission at the same moment. Grades and reviews are added as new version
# rows, and the database refuses a second row with a version number that is already used.
# The service answers that refusal by looking again from the start, and the second look
# finds either the very same grade or review (a retry, answered 200) or a submission that
# has moved on (answered 409). It must never answer 500, and it must never save two rows
# for one version.
#
# There are two kinds of test, because a collision at the exact moment is a matter of luck:
#   1. Planted collisions. The test lets a competing writer slip in after the service has
#      read the history and just before it writes. That forces the "database refused,
#      look again" path every time, so the test proves the path really ran.
#   2. Real collisions. Eight threads send their requests at the same instant. Whatever
#      order they happen to run in, exactly one may win and the others must get the right
#      answer. The outcome is the same whether or not a collision actually occurred.
#
# Every test checks the history afterwards, so a second saved row for one version would
# be caught.
import threading
import uuid
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app import grades, reviews
from app.grades import NewGrade, record_grade
from app.main import app
from app.reviews import NewReview, record_review

pytestmark = pytest.mark.usefixtures("require_test_database")

client = TestClient(app)

MOVED_ON = {"problem": "This submission has changed since that version"}
WORKERS = 8


# In plain English: submits a student's work (version 1) through the API, in a new
# assignment, and returns the submission ID.
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


def grade_body(ai_grade="B"):
    return {"based_on_version": 1, "ai_grade": ai_grade, "ai_reasoning": "Clear but short."}


# In plain English: a submission that has a grade and is waiting for review, at version 2.
def graded_submission():
    submission_id = new_submission()
    response = client.post(f"/submissions/{submission_id}/grades", json=grade_body())
    assert response.status_code == 201
    return submission_id


def review_body(decision="approve", reviewer="instructor1", feedback=None):
    body = {"based_on_version": 2, "decision": decision, "reviewer_username": reviewer}
    if feedback is not None:
        body["feedback"] = feedback
    return body


def history_of(submission_id):
    return client.get(f"/submissions/{submission_id}").json()["history"]


# In plain English: a stand-in for a database connection that behaves exactly like the real
# one, except that just before the service's first INSERT it lets a competing writer go
# first. That is the moment a real race would hit: the service has already read the history
# and is about to write, and someone else's row lands in between.
class RacingConnection:
    def __init__(self, real, before_insert):
        self.real = real
        self.before_insert = before_insert

    def __enter__(self):
        self.real.__enter__()
        return self

    def __exit__(self, *details):
        return self.real.__exit__(*details)

    def execute(self, sql, params=()):
        if sql.lstrip().upper().startswith("INSERT"):
            self.before_insert()
        return self.real.execute(sql, params)


# In plain English: plants the collision. In the given module (grades or reviews), the FIRST
# connection the service opens gets the stand-in above, and the competitor runs just before
# its INSERT. Every later connection is a normal one, including the competitor's own and the
# second look the service takes. The returned dictionary counts how many times the
# competitor ran, so a test can prove the collision really happened.
def plant_collision(monkeypatch, module, competitor):
    real_connect = module.connect
    state = {"opened": 0, "competitor_ran": 0}

    def competing_first():
        state["competitor_ran"] += 1
        competitor()

    def connect_with_collision():
        state["opened"] += 1
        connection = real_connect()
        if state["opened"] == 1:
            return RacingConnection(connection, competing_first)
        return connection

    monkeypatch.setattr(module, "connect", connect_with_collision)
    return state


# In plain English: runs one request per entry at the same instant. Each thread waits at a
# barrier until all of them are ready, then they all go. Each thread uses its own test
# client. Whatever each one returns, or the exception it raised, is collected in order.
def run_together(requests):
    barrier = threading.Barrier(len(requests))
    results = [None] * len(requests)

    def worker(index, send):
        local_client = TestClient(app)
        barrier.wait()
        try:
            results[index] = send(local_client)
        except Exception as error:  # a crash is a result too, and the test will fail on it
            results[index] = error

    threads = [
        threading.Thread(target=worker, args=(index, send))
        for index, send in enumerate(requests)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def statuses(results):
    for result in results:
        assert not isinstance(result, Exception), result
    return sorted(result.status_code for result in results)


# ---------------------------------------------------------------------------
# 1. Planted collisions: a competitor writes after the read and before the write
# ---------------------------------------------------------------------------


# In plain English: a different grade for the same version lands first. The service's own
# write is refused by the database, it looks again, and it answers 409 "changed". The
# competitor's grade is the one that stays, and there is exactly one new row.
def test_a_grade_that_loses_to_a_different_grade_gets_a_conflict(monkeypatch):
    submission_id = new_submission()
    competitor = lambda: record_grade(
        UUID(submission_id),
        NewGrade(based_on_version=1, ai_grade="A", ai_reasoning="The competitor."),
    )
    state = plant_collision(monkeypatch, grades, competitor)

    response = client.post(f"/submissions/{submission_id}/grades", json=grade_body("B"))

    assert state["competitor_ran"] == 1
    assert response.status_code == 409
    assert response.json() == MOVED_ON
    history = history_of(submission_id)
    assert len(history) == 2
    assert history[1]["ai_grade"] == "A"


# In plain English: the very same grade lands first (two workers doing the same job). The
# service's own write is refused, it looks again, finds its own grade already saved, and
# answers 200 as for a retry. There is still exactly one new row.
def test_a_grade_that_loses_to_the_same_grade_is_treated_as_a_retry(monkeypatch):
    submission_id = new_submission()
    competitor = lambda: record_grade(
        UUID(submission_id),
        NewGrade(based_on_version=1, ai_grade="B", ai_reasoning="Clear but short."),
    )
    state = plant_collision(monkeypatch, grades, competitor)

    response = client.post(f"/submissions/{submission_id}/grades", json=grade_body("B"))

    assert state["competitor_ran"] == 1
    assert response.status_code == 200
    assert response.json()["version"] == 2
    assert response.json()["ai_grade"] == "B"
    assert len(history_of(submission_id)) == 2


# In plain English: a different review for the same version lands first. The service looks
# again and answers 409 "changed". The competitor's rejection stays, with one new row.
def test_a_review_that_loses_to_a_different_review_gets_a_conflict(monkeypatch):
    submission_id = graded_submission()
    competitor = lambda: record_review(
        UUID(submission_id),
        NewReview(
            based_on_version=2,
            decision="reject",
            reviewer_username="instructor2",
            feedback="The competitor.",
        ),
    )
    state = plant_collision(monkeypatch, reviews, competitor)

    response = client.post(f"/submissions/{submission_id}/reviews", json=review_body())

    assert state["competitor_ran"] == 1
    assert response.status_code == 409
    assert response.json() == MOVED_ON
    history = history_of(submission_id)
    assert len(history) == 3
    assert history[2]["status"] == "rejected"
    assert history[2]["reviewer_username"] == "instructor2"


# In plain English: the very same review lands first. The service looks again, finds its
# own review already saved and answers 200 as for a retry, with one new row.
def test_a_review_that_loses_to_the_same_review_is_treated_as_a_retry(monkeypatch):
    submission_id = graded_submission()
    competitor = lambda: record_review(
        UUID(submission_id),
        NewReview(based_on_version=2, decision="approve", reviewer_username="instructor1"),
    )
    state = plant_collision(monkeypatch, reviews, competitor)

    response = client.post(f"/submissions/{submission_id}/reviews", json=review_body())

    assert state["competitor_ran"] == 1
    assert response.status_code == 200
    assert response.json()["version"] == 3
    assert response.json()["status"] == "approved"
    assert len(history_of(submission_id)) == 3


# ---------------------------------------------------------------------------
# 2. Real collisions: eight requests at the same instant
# ---------------------------------------------------------------------------


# In plain English: eight workers each send a DIFFERENT grade for the same version at the
# same instant. Exactly one wins with 201 and the other seven get 409. Nobody gets a 500
# and only one row is added.
def test_eight_different_grades_at_once_have_exactly_one_winner():
    submission_id = new_submission()
    url = f"/submissions/{submission_id}/grades"
    requests = [
        (lambda local, grade=grade: local.post(url, json=grade_body(grade)))
        for grade in "ABCDEFGH"
    ]

    results = run_together(requests)

    assert statuses(results) == [201] + [409] * (WORKERS - 1)
    assert len(history_of(submission_id)) == 2


# In plain English: eight workers send the SAME grade for the same version at the same
# instant. Exactly one is the first (201) and the other seven are recognised as retries
# (200). Only one row is added.
def test_eight_identical_grades_at_once_add_one_row():
    submission_id = new_submission()
    url = f"/submissions/{submission_id}/grades"
    requests = [lambda local: local.post(url, json=grade_body("B"))] * WORKERS

    results = run_together(requests)

    assert statuses(results) == [200] * (WORKERS - 1) + [201]
    assert len(history_of(submission_id)) == 2


# In plain English: eight reviewers each send a DIFFERENT review for the same grade at the
# same instant (some approve, some reject). Exactly one wins and the rest get 409. Only one
# row is added.
def test_eight_different_reviews_at_once_have_exactly_one_winner():
    submission_id = graded_submission()
    url = f"/submissions/{submission_id}/reviews"
    requests = [
        (
            lambda local, number=number: local.post(
                url,
                json=review_body(
                    decision="approve" if number % 2 == 0 else "reject",
                    reviewer=f"instructor{number}",
                    feedback=None if number % 2 == 0 else "Send it back.",
                ),
            )
        )
        for number in range(WORKERS)
    ]

    results = run_together(requests)

    assert statuses(results) == [201] + [409] * (WORKERS - 1)
    assert len(history_of(submission_id)) == 3


# In plain English: eight reviewers send the SAME approval at the same instant. Exactly one
# is the first (201) and the other seven are recognised as retries (200). Only one row is
# added, so there is still just one approval.
def test_eight_identical_approvals_at_once_add_one_row():
    submission_id = graded_submission()
    url = f"/submissions/{submission_id}/reviews"
    requests = [lambda local: local.post(url, json=review_body())] * WORKERS

    results = run_together(requests)

    assert statuses(results) == [200] * (WORKERS - 1) + [201]
    history = history_of(submission_id)
    assert len(history) == 3
    assert [entry["status"] for entry in history].count("approved") == 1
