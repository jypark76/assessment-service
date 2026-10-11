# In plain English: tests that every request body the assessment service accepts is checked field by field. A
# request with a field we never defined is refused, and a request that leaves out a required field is refused
# naming that field. Neither the extra field's name nor anything the caller typed is repeated in the reply.
#
# Why it matters (OWASP A10, CWE-234 failure to handle a missing parameter and CWE-235 improper handling of
# extra parameters): an unexpected field that is silently accepted can change behaviour that nobody tested, and a
# missing field that is silently defaulted can create a record nobody meant. The answer to both is a clear 422.
# These requests are turned away before any database work, so no database is needed here.
import uuid

import pytest
from fastapi.testclient import TestClient

import test_assignments
import test_grades
import test_reviews
import test_submissions
from app.assignments import NewAssignment
from app.grades import NewGrade
from app.main import app
from app.reviews import NewReview
from app.submissions import NewSubmission
from conftest import AUTH_HEADERS

client = TestClient(app, headers=AUTH_HEADERS)
SUBMISSION = str(uuid.uuid4())
SENTINEL = "EXTRA-FIELD-NAME-5150"

# route -> (address, the model behind it, a good body)
ROUTES = {
    "assignments": ("/assignments", NewAssignment, test_assignments.good_body()),
    "submissions": ("/submissions", NewSubmission, test_submissions.good_body(str(uuid.uuid4()))),
    "grades": (f"/submissions/{SUBMISSION}/grades", NewGrade, test_grades.grade_body()),
    "reviews": (f"/submissions/{SUBMISSION}/reviews", NewReview, test_reviews.review_body()),
}


def required_fields(model):
    return [name for name, field in model.model_fields.items() if field.is_required()]


@pytest.mark.owasp("A10", 235)
@pytest.mark.parametrize("route", sorted(ROUTES))
def test_a_field_we_never_defined_is_refused_without_repeating_its_name(route):
    address, _, body = ROUTES[route]
    reply = client.post(address, json={**body, SENTINEL: "x"})
    assert reply.status_code == 422
    assert reply.json() == {"problems": [{"field": "body", "reason": "Extra inputs are not permitted"}]}
    assert SENTINEL not in reply.text


@pytest.mark.owasp("A10", 234)
@pytest.mark.parametrize("route", sorted(ROUTES))
def test_a_missing_required_field_is_refused_naming_that_field(route):
    address, model, body = ROUTES[route]
    required = required_fields(model)
    assert required, "the model has no required fields, so there is nothing to check"
    for name in required:
        without = {key: value for key, value in body.items() if key != name}
        reply = client.post(address, json=without)
        assert reply.status_code == 422, name
        assert {"field": f"body.{name}", "reason": "Field required"} in reply.json()["problems"], name


@pytest.mark.owasp("A10", 234)
@pytest.mark.parametrize("route", sorted(ROUTES))
def test_an_empty_body_is_refused_for_every_required_field_at_once(route):
    address, model, _ = ROUTES[route]
    reply = client.post(address, json={})
    assert reply.status_code == 422
    named = {problem["field"] for problem in reply.json()["problems"]}
    assert {f"body.{name}" for name in required_fields(model)} <= named


@pytest.mark.owasp("A10", 234)
@pytest.mark.parametrize("route", sorted(ROUTES))
def test_no_body_at_all_is_refused(route):
    address, _, _ = ROUTES[route]
    assert client.post(address).status_code == 422


@pytest.mark.owasp("A10", 235)
@pytest.mark.parametrize("route", sorted(ROUTES))
@pytest.mark.owasp("A08", 915)
def test_every_model_forbids_extra_fields(route):
    _, model, _ = ROUTES[route]
    assert model.model_config.get("extra") == "forbid"
