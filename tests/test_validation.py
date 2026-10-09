# In plain English: these tests check how the service words its "bad input" replies,
# without needing a database. The service has no routes that take input yet, so
# the tests work in two ways:
#   - directly on the two small helpers that pick the field name and the reason to
#     show, and
#   - through a tiny stand-in route built inside the test, which uses the SAME
#     error handler the real service uses, so the whole reply can be checked.
# The promise they protect: a refusal names the field and the reason but never
# repeats what the caller sent, not even the name of a field the caller invented.
from uuid import UUID

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict, Field

from app.main import SAFE_ERROR_KINDS, bad_input, safe_field, safe_reason


# In plain English: a tiny stand-in service used only in these tests. It has one
# route that expects an assignment ID, a short note and nothing else, and it uses
# the real error handler from the service.
class Probe(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignment_id: UUID
    note: str = Field(min_length=1, max_length=10)


probe_app = FastAPI()
probe_app.add_exception_handler(RequestValidationError, bad_input)


@probe_app.post("/probe")
def probe(body: Probe):
    return {"ok": True}


client = TestClient(probe_app)


def good_probe():
    return {"assignment_id": "11111111-1111-1111-1111-111111111111", "note": "hello"}


# In plain English: the control. A correct request goes through, so the refusals
# below really come from the rules and not from a broken stand-in.
def test_a_good_request_is_accepted():
    assert client.post("/probe", json=good_probe()).status_code == 200


# In plain English: a bad UUID gets fixed wording. The built-in wording quotes the
# offending character, and that must never come back.
def test_bad_uuid_gets_fixed_wording():
    data = good_probe()
    data["assignment_id"] = "SECRET-MARKER-12345"
    response = client.post("/probe", json=data)
    assert response.status_code == 422
    assert response.json() == {
        "problems": [{"field": "body.assignment_id", "reason": "Input should be a valid UUID"}]
    }
    assert "SECRET-MARKER" not in response.text


# In plain English: a caller can pick any name for an extra field, so the name is
# caller data too. The reply names only the place ("body"), never the chosen name.
def test_an_invented_field_name_is_never_echoed():
    data = good_probe()
    data["SECRET-MARKER-12345"] = "x"
    response = client.post("/probe", json=data)
    assert response.status_code == 422
    assert response.json() == {
        "problems": [{"field": "body", "reason": "Extra inputs are not permitted"}]
    }
    assert "SECRET-MARKER" not in response.text


# In plain English: a text that is too long is refused with the rule, not the text.
def test_too_long_text_is_refused_without_repeating_it():
    data = good_probe()
    data["note"] = "SECRET-MARKER-" + "x" * 50
    response = client.post("/probe", json=data)
    assert response.status_code == 422
    assert [problem["field"] for problem in response.json()["problems"]] == ["body.note"]
    assert "SECRET-MARKER" not in response.text


# In plain English: for any kind of error we have not looked at one by one, the
# reply says only "Invalid value". Here a broken JSON body is cut off in the middle
# of a text, and none of that text may come back.
def test_unknown_kinds_of_error_get_generic_wording():
    response = client.post(
        "/probe",
        content='{"note": "SECRET-MARKER',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert "SECRET-MARKER" not in response.text
    assert [problem["reason"] for problem in response.json()["problems"]] == ["Invalid value"]


# In plain English: the helper rules on their own, without any request. UUID error
# kinds get fixed wording, the kinds known to be safe keep their wording, and
# anything else says "Invalid value".
def test_reason_helper_rules():
    for kind in ("uuid_parsing", "uuid_type", "uuid_version"):
        item = {"type": kind, "msg": "found `S` at 1", "loc": ("body", "assignment_id")}
        assert safe_reason(item) == "Input should be a valid UUID"
    for kind in SAFE_ERROR_KINDS:
        item = {"type": kind, "msg": "a rule description", "loc": ("body", "note")}
        assert safe_reason(item) == "a rule description"
    unknown = {"type": "something_new", "msg": "SECRET-MARKER", "loc": ("body",)}
    assert safe_reason(unknown) == "Invalid value"


# In plain English: the field helper shows the normal path, and drops the last part
# of the path only for an unexpected extra field.
def test_field_helper_rules():
    normal = {"type": "missing", "loc": ("body", "note"), "msg": ""}
    query = {"type": "missing", "loc": ("query", "assignment_id"), "msg": ""}
    extra = {"type": "extra_forbidden", "loc": ("body", "SECRET-MARKER-12345"), "msg": ""}
    assert safe_field(normal) == "body.note"
    assert safe_field(query) == "query.assignment_id"
    assert safe_field(extra) == "body"
