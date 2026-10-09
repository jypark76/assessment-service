# In plain English: these tests check that the service turns away bad requests
# at the door. They need no database, because a bad request is refused before
# any database work starts. They also check that the refusal message never
# repeats back what the caller sent.
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

GOOD_ID = "11111111-1111-1111-1111-111111111111"


# In plain English: a complete, valid request to save an example. Each test
# below copies it and breaks exactly one thing.
def good_example():
    return {
        "assignment_id": GOOD_ID,
        "student_work": "The mitochondria makes energy for the cell.",
        "grade": "A",
        "reasoning": "Correct and clear.",
    }


# In plain English: a complete, valid search request, used the same way.
def good_search():
    return {"assignment_id": GOOD_ID, "query_text": "cells produce energy"}


# In plain English: checks the request was refused with 422 ("bad input") and
# that the reply only names the field and reason. It must not contain the
# "input" or "ctx" parts that would echo the caller's data back.
def assert_refused(response, field):
    assert response.status_code == 422
    body = response.json()
    assert list(body.keys()) == ["problems"]
    assert body["problems"][0]["field"] == f"body.{field}"
    for problem in body["problems"]:
        assert set(problem.keys()) == {"field", "reason"}


# In plain English: an unexpected extra field must be refused, and the reply must
# name only the place ("body"), never the name the caller chose for the field.
def assert_extra_field_refused(response):
    assert response.status_code == 422
    assert response.json() == {
        "problems": [{"field": "body", "reason": "Extra inputs are not permitted"}]
    }


def test_save_rejects_bad_uuid():
    data = good_example()
    data["assignment_id"] = "not-a-uuid"
    assert_refused(client.post("/examples", json=data), "assignment_id")


def test_save_rejects_blank_student_work():
    data = good_example()
    data["student_work"] = "   "
    assert_refused(client.post("/examples", json=data), "student_work")


def test_save_rejects_oversize_student_work():
    data = good_example()
    data["student_work"] = "a" * 20001
    assert_refused(client.post("/examples", json=data), "student_work")


def test_save_rejects_oversize_grade():
    data = good_example()
    data["grade"] = "a" * 101
    assert_refused(client.post("/examples", json=data), "grade")


def test_save_rejects_extra_field():
    data = good_example()
    data["extra"] = "sneaky"
    assert_extra_field_refused(client.post("/examples", json=data))


def test_save_rejects_missing_field():
    data = good_example()
    del data["reasoning"]
    assert_refused(client.post("/examples", json=data), "reasoning")


def test_search_rejects_bad_uuid():
    data = good_search()
    data["assignment_id"] = "not-a-uuid"
    assert_refused(client.post("/examples/search", json=data), "assignment_id")


def test_search_rejects_blank_query():
    data = good_search()
    data["query_text"] = "   "
    assert_refused(client.post("/examples/search", json=data), "query_text")


def test_search_rejects_limit_too_big():
    data = good_search()
    data["limit"] = 50
    assert_refused(client.post("/examples/search", json=data), "limit")


def test_search_rejects_limit_zero():
    data = good_search()
    data["limit"] = 0
    assert_refused(client.post("/examples/search", json=data), "limit")


def test_search_rejects_extra_field():
    data = good_search()
    data["extra"] = "sneaky"
    assert_extra_field_refused(client.post("/examples/search", json=data))


# In plain English: the list address needs a real UUID too.
def test_list_rejects_bad_uuid():
    response = client.get("/examples", params={"assignment_id": "not-a-uuid"})
    assert response.status_code == 422
    assert list(response.json().keys()) == ["problems"]


# In plain English: the refusal must not repeat the caller's secret-looking
# text anywhere in the reply.
def test_refusal_does_not_echo_input():
    data = good_example()
    data["assignment_id"] = "SECRET-MARKER-12345"
    response = client.post("/examples", json=data)
    assert response.status_code == 422
    assert "SECRET-MARKER-12345" not in response.text


# In plain English: a null character (the invisible character with code zero)
# cannot be stored by Postgres. It must be turned away at the door as bad input
# (422), and never reach the database and come back as a 503 "try again later",
# which a client would retry forever.
def test_save_rejects_null_characters_in_every_text_field():
    for field in ("student_work", "grade", "reasoning"):
        data = good_example()
        data[field] = "abc\u0000def"
        response = client.post("/examples", json=data)
        assert_refused(response, field)
        assert "abc" not in response.text


def test_search_rejects_null_characters_in_the_query():
    data = good_search()
    data["query_text"] = "abc\u0000def"
    response = client.post("/examples/search", json=data)
    assert_refused(response, "query_text")
    assert "abc" not in response.text


# In plain English: the reason for a bad UUID must be fixed wording. The built-in
# wording quotes the offending character, and the README promises the reply never
# repeats what the caller sent.
def test_bad_uuid_reason_is_fixed_wording_everywhere():
    data = good_example()
    data["assignment_id"] = "SECRET-MARKER-12345"
    saved = client.post("/examples", json=data).json()
    assert saved == {"problems": [{"field": "body.assignment_id", "reason": "Input should be a valid UUID"}]}
    listed = client.get("/examples", params={"assignment_id": "SECRET-MARKER-12345"}).json()
    assert listed == {"problems": [{"field": "query.assignment_id", "reason": "Input should be a valid UUID"}]}


# In plain English: for any kind of error we have not looked at one by one, the
# reply says only "Invalid value". Here a broken JSON body is cut off in the
# middle of a text, and none of that text may come back.
def test_unknown_kinds_of_error_get_generic_wording():
    response = client.post(
        "/examples",
        content='{"student_work": "SECRET-MARKER',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert "SECRET-MARKER" not in response.text
    assert [problem["reason"] for problem in response.json()["problems"]] == ["Invalid value"]


# In plain English: a caller can pick any name for an extra field, so the name is
# caller data too. Using a secret-looking name shows whether it comes back.
def test_extra_field_names_are_never_echoed():
    save_data = good_example()
    save_data["SECRET-MARKER-12345"] = "x"
    save_response = client.post("/examples", json=save_data)
    assert_extra_field_refused(save_response)
    assert "SECRET-MARKER-12345" not in save_response.text

    search_data = good_search()
    search_data["SECRET-MARKER-12345"] = "x"
    search_response = client.post("/examples/search", json=search_data)
    assert_extra_field_refused(search_response)
    assert "SECRET-MARKER-12345" not in search_response.text


# In plain English: the borrow flag must be a real true or false. Words like "yes" and
# numbers like 1 are refused, so nobody turns the fallback on by accident with a value
# that only looks like true.
def test_search_rejects_a_fallback_flag_that_is_not_true_or_false():
    for bad in ("yes", 1, "maybe"):
        data = good_search()
        data["fallback_to_all"] = bad
        assert_refused(client.post("/examples/search", json=data), "fallback_to_all")
