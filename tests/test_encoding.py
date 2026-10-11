# In plain English: tests about how this service reads and writes text, so what it sends out means the
# same thing to every reader and odd characters are never mishandled.
#
# Part 1: every reply is JSON, labelled as JSON, and decodes to exactly what was stored. Text that
# looks like web page code (<script>) is only ever data inside that JSON.
# Part 2: unusual characters (invisible marks, terminal escape codes, text-direction tricks, the
# highest Unicode character, a half-written character) either round-trip exactly or are refused with
# a normal 422. They never cause a crash (a 500) or a changed value.
# Part 3: what the Kafka senders write is plain, unambiguous JSON (no field twice, no NaN), and a Kafka
# message that says the same field twice, or contains NaN or Infinity, is refused: different programs
# read duplicates differently (some keep the first, some the last).
# (OWASP A05: CWE-115, CWE-116 and CWE-159.)
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.job_sender import build_message as build_job
from app.main import app
from app.results_consumer import handle_message
from app.sender import build_message as build_approved
from conftest import AUTH_HEADERS
from test_results_consumer import good_value, recorder_new

bare = TestClient(app, headers=AUTH_HEADERS)

# Text that is easy to mishandle. Each one is either stored exactly or refused with a 422.
SPECIALS = [
    "<script>alert(1)</script>",
    "</textarea><img src=x onerror=alert(1)>",
    "&amp; &lt; &#60; %3Cscript%3E",
    "\\u0041 \\n \\x41 \\\\",
    "\x1b[31mred\x1b[0m terminal escape",
    "‮evil‬ text-direction override",
    "﻿starts with a byte order mark",
    "\x7f delete character",
    "line separator paragraph",
    "\U0010ffff highest character",
    "tab\tinside and \x0b vertical tab",
    "emoji 👩‍💻 and combining é",
]


def make_assignment(**change):
    data = {"instructor_username": "instructor1", "title": f"Essay {uuid.uuid4()}", "rubric": "Grade it."}
    data.update(change)
    return bare.post("/assignments", json=data)


def make_submission(assignment_id, **change):
    data = {"submission_id": str(uuid.uuid4()), "assignment_id": assignment_id, "student_name": "Alex", "submission_text": "My essay."}
    data.update(change)
    return bare.post("/submissions", json=data), data["submission_id"]


# ---------- Part 1: every reply is JSON ----------

def assert_json_reply(response):
    assert response.headers["content-type"].split(";")[0] == "application/json", response.headers["content-type"]
    return response.json()  # decodes, or the test fails


@pytest.mark.owasp("A05", 115, 116, 159)
def test_error_replies_are_labelled_json_and_decode():
    for reply in (
        bare.get("/assignments", params={"limit": "x"}),
        bare.post("/assignments", json={"nope": "<script>"}),
        bare.get("/nothing-here"),
        TestClient(app).get("/assignments"),
        TestClient(app).get("/health"),
    ):
        assert_json_reply(reply)


@pytest.mark.usefixtures("require_test_database")
@pytest.mark.owasp("A05", 115, 116, 159)
def test_success_replies_are_labelled_json_and_html_like_text_stays_data():
    made = make_assignment(rubric="<script>alert(1)</script>")
    assert made.status_code == 201
    assignment_id = assert_json_reply(made)["assignment_id"]
    assert assert_json_reply(bare.get(f"/assignments/{assignment_id}"))["rubric"] == "<script>alert(1)</script>"
    reply, submission_id = make_submission(assignment_id, submission_text="</textarea><b>")
    assert reply.status_code == 201
    assert assert_json_reply(bare.get(f"/submissions/{submission_id}"))["submission_text"] == "</textarea><b>"
    assert_json_reply(bare.get("/assignments"))


# ---------- Part 2: unusual characters ----------

@pytest.mark.usefixtures("require_test_database")
@pytest.mark.parametrize("special", SPECIALS)
@pytest.mark.owasp("A05", 115, 116, 159)
def test_unusual_characters_are_stored_exactly_or_refused_never_a_crash(special):
    made = make_assignment(rubric=special, title=f"{special} {uuid.uuid4()}")
    assert made.status_code in (201, 422), (special, made.status_code, made.text)
    assignment_id = None
    if made.status_code == 201:
        assignment_id = made.json()["assignment_id"]
        assert bare.get(f"/assignments/{assignment_id}").json()["rubric"] == special
    if assignment_id is None:
        assignment_id = make_assignment().json()["assignment_id"]
    reply, submission_id = make_submission(assignment_id, submission_text=special, student_name=special)
    assert reply.status_code in (201, 422), (special, reply.status_code, reply.text)
    if reply.status_code == 201:
        found = bare.get(f"/submissions/{submission_id}").json()
        assert found["submission_text"] == special and found["student_name"] == special.strip()
        graded = bare.post(f"/submissions/{submission_id}/grades", json={"based_on_version": 1, "ai_grade": "B", "ai_reasoning": special})
        assert graded.status_code in (201, 422), (special, graded.status_code)


@pytest.mark.usefixtures("require_test_database")
@pytest.mark.owasp("A05", 115, 116, 159)
def test_a_half_written_character_and_a_null_are_refused_with_a_normal_422():
    assignment_id = make_assignment().json()["assignment_id"]  # control: the route works
    for escaped in ('"\\ud800"', '"a\\u0000b"', '"\\udfff"'):
        raw = ('{"submission_id": "%s", "assignment_id": "%s", "student_name": "A", "submission_text": %s}' % (uuid.uuid4(), assignment_id, escaped)).encode()
        reply = bare.post("/submissions", content=raw, headers={"Content-Type": "application/json"})
        assert reply.status_code == 422, (escaped, reply.status_code)
        assert_json_reply(reply)


@pytest.mark.owasp("A05", 115, 116, 159)
def test_a_request_that_is_not_valid_utf8_or_not_json_is_a_client_error_not_a_crash():
    for raw in (b'{"title": "\xff\xfe"}', b"{not json", b"", b"[1,2,3]", b'"just a string"'):
        reply = bare.post("/assignments", content=raw, headers={"Content-Type": "application/json"})
        assert reply.status_code in (400, 422), (raw, reply.status_code)  # the framework answers 400 for undecodable text
        assert_json_reply(reply)
        assert "not json" not in reply.text and "just a string" not in reply.text


# ---------- Part 3: unambiguous Kafka messages ----------

def strict_loads(raw):
    def no_repeats(pairs):
        names = [name for name, _ in pairs]
        assert len(names) == len(set(names)), f"repeated field in {raw!r}"
        return dict(pairs)

    def no_special(token):
        raise AssertionError(f"special number {token} in {raw!r}")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=no_repeats, parse_constant=no_special)


@pytest.mark.owasp("A05", 115, 116, 159)
def test_what_the_senders_write_is_plain_unambiguous_json():
    for special in SPECIALS:
        _, approved = build_approved((uuid.uuid4(), uuid.uuid4(), special, "A", special))
        assert strict_loads(approved)["student_work"] == special.strip()
        _, job = build_job((uuid.uuid4(), 1, uuid.uuid4(), special, special, special))
        data = strict_loads(job)
        assert data["rubric"] == special and data["student_work"] == special and data["feedback"] == special


def message(text):
    data = good_value()
    return data["submission_id"].encode(), text.replace("SUB", data["submission_id"]).encode()


@pytest.mark.owasp("A05", 115, 116, 159)
def test_a_result_that_repeats_a_field_is_refused_as_invalid_json():
    for text in (
        '{"schema_version":1,"submission_id":"SUB","based_on_version":1,"ai_grade":"A","ai_grade":"F","ai_reasoning":"r"}',
        '{"schema_version":1,"schema_version":2,"submission_id":"SUB","based_on_version":1,"ai_grade":"A","ai_reasoning":"r"}',
        '{"schema_version":1,"submission_id":"SUB","submission_id":"SUB","based_on_version":1,"ai_grade":"A","ai_reasoning":"r"}',
        '{"schema_version":1,"submission_id":"SUB","based_on_version":1,"based_on_version":3,"ai_grade":"A","ai_reasoning":"r"}',
    ):
        key, value = message(text)
        assert handle_message(key, value, record=recorder_new) == ("dead_letter", "invalid_json"), text
    key, control = message('{"schema_version":1,"submission_id":"SUB","based_on_version":1,"ai_grade":"A","ai_reasoning":"r"}')
    assert handle_message(key, control, record=recorder_new) == ("saved", None)


@pytest.mark.owasp("A05", 115, 116, 159)
def test_a_result_with_nan_or_infinity_is_refused_as_invalid_json():
    for token in ("NaN", "Infinity", "-Infinity"):
        key, value = message('{"schema_version":1,"submission_id":"SUB","based_on_version":%s,"ai_grade":"A","ai_reasoning":"r"}' % token)
        assert handle_message(key, value, record=recorder_new) == ("dead_letter", "invalid_json"), token


# A half-written character or a null inside a Kafka message must be refused as a bad field. If it slipped
# through, recording it would crash the consumer and the same message would crash it again after every
# restart.
@pytest.mark.owasp("A05", 115, 116, 159)
def test_a_half_written_character_or_a_null_in_a_result_is_a_bad_field_not_a_crash():
    for escaped in ("a\\ud800b", "\\udfff", "a\\u0000b"):
        key, value = message('{"schema_version":1,"submission_id":"SUB","based_on_version":1,"ai_grade":"A","ai_reasoning":"%s"}' % escaped)
        assert handle_message(key, value, record=recorder_new) == ("dead_letter", "invalid_field"), escaped
