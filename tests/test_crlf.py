# In plain English: tests that carriage-return and line-feed characters in anything a caller, a
# Kafka producer or a student sends can never split a web reply header or forge a new line in a log.
#
# Why it matters: a line break inside a header lets an attacker add headers of their own (for
# example a cookie), and a line break inside a log message lets them write fake log lines that
# look like real events. Both are old, well-known attacks (OWASP A05, CWE-93 and CWE-113, and
# log forging, CWE-117).
#
# Part 1 sends line breaks through every place the web service takes text and checks no reply
# header ever carries them. Part 2 sends hostile text through the three Kafka programs and checks no
# log line carries it. Part 3 checks the Kafka key must be a UUID written the normal way: Python's own
# UUID reader also accepts odd forms (a trailing newline, spaces, a plus sign, a 0x prefix), and
# before this guardrail one of those was copied into a log line by the results consumer.
import json
import logging
import uuid
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from app.job_sender import build_message as build_job
from app.main import app
from app.results_consumer import _key_text, handle_message, run
from app.sender import send_batch
from conftest import AUTH_HEADERS
from test_results_consumer import FakeConsumer, FakeMessage, FakeProducer, good_value, recorder_new

MARKER = "CRLF-MARKER"
# A header-splitting attempt and a log-forging attempt in one string.
ATTACK = f"x\r\nSet-Cookie: pwned=1\r\nX-{MARKER}: 1\r\n2026-10-10 INFO offset 0: saved {MARKER}"
UUID_QUIRKS = [
    "1234567812345678123456781234567\n",  # 31 digits and a newline: Python reads this as a UUID
    "12345678-1234-5678-1234-56781234567\r",
    " 1234567812345678123456781234567",
    "+1234567812345678123456781234567",
    "0x234567812345678123456781234567",
    "{12345678-1234-5678-1234-567812345678}",
    "urn:uuid:12345678-1234-5678-1234-567812345678",
    "12345678123456781234567812345678",  # no hyphens
]

bare = TestClient(app, headers=AUTH_HEADERS)


# In plain English: no reply header may contain a line break, a cookie we did not set, or any of the
# attacker's text.
def assert_headers_clean(response):
    for name, value in response.headers.items():
        assert "\r" not in name and "\n" not in name and "\r" not in value and "\n" not in value, (name, value)
        assert MARKER.lower() not in name.lower() and MARKER not in value, (name, value)
        assert "pwned" not in value, (name, value)
    assert "set-cookie" not in response.headers


# ---------- Part 1: reply headers ----------

def test_line_breaks_in_requests_never_reach_reply_headers_on_the_refusal_paths():
    some_id = "11111111-1111-4111-8111-111111111111"
    replies = [
        bare.get("/assignments", params={"limit": ATTACK}),
        bare.get("/submissions", params={"status": ATTACK}),
        bare.get("/submissions", params={"x": ATTACK}),  # the required status is missing
        bare.get("/assignments/" + quote(ATTACK)),
        bare.get("/submissions/" + quote(ATTACK)),
        bare.post("/assignments", json={"nope": ATTACK}),
        bare.post("/submissions", json={"submission_id": ATTACK, "assignment_id": ATTACK, "student_name": ATTACK, "submission_text": ATTACK}),
        bare.post(f"/submissions/{quote(ATTACK)}/grades", json={"based_on_version": 1, "ai_grade": ATTACK, "ai_reasoning": ATTACK}),
        bare.post(f"/submissions/{some_id}/reviews", json={"based_on_version": "x", "decision": ATTACK, "reviewer_username": ATTACK}),
        TestClient(app).get("/assignments", params={"limit": ATTACK}),  # no key at all
        TestClient(app, headers={"Authorization": "Bearer %0d%0aSet-Cookie:%20pwned=1"}).get("/assignments"),
    ]
    for reply in replies:
        assert_headers_clean(reply)
    assert [r.status_code for r in replies[:9]] == [422] * 9
    assert [r.status_code for r in replies[9:]] == [401, 401]


@pytest.mark.usefixtures("require_test_database")
def test_line_breaks_in_saved_text_never_reach_reply_headers_through_the_whole_cycle():
    made = bare.post("/assignments", json={"instructor_username": ATTACK, "title": f"{ATTACK} {uuid.uuid4()}", "rubric": ATTACK})
    assert made.status_code == 201  # control: the text is accepted as plain text
    assignment_id = made.json()["assignment_id"]
    submission_id = str(uuid.uuid4())
    replies = [
        made,
        bare.get(f"/assignments/{assignment_id}"),
        bare.get("/assignments"),
        bare.post("/submissions", json={"submission_id": submission_id, "assignment_id": assignment_id, "student_name": ATTACK, "submission_text": ATTACK}),
        bare.post(f"/submissions/{submission_id}/grades", json={"based_on_version": 1, "ai_grade": "B", "ai_reasoning": ATTACK}),
        bare.post(f"/submissions/{submission_id}/reviews", json={"based_on_version": 2, "decision": "reject", "reviewer_username": ATTACK, "feedback": ATTACK}),
        bare.get(f"/submissions/{submission_id}"),
        bare.get("/submissions", params={"status": "rejected", "assignment_id": assignment_id}),
    ]
    for reply in replies:
        assert reply.status_code in (200, 201), reply.text
        assert_headers_clean(reply)


# ---------- Part 2: log lines ----------

def assert_logs_clean(caplog):
    assert caplog.records, "nothing was logged, so this check would pass by accident"
    for record in caplog.records:
        line = record.getMessage()
        assert "\r" not in line and "\n" not in line, repr(line)
        assert MARKER not in line, repr(line)
        assert "Set-Cookie" not in line, repr(line)


def test_the_results_consumer_never_puts_line_breaks_or_input_into_the_log(caplog):
    from app.grades import SubmissionMovedOn

    def outdated(submission_id, grade):
        raise SubmissionMovedOn()

    log = []
    ok = good_value(ai_reasoning=ATTACK)
    upper = good_value()
    messages = [FakeMessage(quirk.encode(), json.dumps(good_value(submission_id=quirk)).encode(), index) for index, quirk in enumerate(UUID_QUIRKS)]
    messages += [
        FakeMessage(ATTACK.encode(), ATTACK.encode(), 20),
        FakeMessage(None, None, 21),
        FakeMessage(b"\xff\xfe\r\n", b"\xff\xfe\r\n", 22),
        FakeMessage(ok["submission_id"].encode(), json.dumps(ok).encode(), 23),  # valid key, hostile text, outdated outcome
        FakeMessage(upper["submission_id"].upper().encode(), json.dumps(upper).encode(), 24),  # valid key in capitals, outdated outcome
    ]
    fake = FakeConsumer(messages, log)
    with caplog.at_level(logging.DEBUG):
        run(fake, FakeProducer(log), record=outdated, should_stop=lambda: not fake.messages)
    assert_logs_clean(caplog)
    assert any("outdated" in record.getMessage() for record in caplog.records)  # the risky log line did run


# In plain English: the one place a Kafka key is written into a log line rewrites it from the UUID it
# stands for. Even though the key check now refuses odd keys first, this second line of defence is
# tested on its own: whatever bytes are given, the text returned has no line break and no input text.
@pytest.mark.parametrize("raw", [quirk.encode() for quirk in UUID_QUIRKS] + [ATTACK.encode(), b"\xff\xfe\r\n", None, b""])
def test_the_key_as_shown_in_a_log_line_never_carries_input(raw):
    shown = _key_text(raw)
    assert "\r" not in shown and "\n" not in shown and MARKER not in shown and " " not in shown
    assert shown == "unreadable" or len(shown) == 36


def test_the_senders_never_put_line_breaks_or_student_text_into_the_log(caplog):
    class Store:
        def __init__(self, rows):
            self.rows = rows

        def fetch(self, limit, skip=()):
            return [r for r in self.rows if r[0] not in skip and (r[0], 1) not in skip]

        def record(self, identity):
            pass

    bad_approved = (uuid.uuid4(), uuid.uuid4(), ATTACK, "", ATTACK)  # an empty grade makes it unbuildable
    bad_job = (uuid.uuid4(), 1, uuid.uuid4(), "", ATTACK, ATTACK)  # an empty rubric makes it unbuildable
    with caplog.at_level(logging.DEBUG):
        send_batch(FakeProducerForSender(), Store([bad_approved]).fetch, lambda identity: None, skipped=set())
        send_batch(
            FakeProducerForSender(), Store([bad_job]).fetch, lambda identity: None, skipped=set(),
            topic="grading-jobs", build=build_job, identify=lambda row: (row[0], row[1]),
        )
    assert_logs_clean(caplog)


class FakeProducerForSender:
    def produce(self, topic, key=None, value=None, on_delivery=None):
        raise AssertionError("an unbuildable row must never be published")

    def flush(self, timeout=None):
        return 0


# ---------- Part 3: the key must be a UUID written the normal way ----------

@pytest.mark.parametrize("quirk", UUID_QUIRKS)
def test_a_key_that_is_not_a_normally_written_uuid_is_refused_even_when_python_would_read_it(quirk):
    data = good_value(submission_id=quirk)
    outcome = handle_message(quirk.encode(), json.dumps(data).encode(), record=recorder_new)
    assert outcome[0] == "dead_letter", (quirk, outcome)


def test_the_normal_form_still_works_in_lower_and_upper_case():
    data = good_value()
    label = data["submission_id"]
    assert handle_message(label.encode(), json.dumps(data).encode(), record=recorder_new) == ("saved", None)
    assert handle_message(label.upper().encode(), json.dumps(data).encode(), record=recorder_new) == ("saved", None)
