# In plain English: tests for the results consumer, the program that takes grades back from the
# grader off the Kafka topic "grading-results" and records them. The message format is the
# shared contract in platform/contracts/grading-results.md. Most tests use a pretend Kafka and
# a pretend recorder, so they need nothing running. The last tests use the real database
# (guarded like the other database tests) to check a grade is really recorded, a repeat is
# recognised and a stale result is dropped.
#
# The promise they protect: a message is marked "done" (committed) only AFTER it has been dealt
# with, so a crash never loses one. A message that can never be recorded is copied to the
# dead-letter topic (and that copy must be CONFIRMED delivered before the commit), and trouble
# that may pass (database or Kafka down) commits nothing so the message is tried again.
import json
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient

from app import results_consumer
from app.grades import (
    GRADE_MAX,
    REASONING_MAX,
    NotWaitingForGrade,
    SubmissionMovedOn,
    SubmissionNotFound,
    VersionDoesNotExist,
)
from app.main import app
from app.results_consumer import DEAD_LETTER_TOPIC, TOPIC, handle_message, run
from conftest import AUTH_HEADERS

# The reader's limits, copied from the table in platform/contracts/grading-results.md.
CONTRACT_READER_LIMITS = {"ai_grade": 20, "ai_reasoning": 10_000}


def good_value(**change):
    data = {
        "schema_version": 1,
        "submission_id": str(uuid.uuid4()),
        "based_on_version": 1,
        "ai_grade": "B",
        "ai_reasoning": "Clear but short.",
    }
    data.update(change)
    return data


def encode(data):
    return json.dumps(data).encode("utf-8")


def keyed(data):
    return data["submission_id"].encode(), encode(data)


def recorder_new(submission_id, grade):
    return {"version": grade.based_on_version + 1}, True


def recorder_repeat(submission_id, grade):
    return {"version": grade.based_on_version + 1}, False


def never_record(submission_id, grade):
    raise AssertionError("a bad message must never reach the recorder")


# ---------- handle_message: what happens to each kind of message ----------

def test_a_good_result_is_recorded_with_the_version_it_names():
    data = good_value(based_on_version=3, ai_grade="  A  ")
    seen = []

    def record(submission_id, grade):
        seen.append((submission_id, grade))
        return {}, True

    assert handle_message(*keyed(data), record=record) == ("saved", None)
    submission_id, grade = seen[0]
    assert str(submission_id) == data["submission_id"]
    assert (grade.based_on_version, grade.ai_grade, grade.ai_reasoning) == (3, "A", "Clear but short.")


def test_a_repeat_is_recognised_and_not_an_error():
    assert handle_message(*keyed(good_value()), record=recorder_repeat) == ("repeat", None)


def test_reasoning_is_kept_exactly_as_written():
    seen = []

    def record(submission_id, grade):
        seen.append(grade)
        return {}, True

    handle_message(*keyed(good_value(ai_reasoning="  why  ")), record=record)
    assert seen[0].ai_reasoning == "  why  "


def _without(field):
    data = good_value()
    key = data["submission_id"].encode()
    del data[field]
    return key, encode(data)


def bad_cases():
    other_key = str(uuid.uuid4()).encode()
    return {
        "invalid_json": (other_key, b"{not json", "invalid_json"),
        "not_utf8": (other_key, b"\xff\xfe", "invalid_json"),
        "not_an_object": (other_key, b"[1, 2]", "invalid_json"),
        "empty_value": (other_key, None, "invalid_json"),
        "unknown_version": (*keyed(good_value(schema_version=2)), "unknown_schema_version"),
        "missing_version": (*_without("schema_version"), "unknown_schema_version"),
        "version_true_is_not_one": (*keyed(good_value(schema_version=True)), "unknown_schema_version"),
        "empty_grade": (*keyed(good_value(ai_grade="")), "invalid_field"),
        "blank_grade": (*keyed(good_value(ai_grade="   ")), "invalid_field"),
        "grade_too_long": (*keyed(good_value(ai_grade="g" * (GRADE_MAX + 1))), "invalid_field"),
        "blank_reasoning": (*keyed(good_value(ai_reasoning="   ")), "invalid_field"),
        "reasoning_too_long": (*keyed(good_value(ai_reasoning="r" * (REASONING_MAX + 1))), "invalid_field"),
        "null_character": (*keyed(good_value(ai_reasoning="a\x00b")), "invalid_field"),
        "bad_uuid": (b"nope", encode(good_value(submission_id="nope")), "invalid_field"),
        "version_zero": (*keyed(good_value(based_on_version=0)), "invalid_field"),
        "version_as_text": (*keyed(good_value(based_on_version="1")), "invalid_field"),
        "extra_field": (*keyed(good_value(student_name="Ann")), "invalid_field"),
        "missing_grade": (*_without("ai_grade"), "invalid_field"),
        "key_mismatch": (other_key, encode(good_value()), "key_mismatch"),
        "key_missing": (None, encode(good_value()), "key_mismatch"),
    }


@pytest.mark.parametrize("name", sorted(bad_cases()))
@pytest.mark.owasp("A05", 20)
def test_a_bad_message_is_dead_lettered_with_its_code_and_never_recorded(name):
    key, value, reason = bad_cases()[name]
    assert handle_message(key, value, record=never_record) == ("dead_letter", reason)


def test_the_longest_allowed_result_is_accepted():
    data = good_value(ai_grade="g" * GRADE_MAX, ai_reasoning="r" * REASONING_MAX)
    assert handle_message(*keyed(data), record=recorder_new) == ("saved", None)


def test_a_result_for_a_submission_that_does_not_exist_is_dead_lettered():
    def record(submission_id, grade):
        raise SubmissionNotFound()

    assert handle_message(*keyed(good_value()), record=record) == ("dead_letter", "unknown_submission")


# A normal race, not an error: the submission moved on, or another grade for that version won.
@pytest.mark.parametrize("error", [SubmissionMovedOn(), NotWaitingForGrade()])
def test_an_out_of_date_result_is_dropped_not_dead_lettered(error):
    def record(submission_id, grade):
        raise error

    assert handle_message(*keyed(good_value()), record=record) == ("outdated", None)


# A grader that copies back a version the submission never had is a bug, not a race. Dropping it
# quietly would hide the bug (every result would vanish with one info line), so it is dead-lettered
# where a person will see it.
def test_a_result_for_a_version_that_never_existed_is_dead_lettered_not_dropped():
    def record(submission_id, grade):
        raise VersionDoesNotExist()

    assert handle_message(*keyed(good_value()), record=record) == ("dead_letter", "unknown_version")


def test_a_version_that_never_existed_is_a_kind_of_moved_on_so_the_route_still_answers_409():
    assert issubclass(VersionDoesNotExist, SubmissionMovedOn)


# A save the database refuses for this message alone would fail the same way every time, so it
# is dead-lettered instead of blocking its lane for ever.
@pytest.mark.parametrize("error", [psycopg.DataError("bad"), psycopg.IntegrityError("rule")])
def test_a_save_the_database_refuses_for_this_message_is_dead_lettered(error):
    def record(submission_id, grade):
        raise error

    assert handle_message(*keyed(good_value()), record=record) == ("dead_letter", "record_rejected")


def test_a_database_outage_is_not_swallowed():
    def record(submission_id, grade):
        raise psycopg.OperationalError("down")

    with pytest.raises(psycopg.OperationalError):
        handle_message(*keyed(good_value()), record=record)


@pytest.mark.owasp("A09", 532)
def test_the_reason_never_contains_the_student_text_or_the_reasoning():
    data = good_value(ai_reasoning="SECRET-MARKER", ai_grade="")
    assert "SECRET-MARKER" not in repr(handle_message(*keyed(data), record=never_record))


# ---------- the limits fit at both ends ----------

def test_the_consumer_accepts_exactly_what_the_contract_table_says():
    assert (GRADE_MAX, REASONING_MAX) == (CONTRACT_READER_LIMITS["ai_grade"], CONTRACT_READER_LIMITS["ai_reasoning"])


# ---------- run: the loop and the order of "done" ----------

class FakeMessage:
    def __init__(self, key, value, offset=0, error=None):
        self._key, self._value, self._offset, self._error = key, value, offset, error

    def key(self):
        return self._key

    def value(self):
        return self._value

    def offset(self):
        return self._offset

    def error(self):
        return self._error


class FakeConsumer:
    def __init__(self, messages, log):
        self.messages = list(messages)
        self.log = log
        self.subscribed = None
        self.closed = False

    def subscribe(self, topics):
        self.subscribed = topics

    def poll(self, timeout):
        # A loop that keeps polling after the messages ran out would hang a test forever.
        assert self.messages, "polled after the messages ran out"
        return self.messages.pop(0)

    def commit(self, message=None, asynchronous=True):
        assert asynchronous is False
        self.log.append(("commit", message.offset()))

    def close(self):
        self.closed = True


class FakeProducer:
    # "rejected" pretends the broker refused the copy: the delivery callback gets an error
    # while flush() still reports nothing queued, as real Kafka does.
    def __init__(self, log, left_over=0, rejected=False):
        self.log = log
        self.left_over = left_over
        self.rejected = rejected
        self.callbacks = []

    def produce(self, topic, key=None, value=None, headers=None, on_delivery=None):
        self.log.append(("produce", topic, key, value, headers))
        self.callbacks.append(on_delivery)

    def flush(self, timeout=None):
        self.log.append(("flush",))
        for callback in self.callbacks:
            if callback is not None:
                callback("broker said no" if self.rejected else None, None)
        return self.left_over


def run_with(messages, record, left_over=0):
    log = []
    fake = FakeConsumer(messages, log)
    run(fake, FakeProducer(log, left_over), record=record, should_stop=lambda: not fake.messages)
    return fake, log


def test_the_loop_subscribes_to_the_agreed_topic():
    fake, _ = run_with([], recorder_new)
    assert fake.subscribed == [TOPIC] == ["grading-results"]
    assert fake.closed


def test_a_message_is_committed_only_after_it_is_recorded():
    order = []

    def record(submission_id, grade):
        order.append("recorded")
        return {}, True

    class Recording(FakeConsumer):
        def commit(self, message=None, asynchronous=True):
            order.append("commit")
            super().commit(message, asynchronous)

    log = []
    fake = Recording([FakeMessage(*keyed(good_value()), 7)], log)
    run(fake, FakeProducer(log), record=record, should_stop=lambda: not fake.messages)
    assert order == ["recorded", "commit"]
    assert log == [("commit", 7)]


def test_a_database_failure_means_no_commit_and_the_loop_stops():
    def record(submission_id, grade):
        raise psycopg.OperationalError("down")

    log = []
    fake = FakeConsumer([FakeMessage(*keyed(good_value()), 3)], log)
    with pytest.raises(psycopg.OperationalError):
        run(fake, FakeProducer(log), record=record, should_stop=lambda: False)
    assert log == []
    assert fake.closed


def test_a_bad_message_is_copied_to_the_dead_letter_topic_before_the_commit():
    _, log = run_with([FakeMessage(b"k", b"{oops", 5)], never_record)
    assert [entry[0] for entry in log] == ["produce", "flush", "commit"]
    _, topic, key, value, headers = log[0]
    assert topic == DEAD_LETTER_TOPIC == "grading-results.dead-letter"
    assert key == b"k" and value == b"{oops"
    assert dict(headers)["error"] == b"invalid_json"
    assert log[2] == ("commit", 5)


def test_a_dead_letter_the_broker_refused_is_not_committed():
    log = []
    fake = FakeConsumer([FakeMessage(b"k", b"{oops", 5)], log)
    with pytest.raises(RuntimeError):
        run(fake, FakeProducer(log, rejected=True), record=never_record, should_stop=lambda: False)
    assert ("commit", 5) not in log


def test_a_dead_letter_that_is_not_flushed_is_not_committed():
    log = []
    fake = FakeConsumer([FakeMessage(b"k", b"{oops", 5)], log)
    with pytest.raises(RuntimeError):
        run(fake, FakeProducer(log, left_over=1), record=never_record, should_stop=lambda: False)
    assert ("commit", 5) not in log


def test_a_repeat_and_an_outdated_result_are_committed_and_nothing_is_dead_lettered(caplog):
    def outdated(submission_id, grade):
        raise SubmissionMovedOn()

    _, log = run_with([FakeMessage(*keyed(good_value()), 1)], recorder_repeat)
    assert log == [("commit", 1)]
    data = good_value()
    with caplog.at_level("INFO"):
        _, log = run_with([FakeMessage(*keyed(data), 2)], outdated)
    assert log == [("commit", 2)]
    assert data["submission_id"] in caplog.text and "outdated" in caplog.text


def test_messages_are_handled_in_order_each_committed_in_turn():
    _, log = run_with(
        [FakeMessage(*keyed(good_value()), 1), FakeMessage(b"bad", b"{", 2), FakeMessage(*keyed(good_value()), 3)],
        recorder_new,
    )
    assert [entry for entry in log if entry[0] == "commit"] == [("commit", 1), ("commit", 2), ("commit", 3)]


def test_a_kafka_error_stops_the_loop_without_a_commit():
    log = []
    fake = FakeConsumer([FakeMessage(None, None, 9, error="broker gone")], log)
    with pytest.raises(RuntimeError):
        run(fake, FakeProducer(log), record=never_record, should_stop=lambda: False)
    assert log == []


# ---------- the settings ----------

def test_the_group_and_manual_commit_settings():
    settings = results_consumer.consumer_settings({"KAFKA_BOOTSTRAP": "kafka:9092"})
    assert settings["group.id"] == "assessment-grading-results"
    assert settings["enable.auto.commit"] is False
    assert settings["auto.offset.reset"] == "earliest"
    assert settings["bootstrap.servers"] == "kafka:9092"


def test_a_missing_bootstrap_setting_stops_early():
    with pytest.raises(RuntimeError):
        results_consumer.consumer_settings({})


def test_the_real_program_starts_and_stops_cleanly_with_a_pretend_kafka_library(monkeypatch):
    # A deployed pod once crashed because main() passed run() an argument it did not take. This
    # runs main() itself, with a pretend Kafka library, and stops it the way Kubernetes does.
    import signal
    import sys
    import types

    started = {}

    class PretendConsumer:
        def __init__(self, settings):
            started["group"] = settings["group.id"]
            self.closed = False

        def subscribe(self, topics):
            started["topics"] = topics

        def poll(self, timeout):
            signal.raise_signal(signal.SIGINT)  # as if Kubernetes asked it to stop
            return None

        def close(self):
            started["closed"] = True

    class PretendProducer:
        def __init__(self, settings):
            started["producer"] = settings["bootstrap.servers"]

    monkeypatch.setitem(sys.modules, "confluent_kafka", types.SimpleNamespace(Consumer=PretendConsumer, Producer=PretendProducer))
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "kafka:9092")
    previous = signal.getsignal(signal.SIGINT)
    try:
        results_consumer.main()
    finally:
        signal.signal(signal.SIGINT, previous)
    assert started == {"group": "assessment-grading-results", "topics": ["grading-results"], "closed": True, "producer": "kafka:9092"}


# ---------- with the real database ----------

client = TestClient(app, headers=AUTH_HEADERS)


def new_submission():
    assignment = client.post(
        "/assignments",
        json={"instructor_username": "instructor1", "title": f"Essay {uuid.uuid4()}", "rubric": "Grade it."},
    ).json()["assignment_id"]
    submission_id = str(uuid.uuid4())
    assert client.post(
        "/submissions",
        json={"submission_id": submission_id, "assignment_id": assignment, "student_name": "Alex", "submission_text": "My essay."},
    ).status_code == 201
    return submission_id


def history(submission_id):
    return client.get(f"/submissions/{submission_id}").json()["history"]


@pytest.mark.usefixtures("require_test_database")
def test_a_good_result_is_really_recorded_then_recognised_as_a_repeat():
    submission_id = new_submission()
    data = good_value(submission_id=submission_id, ai_grade="A", ai_reasoning="Well argued.")
    assert handle_message(*keyed(data)) == ("saved", None)
    assert handle_message(*keyed(data)) == ("repeat", None)
    versions = history(submission_id)
    assert [v["status"] for v in versions] == ["submitted", "graded"]
    assert (versions[1]["ai_grade"], versions[1]["ai_reasoning"]) == ("A", "Well argued.")


@pytest.mark.usefixtures("require_test_database")
def test_a_second_different_grade_for_the_same_version_is_outdated_and_changes_nothing():
    submission_id = new_submission()
    assert handle_message(*keyed(good_value(submission_id=submission_id, ai_grade="A"))) == ("saved", None)
    assert handle_message(*keyed(good_value(submission_id=submission_id, ai_grade="F"))) == ("outdated", None)
    assert [v["ai_grade"] for v in history(submission_id)] == [None, "A"]


@pytest.mark.usefixtures("require_test_database")
def test_a_result_for_a_version_that_never_existed_is_dead_lettered():
    submission_id = new_submission()
    assert handle_message(*keyed(good_value(submission_id=submission_id, based_on_version=5))) == ("dead_letter", "unknown_version")
    assert len(history(submission_id)) == 1


@pytest.mark.usefixtures("require_test_database")
def test_a_result_for_an_older_version_is_still_just_outdated():
    submission_id = new_submission()
    assert handle_message(*keyed(good_value(submission_id=submission_id, based_on_version=1))) == ("saved", None)
    assert client.post(
        f"/submissions/{submission_id}/reviews",
        json={"based_on_version": 2, "decision": "reject", "reviewer_username": "instructor1", "feedback": "Redo."},
    ).status_code == 201
    # Version 1 did exist; the submission has simply moved on to version 3.
    assert handle_message(*keyed(good_value(submission_id=submission_id, based_on_version=1, ai_grade="Z"))) == ("outdated", None)


@pytest.mark.usefixtures("require_test_database")
def test_a_result_for_an_unknown_submission_is_dead_lettered():
    assert handle_message(*keyed(good_value())) == ("dead_letter", "unknown_submission")
