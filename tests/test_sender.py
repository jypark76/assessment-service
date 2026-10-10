# In plain English: tests for the sender, the program that passes approved examples on to
# the knowledge service through Kafka. The message format is the shared contract in
# platform/contracts/approved-examples.md. Most tests use a pretend Kafka and pretend
# database calls, so they need nothing running. The last tests use the real database
# (guarded like the other database tests) to check which submissions count as "waiting to
# be sent".
#
# The promise they protect: a submission is recorded as sent ONLY after Kafka confirms it
# arrived. Anything not confirmed is sent again on the next round. A repeat is harmless
# because the reader recognises it.
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app import sender
from app.grades import GRADE_MAX, REASONING_MAX
from app.main import app
from app.sender import TOPIC, build_message, send_batch
from app.submissions import TEXT_MAX
from conftest import AUTH_HEADERS

# The reader's limits, copied from the table in platform/contracts/approved-examples.md.
# If the contract changes, change this table, the sender and the reader together.
CONTRACT_READER_LIMITS = {"student_work": 20_000, "grade": 100, "reasoning": 10_000}


def row(**change):
    data = {
        "submission_id": uuid.uuid4(),
        "assignment_id": uuid.uuid4(),
        "submission_text": "Photosynthesis turns light into sugar.",
        "ai_grade": "A",
        "ai_reasoning": "Clear and correct.",
    }
    data.update(change)
    return (data["submission_id"], data["assignment_id"], data["submission_text"], data["ai_grade"], data["ai_reasoning"])


# ---------- the message follows the contract ----------

def test_the_message_has_exactly_the_contract_fields():
    submission_id, assignment_id, text, grade, reasoning = row()
    key, value = build_message((submission_id, assignment_id, text, grade, reasoning))
    assert key == str(submission_id).encode("utf-8")
    assert json.loads(value) == {
        "schema_version": 1,
        "source_submission_id": str(submission_id),
        "assignment_id": str(assignment_id),
        "student_work": text,
        "grade": grade,
        "reasoning": reasoning,
    }


def test_no_student_name_or_reviewer_ever_goes_into_the_message():
    _, value = build_message(row())
    for forbidden in ("student_name", "reviewer", "feedback", "created_at"):
        assert forbidden not in value.decode("utf-8")


def test_spaces_at_either_end_are_trimmed_like_the_contract_says():
    _, value = build_message(row(submission_text="  essay  ", ai_grade=" B ", ai_reasoning="\nwhy\n"))
    data = json.loads(value)
    assert (data["student_work"], data["grade"], data["reasoning"]) == ("essay", "B", "why")


def test_non_ascii_text_survives_as_utf8():
    _, value = build_message(row(submission_text="Café ☕ 学生"))
    assert json.loads(value.decode("utf-8"))["student_work"] == "Café ☕ 学生"


def test_the_longest_allowed_values_make_a_valid_message():
    key, value = build_message(row(submission_text="w" * TEXT_MAX, ai_grade="g" * GRADE_MAX, ai_reasoning="r" * REASONING_MAX))
    data = json.loads(value)
    assert len(data["student_work"]) == 20_000 and len(data["reasoning"]) == 10_000


# A row the contract would refuse must never be sent (it would only land in the reader's
# dead-letter topic), so building it fails instead.
@pytest.mark.parametrize(
    "bad",
    [
        {"submission_text": ""},
        {"submission_text": "   "},
        {"ai_grade": ""},
        {"ai_reasoning": ""},
        {"submission_text": "w" * 20_001},
        {"ai_grade": "g" * 101},
        {"ai_reasoning": "r" * 10_001},
        {"submission_text": "a\x00b"},
        {"ai_grade": None},
    ],
)
def test_a_row_the_contract_would_refuse_is_not_turned_into_a_message(bad):
    with pytest.raises(ValueError):
        build_message(row(**bad))


# ---------- the limits fit at both ends ----------

def test_the_sender_never_accepts_more_than_the_reader_does():
    assert TEXT_MAX <= CONTRACT_READER_LIMITS["student_work"]
    assert GRADE_MAX <= CONTRACT_READER_LIMITS["grade"]
    assert REASONING_MAX <= CONTRACT_READER_LIMITS["reasoning"]


def test_the_senders_own_message_rules_match_the_contract_table():
    limits = sender.MESSAGE_LIMITS
    assert limits == CONTRACT_READER_LIMITS


# ---------- the loop: record only after Kafka confirms ----------

class FakeProducer:
    # "refuse" is a set of keys the broker will refuse. A refusal is reported ONLY through
    # the delivery callback while flush() still returns 0, as real Kafka does.
    def __init__(self, refuse=(), left_over=0):
        self.refuse = set(refuse)
        self.left_over = left_over
        self.pending = []
        self.sent = []

    def produce(self, topic, key=None, value=None, on_delivery=None):
        self.sent.append((topic, key, value))
        self.pending.append((key, on_delivery))

    def flush(self, timeout=None):
        for key, callback in self.pending:
            callback("refused" if key in self.refuse else None, None)
        self.pending = []
        return self.left_over


class FakeStore:
    def __init__(self, rows):
        self.rows = list(rows)
        self.recorded = []

    def fetch(self, limit, skip=()):
        waiting = [r for r in self.rows if r[0] not in self.recorded and r[0] not in skip]
        return waiting[:limit]

    def record(self, submission_id):
        self.recorded.append(submission_id)


def batch(store, producer, limit=50, skipped=None):
    return send_batch(producer, store.fetch, store.record, limit=limit, skipped=skipped if skipped is not None else set())


def test_confirmed_messages_go_to_the_agreed_topic_and_are_recorded():
    store = FakeStore([row(), row()])
    producer = FakeProducer()
    assert batch(store, producer) == 2
    assert {topic for topic, _, _ in producer.sent} == {TOPIC} == {"approved-examples"}
    assert store.recorded == [r[0] for r in store.rows]


def test_a_message_the_broker_refused_is_not_recorded_and_is_sent_again_next_round():
    good, refused = row(), row()
    store = FakeStore([good, refused])
    first = FakeProducer(refuse={str(refused[0]).encode()})
    assert batch(store, first) == 1
    assert store.recorded == [good[0]]
    second = FakeProducer()
    assert batch(store, second) == 1
    assert store.recorded == [good[0], refused[0]]
    assert [key for _, key, _ in second.sent] == [str(refused[0]).encode()]


def test_a_flush_that_leaves_messages_behind_records_nothing():
    store = FakeStore([row()])
    assert batch(store, FakeProducer(left_over=1)) == 0
    assert store.recorded == []


def test_a_submission_already_recorded_is_never_sent_again():
    store = FakeStore([row()])
    batch(store, FakeProducer())
    again = FakeProducer()
    assert batch(store, again) == 0
    assert again.sent == []


def test_a_bad_row_is_skipped_and_does_not_block_the_others():
    bad, good = row(ai_grade=""), row()
    store = FakeStore([bad, good])
    producer = FakeProducer()
    assert batch(store, producer) == 1
    assert store.recorded == [good[0]]


# Without this, a full batch of unbuildable rows would be fetched, skipped and fetched again
# forever, and every approval behind them would never be reached.
def test_a_pile_of_unbuildable_rows_cannot_hold_up_the_good_ones_behind_them():
    bad = [row(ai_grade="") for _ in range(3)]
    good = row()
    store = FakeStore(bad + [good])
    skipped = set()
    producer = FakeProducer()
    assert batch(store, producer, limit=3, skipped=skipped) == 0  # the whole batch was bad
    assert skipped == {r[0] for r in bad}
    assert batch(store, producer, limit=3, skipped=skipped) == 1  # next round reaches the good one
    assert store.recorded == [good[0]]


def test_a_bad_row_is_complained_about_once_not_every_round(caplog):
    bad = row(ai_grade="")
    store = FakeStore([bad])
    skipped = set()
    with caplog.at_level("ERROR"):
        for _ in range(3):
            batch(store, FakeProducer(), skipped=skipped)
    assert caplog.text.count(str(bad[0])) == 1


def test_a_bad_row_is_logged_by_id_only_never_with_student_text(caplog):
    bad = row(submission_text="SECRET-MARKER essay", ai_grade="")
    store = FakeStore([bad])
    with caplog.at_level("INFO"):
        batch(store, FakeProducer())
    assert str(bad[0]) in caplog.text
    assert "SECRET-MARKER" not in caplog.text


def test_only_one_batch_worth_is_fetched_at_a_time():
    store = FakeStore([row() for _ in range(5)])
    assert batch(store, FakeProducer(), limit=2) == 2
    assert len(store.recorded) == 2


def test_run_sleeps_when_there_is_nothing_to_send_and_stops_when_told():
    store = FakeStore([])
    pauses = []
    rounds = iter([False, False, True])
    sender.run(FakeProducer(), store.fetch, store.record, should_stop=lambda: next(rounds), pause=7, sleep=pauses.append)
    assert pauses == [7, 7]


def test_run_does_not_sleep_after_a_full_batch():
    store = FakeStore([row() for _ in range(3)])
    pauses = []
    rounds = iter([False, True])
    sender.run(FakeProducer(), store.fetch, store.record, should_stop=lambda: next(rounds), pause=7, sleep=pauses.append, limit=3)
    assert pauses == []


def test_the_producer_settings_ask_for_full_acknowledgement():
    settings = sender.producer_settings({"KAFKA_BOOTSTRAP": "kafka:9092"})
    assert settings["acks"] == "all"
    assert settings["enable.idempotence"] is True
    assert settings["bootstrap.servers"] == "kafka:9092"


def test_a_missing_bootstrap_setting_stops_early():
    with pytest.raises(RuntimeError):
        sender.producer_settings({})


# ---------- with the real database ----------

client = TestClient(app, headers=AUTH_HEADERS)


def make_submission(statuses):
    assignment = client.post(
        "/assignments",
        json={"instructor_username": "instructor1", "title": f"Essay {uuid.uuid4()}", "rubric": "Grade it."},
    ).json()["assignment_id"]
    submission_id = str(uuid.uuid4())
    assert client.post(
        "/submissions",
        json={"submission_id": submission_id, "assignment_id": assignment, "student_name": "Alex", "submission_text": "My essay."},
    ).status_code == 201
    if "graded" in statuses:
        assert client.post(
            f"/submissions/{submission_id}/grades",
            json={"based_on_version": 1, "ai_grade": "B", "ai_reasoning": "Fine."},
        ).status_code == 201
    if "approved" in statuses:
        assert client.post(
            f"/submissions/{submission_id}/reviews",
            json={"based_on_version": 2, "decision": "approve", "reviewer_username": "instructor1"},
        ).status_code == 201
    if "rejected" in statuses:
        assert client.post(
            f"/submissions/{submission_id}/reviews",
            json={"based_on_version": 2, "decision": "reject", "reviewer_username": "instructor1", "feedback": "Redo."},
        ).status_code == 201
    return submission_id, assignment


def waiting_ids():
    return {str(r[0]) for r in sender.fetch_unsent(10_000)}


@pytest.mark.usefixtures("require_test_database")
def test_only_approved_submissions_wait_to_be_sent():
    submitted, _ = make_submission([])
    graded, _ = make_submission(["graded"])
    rejected, _ = make_submission(["graded", "rejected"])
    approved, assignment = make_submission(["graded", "approved"])
    waiting = waiting_ids()
    assert approved in waiting
    assert not ({submitted, graded, rejected} & waiting)


@pytest.mark.usefixtures("require_test_database")
def test_a_waiting_row_carries_exactly_what_the_message_needs_then_stops_waiting_once_recorded():
    approved, assignment = make_submission(["graded", "approved"])
    found = [r for r in sender.fetch_unsent(10_000) if str(r[0]) == approved]
    assert len(found) == 1
    submission_id, assignment_id, text, grade, reasoning = found[0]
    assert (str(assignment_id), text, grade, reasoning) == (assignment, "My essay.", "B", "Fine.")
    sender.record_sent(submission_id)
    assert approved not in waiting_ids()
    sender.record_sent(submission_id)  # recording twice is harmless
    assert approved not in waiting_ids()


@pytest.mark.usefixtures("require_test_database")
def test_the_oldest_waiting_submission_comes_first():
    first, _ = make_submission(["graded", "approved"])
    second, _ = make_submission(["graded", "approved"])
    order = [str(r[0]) for r in sender.fetch_unsent(10_000) if str(r[0]) in (first, second)]
    assert order == [first, second]


@pytest.mark.usefixtures("require_test_database")
def test_a_skipped_submission_is_left_out_of_the_waiting_list():
    first, _ = make_submission(["graded", "approved"])
    second, _ = make_submission(["graded", "approved"])
    left = {str(r[0]) for r in sender.fetch_unsent(10_000, skip={uuid.UUID(first)})}
    assert first not in left and second in left
