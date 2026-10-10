# In plain English: tests for the job sender, the program that tells the grader which
# submissions are waiting for a grade. It publishes one message per waiting submission
# version on the Kafka topic "grading-jobs". The message format is the shared contract in
# platform/contracts/grading-jobs.md. It works the same way as the approved-example sender:
# the database is the to-do list, and a job is recorded as sent ONLY after Kafka confirms it,
# so anything not confirmed is simply sent again. Most tests use a pretend Kafka and a
# pretend database; the last ones use the real database (guarded like the other database
# tests) to check which submission versions count as "waiting for a grade".
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app import job_sender
from app.assignments import RUBRIC_MAX
from app.job_sender import TOPIC, build_message
from app.main import app
from app.reviews import FEEDBACK_MAX
from app.sender import send_batch
from app.submissions import TEXT_MAX
from conftest import AUTH_HEADERS

# The reader's limits, copied from the table in platform/contracts/grading-jobs.md. If the
# contract changes, change this table, the sender and the grader together.
CONTRACT_READER_LIMITS = {"rubric": 10_000, "student_work": 20_000, "feedback": 10_000}


def row(**change):
    data = {
        "submission_id": uuid.uuid4(),
        "version": 1,
        "assignment_id": uuid.uuid4(),
        "rubric": "Grade for clarity and evidence.",
        "submission_text": "Photosynthesis turns light into sugar.",
        "feedback": None,
    }
    data.update(change)
    return (
        data["submission_id"],
        data["version"],
        data["assignment_id"],
        data["rubric"],
        data["submission_text"],
        data["feedback"],
    )


# ---------- the message follows the contract ----------

def test_a_first_time_job_has_exactly_the_contract_fields_and_no_feedback():
    submission_id, version, assignment_id, rubric, text, _ = row()
    key, value = build_message(row(submission_id=submission_id, version=version, assignment_id=assignment_id, rubric=rubric, submission_text=text))
    assert key == str(submission_id).encode("utf-8")
    assert json.loads(value) == {
        "schema_version": 1,
        "submission_id": str(submission_id),
        "based_on_version": 1,
        "assignment_id": str(assignment_id),
        "rubric": rubric,
        "student_work": text,
    }


def test_a_job_after_a_rejection_carries_the_instructors_feedback():
    _, value = build_message(row(version=3, feedback="Use evidence from the text."))
    data = json.loads(value)
    assert data["based_on_version"] == 3
    assert data["feedback"] == "Use evidence from the text."


def test_no_student_or_reviewer_name_ever_goes_into_the_job():
    _, value = build_message(row(feedback="Needs work."))
    for forbidden in ("student_name", "reviewer", "created_at", "ai_grade", "ai_reasoning"):
        assert forbidden not in value.decode("utf-8")


def test_texts_are_kept_exactly_as_written():
    _, value = build_message(row(rubric="  rubric  ", submission_text="\nessay\n", feedback=" why "))
    data = json.loads(value)
    assert (data["rubric"], data["student_work"], data["feedback"]) == ("  rubric  ", "\nessay\n", " why ")


def test_non_ascii_text_survives_as_utf8():
    _, value = build_message(row(submission_text="Café ☕ 学生"))
    assert json.loads(value.decode("utf-8"))["student_work"] == "Café ☕ 学生"


def test_the_longest_allowed_values_make_a_valid_job():
    _, value = build_message(row(rubric="r" * RUBRIC_MAX, submission_text="w" * TEXT_MAX, feedback="f" * FEEDBACK_MAX))
    data = json.loads(value)
    assert (len(data["rubric"]), len(data["student_work"]), len(data["feedback"])) == (10_000, 20_000, 10_000)


# A row the contract would refuse must never be sent, so building it fails instead.
@pytest.mark.parametrize(
    "bad",
    [
        {"rubric": ""},
        {"rubric": "   "},
        {"submission_text": ""},
        {"submission_text": "   "},
        {"feedback": ""},
        {"feedback": "   "},
        {"rubric": "r" * 10_001},
        {"submission_text": "w" * 20_001},
        {"feedback": "f" * 10_001},
        {"submission_text": "a\x00b"},
        {"version": 0},
        {"rubric": None},
    ],
)
def test_a_row_the_contract_would_refuse_is_not_turned_into_a_job(bad):
    with pytest.raises(ValueError):
        build_message(row(**bad))


# ---------- the limits fit at both ends ----------

def test_the_senders_limits_equal_the_contract_table():
    assert (RUBRIC_MAX, TEXT_MAX, FEEDBACK_MAX) == (10_000, 20_000, 10_000)
    assert job_sender.MESSAGE_LIMITS == CONTRACT_READER_LIMITS


# The message limits come FROM the route limits, not from copies of the numbers. So if someone
# raises a limit in the route code, the message limit rises with it and the test above fails
# loudly, instead of the sender silently refusing longer (valid) text as invalid.
def test_the_message_limits_are_the_route_limits_not_copies_of_them(monkeypatch):
    import importlib

    from app import assignments, reviews, submissions

    try:
        monkeypatch.setattr(assignments, "RUBRIC_MAX", 123)
        monkeypatch.setattr(submissions, "TEXT_MAX", 456)
        monkeypatch.setattr(reviews, "FEEDBACK_MAX", 789)
        reloaded = importlib.reload(job_sender)
        assert reloaded.MESSAGE_LIMITS == {"rubric": 123, "student_work": 456, "feedback": 789}
    finally:
        monkeypatch.undo()
        importlib.reload(job_sender)


def test_the_sender_never_accepts_more_than_the_grader_does():
    assert RUBRIC_MAX <= CONTRACT_READER_LIMITS["rubric"]
    assert TEXT_MAX <= CONTRACT_READER_LIMITS["student_work"]
    assert FEEDBACK_MAX <= CONTRACT_READER_LIMITS["feedback"]


# ---------- the loop: the same record-only-after-confirmation rule ----------

class FakeProducer:
    def __init__(self, refuse=()):
        self.refuse = set(refuse)
        self.pending = []
        self.sent = []

    def produce(self, topic, key=None, value=None, on_delivery=None):
        self.sent.append((topic, key, value))
        self.pending.append((key, on_delivery))

    def flush(self, timeout=None):
        for key, callback in self.pending:
            callback("refused" if key in self.refuse else None, None)
        self.pending = []
        return 0


class FakeStore:
    def __init__(self, rows):
        self.rows = list(rows)
        self.recorded = []

    def fetch(self, limit, skip=()):
        return [r for r in self.rows if (r[0], r[1]) not in self.recorded and (r[0], r[1]) not in skip][:limit]

    def record(self, identity):
        self.recorded.append(identity)


def batch(store, producer, skipped=None):
    return send_batch(
        producer,
        store.fetch,
        store.record,
        skipped=skipped if skipped is not None else set(),
        topic=TOPIC,
        build=build_message,
        identify=job_sender.identify,
    )


def test_confirmed_jobs_go_to_the_grading_jobs_topic_and_are_recorded_by_submission_and_version():
    first, second = row(), row(version=3, feedback="Try again.")
    store = FakeStore([first, second])
    producer = FakeProducer()
    assert batch(store, producer) == 2
    assert {topic for topic, _, _ in producer.sent} == {TOPIC} == {"grading-jobs"}
    assert store.recorded == [(first[0], 1), (second[0], 3)]


def test_a_job_the_broker_refused_is_not_recorded_and_is_sent_again():
    good, refused = row(), row()
    store = FakeStore([good, refused])
    assert batch(store, FakeProducer(refuse={str(refused[0]).encode()})) == 1
    assert store.recorded == [(good[0], 1)]
    assert batch(store, FakeProducer()) == 1
    assert store.recorded == [(good[0], 1), (refused[0], 1)]


def test_a_new_version_of_a_recorded_submission_is_a_new_job():
    store = FakeStore([row()])
    batch(store, FakeProducer())
    submission_id = store.rows[0][0]
    store.rows.append(row(submission_id=submission_id, version=3, feedback="Again."))
    again = FakeProducer()
    assert batch(store, again) == 1
    assert json.loads(again.sent[0][2])["based_on_version"] == 3


def test_a_bad_row_is_skipped_once_and_cannot_hold_up_the_others(caplog):
    bad, good = row(rubric=""), row()
    store = FakeStore([bad, good])
    skipped = set()
    with caplog.at_level("ERROR"):
        assert batch(store, FakeProducer(), skipped) == 1
        batch(store, FakeProducer(), skipped)
    assert skipped == {(bad[0], 1)}
    assert caplog.text.count(str(bad[0])) == 1


def test_the_producer_settings_are_the_same_safe_ones_as_the_other_sender():
    settings = job_sender.producer_settings({"KAFKA_BOOTSTRAP": "kafka:9092"})
    assert settings["acks"] == "all" and settings["enable.idempotence"] is True


# ---------- with the real database ----------

client = TestClient(app, headers=AUTH_HEADERS)


def new_submission(rubric="Grade it."):
    assignment = client.post(
        "/assignments",
        json={"instructor_username": "instructor1", "title": f"Essay {uuid.uuid4()}", "rubric": rubric},
    ).json()["assignment_id"]
    submission_id = str(uuid.uuid4())
    assert client.post(
        "/submissions",
        json={"submission_id": submission_id, "assignment_id": assignment, "student_name": "Alex", "submission_text": "My essay."},
    ).status_code == 201
    return submission_id, assignment


def grade(submission_id, version):
    assert client.post(
        f"/submissions/{submission_id}/grades",
        json={"based_on_version": version, "ai_grade": "B", "ai_reasoning": "Fine."},
    ).status_code == 201


def review(submission_id, version, decision, feedback=None):
    body = {"based_on_version": version, "decision": decision, "reviewer_username": "instructor1"}
    if feedback:
        body["feedback"] = feedback
    assert client.post(f"/submissions/{submission_id}/reviews", json=body).status_code == 201


def waiting():
    return {(str(r[0]), r[1]): r for r in job_sender.fetch_waiting(10_000)}


@pytest.mark.usefixtures("require_test_database")
def test_a_new_submission_waits_for_a_grade_with_its_rubric_and_no_feedback():
    submission_id, assignment = new_submission(rubric="Mark the argument.")
    found = waiting()[(submission_id, 1)]
    _, version, assignment_id, rubric, text, feedback = found
    assert (version, str(assignment_id), rubric, text, feedback) == (1, assignment, "Mark the argument.", "My essay.", None)


@pytest.mark.usefixtures("require_test_database")
def test_only_submissions_waiting_for_a_grade_are_listed():
    graded, _ = new_submission()
    grade(graded, 1)
    approved, _ = new_submission()
    grade(approved, 1)
    review(approved, 2, "approve")
    found = {key[0] for key in waiting()}
    assert graded not in found and approved not in found


@pytest.mark.usefixtures("require_test_database")
def test_a_rejected_submission_waits_again_with_the_instructors_feedback():
    submission_id, _ = new_submission()
    grade(submission_id, 1)
    review(submission_id, 2, "reject", feedback="Add evidence.")
    assert (submission_id, 1) not in waiting() and (submission_id, 2) not in waiting()
    found = waiting()[(submission_id, 3)]
    assert found[5] == "Add evidence."
    assert found[1] == 3


@pytest.mark.usefixtures("require_test_database")
def test_a_recorded_job_stops_waiting_but_the_next_rejection_creates_a_new_one():
    submission_id, _ = new_submission()
    job_sender.record_job_sent((uuid.UUID(submission_id), 1))
    job_sender.record_job_sent((uuid.UUID(submission_id), 1))  # twice is harmless
    assert (submission_id, 1) not in waiting()
    grade(submission_id, 1)
    review(submission_id, 2, "reject", feedback="Again.")
    assert (submission_id, 3) in waiting()


@pytest.mark.usefixtures("require_test_database")
def test_a_skipped_version_is_left_out_and_the_oldest_comes_first():
    first, _ = new_submission()
    second, _ = new_submission()
    order = [str(r[0]) for r in job_sender.fetch_waiting(10_000) if str(r[0]) in (first, second)]
    assert order == [first, second]
    left = {str(r[0]) for r in job_sender.fetch_waiting(10_000, skip={(uuid.UUID(first), 1)})}
    assert first not in left and second in left


# The real program starts the loop with run(), so run() must pass the job sender's topic,
# message builder and identifier on to the shared sending code. (A deployed pod once crashed
# on this because only send_batch had been tested with them.)
def test_run_sends_jobs_to_the_jobs_topic_through_the_shared_loop():
    store = FakeStore([row()])
    producer = FakeProducer()
    rounds = iter([False, True])
    job_sender.run(
        producer,
        store.fetch,
        store.record,
        should_stop=lambda: next(rounds),
        sleep=lambda seconds: None,
        topic=TOPIC,
        build=build_message,
        identify=job_sender.identify,
    )
    assert [topic for topic, _, _ in producer.sent] == ["grading-jobs"]
    assert store.recorded == [(store.rows[0][0], 1)]


# ---------- a job that was confirmed but never answered is sent again ----------
# Recording a job as sent only proves Kafka got it. The grader may later dead-letter it, or
# the topic may drop it after its 7 days. So a job that has had no answer for a long time is
# sent again, a limited number of times, and then left for a person.

def hours_ago(hours):
    from datetime import datetime, timedelta, timezone

    return datetime.now(timezone.utc) - timedelta(hours=hours)


@pytest.mark.usefixtures("require_test_database")
def test_a_job_with_no_answer_for_a_long_time_is_sent_again_but_a_recent_one_is_not():
    old, _ = new_submission()
    recent, _ = new_submission()
    job_sender.record_job_sent((uuid.UUID(old), 1), sent_at=hours_ago(job_sender.RESEND_AFTER_HOURS + 1))
    job_sender.record_job_sent((uuid.UUID(recent), 1), sent_at=hours_ago(1))
    found = waiting()
    assert (old, 1) in found
    assert (recent, 1) not in found


@pytest.mark.usefixtures("require_test_database")
def test_a_job_is_sent_again_only_a_limited_number_of_times():
    submission_id, _ = new_submission()
    for attempt in range(job_sender.MAX_SENDS):
        assert (submission_id, 1) in waiting(), attempt
        job_sender.record_job_sent(
            (uuid.UUID(submission_id), 1),
            sent_at=hours_ago(job_sender.RESEND_AFTER_HOURS * (job_sender.MAX_SENDS - attempt) + 1),
        )
    assert (submission_id, 1) not in waiting()


@pytest.mark.usefixtures("require_test_database")
def test_an_answered_job_is_never_sent_again_however_old():
    submission_id, _ = new_submission()
    job_sender.record_job_sent((uuid.UUID(submission_id), 1), sent_at=hours_ago(job_sender.RESEND_AFTER_HOURS * 3))
    grade(submission_id, 1)
    assert (submission_id, 1) not in waiting() and (submission_id, 2) not in waiting()


@pytest.mark.usefixtures("require_test_database")
def test_the_resend_rules_are_visible_in_the_constants():
    assert job_sender.RESEND_AFTER_HOURS >= 1
    assert 2 <= job_sender.MAX_SENDS <= 10
