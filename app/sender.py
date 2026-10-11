# In plain English: the sender. When an instructor approves a grade, the essay and its
# grade should reach the knowledge service so the grader can learn from it. This program
# does that by publishing a message on the Kafka topic "approved-examples". The message
# format is the shared contract in platform/contracts/approved-examples.md.
#
# How it works (the "outbox" idea):
#   - Approving a grade only saves a row in the database. It never talks to Kafka, so a
#     Kafka outage can never stop an instructor approving.
#   - This program runs on its own, looping every few seconds. Each round it asks the
#     database: "which approved submissions are not in approval_sends yet?"
#   - It publishes a message for each one. ONLY when Kafka confirms a message arrived does
#     it add that submission to approval_sends. Anything not confirmed is still "waiting"
#     and is sent again next round. That is also the re-send sweep: nothing is lost if
#     Kafka is down or the program crashes at a bad moment.
#   - Delivery is at-least-once. A message may occasionally arrive twice. That is harmless,
#     because the reader recognises the submission ID and saves nothing twice.
#
# Nothing the student wrote is ever logged. Logs carry submission IDs and counts only.
import logging
import os
import signal
import time
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db import connect
from app.text_rules import must_be_storable_text

TOPIC = "approved-examples"

# The reader's limits, from the table in the contract. The message is checked against
# them before it is sent, so a message the reader would refuse is never published.
MESSAGE_LIMITS = {"student_work": 20_000, "grade": 100, "reasoning": 10_000}

log = logging.getLogger("assessment-sender")


# In plain English: the rules for one message, straight from the contract. Extra fields are
# refused, spaces at either end are trimmed, and each text must be 1 up to its limit long.
class ApprovedExampleMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: Literal[1] = 1
    source_submission_id: uuid.UUID
    assignment_id: uuid.UUID
    student_work: str = Field(min_length=1, max_length=MESSAGE_LIMITS["student_work"])
    grade: str = Field(min_length=1, max_length=MESSAGE_LIMITS["grade"])
    reasoning: str = Field(min_length=1, max_length=MESSAGE_LIMITS["reasoning"])

    _check_text = field_validator("student_work", "grade", "reasoning")(must_be_storable_text)


# In plain English: turns one approved submission into the key and value of a Kafka message.
# The key is the submission ID as text. The value is the contract's JSON. It raises
# ValueError if the row would break the contract (which the limits should make impossible).
# The error is not allowed to carry the student's text, so the caller logs only the ID.
def build_message(row):
    submission_id, assignment_id, submission_text, ai_grade, ai_reasoning = row
    message = ApprovedExampleMessage(
        source_submission_id=submission_id,
        assignment_id=assignment_id,
        student_work=submission_text,
        grade=ai_grade,
        reasoning=ai_reasoning,
    )
    return str(submission_id).encode("utf-8"), message.model_dump_json().encode("utf-8")


# In plain English: the approved submissions that have not been confirmed as sent, oldest
# first, leaving out the ones in "skip" (see send_batch). A submission has one row per
# version, and the approved version is the one with the final grade and reasoning. Reads only.
def fetch_unsent(limit, skip=()):
    with connect() as connection:
        return connection.execute(
            "SELECT s.submission_id, s.assignment_id, s.submission_text, s.ai_grade, s.ai_reasoning "
            "FROM submissions s "
            "WHERE s.status = 'approved' "
            "AND NOT EXISTS (SELECT 1 FROM approval_sends a WHERE a.submission_id = s.submission_id) "
            "AND s.submission_id <> ALL(%s::uuid[]) "
            "ORDER BY s.created_at, s.submission_id LIMIT %s",
            (list(skip), limit),
        ).fetchall()


# In plain English: notes that Kafka confirmed this submission. Adding it twice is harmless.
def record_sent(submission_id):
    with connect() as connection:
        connection.execute(
            "INSERT INTO approval_sends (submission_id) VALUES (%s) ON CONFLICT DO NOTHING",
            (submission_id,),
        )


# In plain English: one round. It fetches up to "limit" waiting submissions, publishes them,
# waits for Kafka's answers, and records ONLY the ones Kafka confirmed. flush() alone is not
# proof: it only says how many messages are still queued. A refusal arrives through the
# delivery callback. If flush leaves messages behind, nothing is recorded, and everything is
# sent again next round (harmless). Returns how many were confirmed and recorded.
#
# "skipped" holds the IDs of rows that could not be turned into a valid message. They are
# complained about once, and left out of every later fetch, so a pile of them can never fill
# the batch and hold up the good rows behind them. It lives in memory only: after a restart
# they are tried (and complained about) once more, which is what you want after a fix.
#
# The topic, the message builder and the way a row is identified are parameters, so the
# job sender (app/job_sender.py) uses exactly this same record-only-after-confirmation logic.
def send_batch(producer, fetch, record, limit=50, skipped=None, topic=TOPIC, build=None, identify=None):
    skipped = set() if skipped is None else skipped
    build = build or build_message
    identify = identify or (lambda row: row[0])
    confirmed = []
    refused = 0

    def make_callback(identity):
        def callback(error, _message):
            nonlocal refused
            if error:
                refused += 1
            else:
                confirmed.append(identity)

        return callback

    for row in fetch(limit, skipped):
        identity = identify(row)
        try:
            key, value = build(row)
        except ValueError:
            # Not the error text: it could quote the student's work.
            log.error("submission %s cannot be turned into a valid message; skipped", row[0])
            skipped.add(identity)
            continue
        producer.produce(topic, key=key, value=value, on_delivery=make_callback(identity))

    if producer.flush(30) != 0:
        log.warning("Kafka did not confirm every message in time; they will be sent again")
        return 0
    for identity in confirmed:
        record(identity)
    if refused:
        log.warning("%s message(s) were refused by Kafka; they will be sent again", refused)
    if confirmed:
        log.info("sent %s approved example(s)", len(confirmed))
    return len(confirmed)


# In plain English: the loop. Round after round it sends what is waiting. When a round sent
# nothing (nothing waiting, or Kafka refused everything), it rests for a few seconds first,
# so it never hammers the database or a struggling Kafka. The pieces are parameters so tests
# can pass pretend ones.
def run(producer, fetch, record, should_stop=lambda: False, pause=5, sleep=time.sleep, limit=50, **how):
    skipped: set = set()
    while not should_stop():
        if send_batch(producer, fetch, record, limit=limit, skipped=skipped, **how) == 0:
            sleep(pause)


# In plain English: the Kafka settings. "acks=all" means Kafka confirms only when the
# message is safely stored, and the idempotent setting stops the client's own retries from
# creating duplicates.
def producer_settings(environment):
    bootstrap = environment.get("KAFKA_BOOTSTRAP")
    if not bootstrap:
        raise RuntimeError("Missing required setting: KAFKA_BOOTSTRAP")
    return {
        "bootstrap.servers": bootstrap,
        "acks": "all",
        "enable.idempotence": True,
        "delivery.timeout.ms": 30_000,
    }


# In plain English: starts the real sender. It stops cleanly when Kubernetes asks it to
# (SIGTERM), after finishing the round in hand.
def main():
    from confluent_kafka import Producer

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    producer = Producer(producer_settings(os.environ))
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(True))
    signal.signal(signal.SIGINT, lambda *_: stopping.append(True))
    run(producer, fetch_unsent, record_sent, should_stop=lambda: bool(stopping))


if __name__ == "__main__":
    main()
