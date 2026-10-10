# In plain English: the results consumer. The grader sends each grade back as a message on the
# Kafka topic "grading-results". This program takes them off the topic and records each as the
# submission's next version, using the same routine as the web address POST
# /submissions/{id}/grades. The message format is the shared contract in
# platform/contracts/grading-results.md.
#
# The promise it keeps: a message is marked "done" (committed) only AFTER it has been dealt with,
# so a crash can never lose one. Dealt with means one of:
#   saved        a good grade for a submission that was waiting: recorded as the next version.
#   repeat       the same grade was already recorded; nothing is added twice.
#   outdated     the submission has moved on, or another grade for that version won. This is a
#                normal race, not an error: it is dropped and only the submission ID and the word
#                "outdated" are logged.
#   dead_letter  a message that can never be recorded (not JSON, unknown version, a broken rule,
#                key not equal to the submission ID, a submission that does not exist, or a save
#                the database refuses for this message alone). It is copied to the topic
#                "grading-results.dead-letter" with the reason in a header, so it cannot block its
#                lane, and a person can look at it. The copy must be CONFIRMED delivered before
#                the commit.
# Temporary trouble (database down, Kafka down) is NOT dealt with: nothing is committed, the
# program stops with an error, Kubernetes restarts it and the message is tried again.
#
# Nothing the student wrote, and no reasoning text, is ever logged. Logs carry the outcome, the
# submission ID and the offset.
import logging
import os
import signal
import uuid
from typing import Literal

import json
import psycopg
from pydantic import ValidationError

from app.grades import (
    NewGrade,
    NotWaitingForGrade,
    SubmissionMovedOn,
    SubmissionNotFound,
    record_grade,
)

TOPIC = "grading-results"
DEAD_LETTER_TOPIC = "grading-results.dead-letter"
GROUP_ID = "assessment-grading-results"

log = logging.getLogger("assessment-results-consumer")


# In plain English: the rules for one message. It is exactly what the grade route accepts (the
# same limits and text rules, no extra fields) plus the format version and the submission ID.
class GradingResultMessage(NewGrade):
    schema_version: Literal[1]
    submission_id: uuid.UUID


# In plain English: decides what to do with one message and reports the outcome as a pair like
# ("saved", None) or ("dead_letter", "invalid_field"). It raises for temporary trouble (such as
# the database being down) so the caller does not commit. "record" is a parameter only so tests
# can pass a pretend one.
def handle_message(key, value, record=record_grade):
    try:
        data = json.loads(value.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, ValueError, RecursionError):
        return "dead_letter", "invalid_json"
    if not isinstance(data, dict):
        return "dead_letter", "invalid_json"

    version = data.get("schema_version")
    if isinstance(version, bool) or version != 1:
        return "dead_letter", "unknown_schema_version"

    try:
        message = GradingResultMessage.model_validate(data)
    except ValidationError:
        return "dead_letter", "invalid_field"

    try:
        key_id = uuid.UUID(key.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, ValueError):
        return "dead_letter", "key_mismatch"
    if key_id != message.submission_id:
        return "dead_letter", "key_mismatch"

    grade = NewGrade(
        based_on_version=message.based_on_version,
        ai_grade=message.ai_grade,
        ai_reasoning=message.ai_reasoning,
    )
    try:
        _, created = record(message.submission_id, grade)
    except SubmissionNotFound:
        return "dead_letter", "unknown_submission"
    except (SubmissionMovedOn, NotWaitingForGrade):
        return "outdated", None
    except (psycopg.DataError, psycopg.IntegrityError):
        # The database refuses this message by itself. It would fail the same way every time,
        # so it must not block its lane. Connection and other database trouble is NOT caught:
        # that is temporary.
        return "dead_letter", "record_rejected"
    return ("saved" if created else "repeat"), None


# In plain English: the loop. It asks Kafka for one message at a time, deals with it, and only
# then commits. A bad message is copied to the dead-letter topic and that copy must be confirmed
# delivered BEFORE the commit. "consumer" and "producer" are parameters so tests can pass pretend
# ones. The loop ends when should_stop() says so. Any error ends it too, after closing the
# consumer, and the error goes up to the caller.
def run(consumer, producer, record=record_grade, should_stop=lambda: False):
    consumer.subscribe([TOPIC])
    try:
        while not should_stop():
            message = consumer.poll(1.0)
            if message is None:
                continue
            if message.error():
                raise RuntimeError(f"Kafka error: {message.error()}")
            outcome, reason = handle_message(message.key(), message.value(), record=record)
            if outcome == "dead_letter":
                # flush() only says how many copies are still queued. A copy the broker refuses
                # is reported through this callback, so the callback records it.
                refused = []
                producer.produce(
                    DEAD_LETTER_TOPIC,
                    key=message.key(),
                    value=message.value(),
                    headers=[("error", reason.encode("utf-8"))],
                    on_delivery=lambda error, _message: refused.append(error) if error else None,
                )
                if producer.flush(30) != 0 or refused:
                    raise RuntimeError("dead-letter copy was not delivered")
            consumer.commit(message=message, asynchronous=False)
            if outcome == "outdated":
                log.info("offset %s: outdated (submission %s)", message.offset(), _key_text(message.key()))
            else:
                log.info("offset %s: %s%s", message.offset(), outcome, f" ({reason})" if reason else "")
    finally:
        consumer.close()


# In plain English: the key as text for a log line, or a placeholder if it is not readable.
def _key_text(key):
    try:
        return key.decode("utf-8")
    except (AttributeError, UnicodeDecodeError):
        return "unreadable"


# In plain English: the Kafka settings. Commits are manual (the program decides when a message is
# done), a brand-new group starts from the oldest message, and the generous poll interval allows
# for a slow database moment.
def consumer_settings(environment):
    bootstrap = environment.get("KAFKA_BOOTSTRAP")
    if not bootstrap:
        raise RuntimeError("Missing required setting: KAFKA_BOOTSTRAP")
    return {
        "bootstrap.servers": bootstrap,
        "group.id": GROUP_ID,
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
        "max.poll.interval.ms": 300_000,
    }


# In plain English: starts the real consumer. It stops cleanly when Kubernetes asks it to
# (SIGTERM), after finishing the message in hand.
def main():
    from confluent_kafka import Consumer, Producer

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    settings = consumer_settings(os.environ)
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(True))
    signal.signal(signal.SIGINT, lambda *_: stopping.append(True))
    producer = Producer({"bootstrap.servers": settings["bootstrap.servers"]})
    run(Consumer(settings), producer, should_stop=lambda: bool(stopping))


if __name__ == "__main__":
    main()
