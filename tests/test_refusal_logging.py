# In plain English: tests that every refused request is recorded in the log, safely. When the service
# key check turns a caller away, the log gets one line saying WHY (no key, a badly formed header, a
# wrong key, or the service has no key configured), which method and which route, and nothing else.
#
# Why it matters: a service that refuses silently gives nobody a way to notice that someone is trying
# keys, or that a caller has the wrong one (OWASP A09, CWE-778 insufficient logging, CWE-223 and
# CWE-221 security-relevant information left out). But a log line can also leak or be forged, so the
# line never contains the key, the Authorization header or anything the caller can use to write a fake
# line, and a flood of refusals is summarized instead of filling the log (OWASP A10 advice).
import logging

import pytest
from fastapi.testclient import TestClient

from app import auth
from app.main import app
from conftest import AUTH_HEADERS, TEST_KEY

MARKER = "REFUSAL-MARKER"
bare = TestClient(app)


@pytest.fixture(autouse=True)
def fresh_window(monkeypatch):
    # Each test starts with an empty log window and a clock it controls.
    clock = {"now": 1000.0}
    monkeypatch.setattr(auth, "_now", lambda: clock["now"])
    auth.reset_refusal_window()
    return clock


def refusals(caplog):
    return [r for r in caplog.records if r.name == auth.LOGGER_NAME]


@pytest.mark.owasp("A09", 221, 223, 778)
def test_each_kind_of_refusal_is_logged_once_with_its_reason(caplog):
    cases = {
        "missing": {},
        "malformed": {"Authorization": "Basic abc"},
        "wrong": {"Authorization": "Bearer " + "x" * 40},
    }
    for reason, headers in cases.items():
        caplog.clear()
        with caplog.at_level(logging.INFO):
            assert bare.get("/assignments", headers=headers).status_code == 401
        records = refusals(caplog)
        assert len(records) == 1, (reason, [r.getMessage() for r in records])
        assert records[0].levelno == logging.WARNING
        assert f"reason={reason}" in records[0].getMessage()
        assert "method=GET" in records[0].getMessage() and "path=/assignments" in records[0].getMessage()


def test_a_service_with_no_key_configured_logs_that_reason(caplog, monkeypatch):
    monkeypatch.delenv("SERVICE_KEYS")
    with caplog.at_level(logging.INFO):
        assert bare.get("/assignments", headers=AUTH_HEADERS).status_code == 503
    assert [("reason=not_configured" in r.getMessage()) for r in refusals(caplog)] == [True]


def test_the_log_line_never_contains_the_key_or_the_header(caplog):
    sent = "Bearer " + "s3cret-" + "k" * 40
    with caplog.at_level(logging.DEBUG):
        bare.get("/assignments", headers={"Authorization": sent})
        bare.get("/assignments", headers={"Authorization": f"Bearer {TEST_KEY}x"})
    assert refusals(caplog)
    for record in caplog.records:
        text = record.getMessage()
        assert "s3cret" not in text and TEST_KEY not in text and "Bearer" not in text and "Authorization" not in text.replace("authorization", "")


def test_a_hostile_path_cannot_forge_or_split_a_log_line(caplog):
    hostile = f"/x%0d%0a2026-10-10%20INFO%20offset%200:%20saved%20{MARKER}%0aSet-Cookie:%20pwned"
    with caplog.at_level(logging.DEBUG):
        bare.get(hostile)
    records = refusals(caplog)
    assert len(records) == 1
    line = records[0].getMessage()
    assert "\r" not in line and "\n" not in line
    assert MARKER not in line or "%" in line  # it may appear only in its harmless percent-encoded form
    assert "\n2026" not in line


def test_a_very_long_path_is_cut_short(caplog):
    with caplog.at_level(logging.INFO):
        bare.get("/" + "a" * 5000)
    assert len(refusals(caplog)[0].getMessage()) < 400


def test_requests_that_pass_and_the_health_checks_are_not_logged_as_refusals(caplog):
    with caplog.at_level(logging.DEBUG):
        TestClient(app).get("/health")
        TestClient(app).get("/ready")
        TestClient(app, headers=AUTH_HEADERS).get("/assignments", params={"limit": "bad"})  # a 422, not a refusal
    assert refusals(caplog) == []


def test_a_flood_of_refusals_is_logged_up_to_a_limit_then_summarized(caplog, fresh_window):
    with caplog.at_level(logging.INFO):
        for _ in range(auth.REFUSAL_LOG_LIMIT + 30):
            assert bare.get("/assignments").status_code == 401
    assert len(refusals(caplog)) == auth.REFUSAL_LOG_LIMIT  # no line for the extra 30 yet
    caplog.clear()
    fresh_window["now"] += auth.REFUSAL_WINDOW_SECONDS + 1  # the next minute starts
    with caplog.at_level(logging.INFO):
        assert bare.get("/assignments").status_code == 401
    lines = [r.getMessage() for r in refusals(caplog)]
    assert any("30 more" in line for line in lines), lines  # the summary of what was held back
    assert any("reason=missing" in line for line in lines)


def test_refusing_still_works_exactly_as_before():
    assert bare.get("/assignments").status_code == 401
    assert bare.get("/assignments").json() == {"problem": "A valid service key is required"}
    assert bare.get("/assignments").headers["www-authenticate"] == "Bearer"


# ---------- The held-back count is reported even if the refusals stop ----------
# A flood that ends inside a window must not leave the held-back count unreported. A timer reports it
# when the window closes. These tests capture the timer instead of waiting for it, and one test uses
# the real timer with a very short window.

@pytest.fixture
def timers(monkeypatch):
    scheduled = []
    monkeypatch.setattr(auth, "_start_timer", lambda delay, function, window_id: scheduled.append((delay, function, window_id)))
    return scheduled


def test_a_flood_that_stops_inside_the_window_is_still_summarized_by_the_timer(caplog, timers, fresh_window):
    with caplog.at_level(logging.INFO):
        for _ in range(auth.REFUSAL_LOG_LIMIT + 7):
            bare.get("/examples")
    assert len(timers) == 1, "exactly one timer, however many refusals were held back"
    delay, function, window_id = timers[0]
    assert 0 <= delay <= auth.REFUSAL_WINDOW_SECONDS
    caplog.clear()
    with caplog.at_level(logging.INFO):
        function(window_id)  # the window closes with nobody calling again
    lines = [r.getMessage() for r in refusals(caplog)]
    assert len(lines) == 1 and "7 more" in lines[0], lines
    caplog.clear()
    with caplog.at_level(logging.INFO):
        function(window_id)  # firing twice must not report twice
    assert refusals(caplog) == []


def test_no_timer_is_started_when_nothing_was_held_back(caplog, timers):
    with caplog.at_level(logging.INFO):
        for _ in range(auth.REFUSAL_LOG_LIMIT):
            bare.get("/examples")
    assert timers == []


def test_an_old_timer_does_nothing_once_a_new_window_has_started(caplog, timers, fresh_window):
    with caplog.at_level(logging.INFO):
        for _ in range(auth.REFUSAL_LOG_LIMIT + 3):
            bare.get("/examples")
        old_delay, old_function, old_id = timers[0]
        fresh_window["now"] += auth.REFUSAL_WINDOW_SECONDS + 1
        for _ in range(auth.REFUSAL_LOG_LIMIT + 4):
            bare.get("/examples")  # a late refusal starts a new window, which then holds back 4 of its own
    caplog.clear()
    with caplog.at_level(logging.INFO):
        old_function(old_id)  # the old timer finally fires: it must not report the NEW window's count early
    assert refusals(caplog) == []


def test_each_window_gets_its_own_timer(caplog, timers, fresh_window):
    with caplog.at_level(logging.INFO):
        for _ in range(auth.REFUSAL_LOG_LIMIT + 2):
            bare.get("/examples")
        fresh_window["now"] += auth.REFUSAL_WINDOW_SECONDS + 1
        for _ in range(auth.REFUSAL_LOG_LIMIT + 2):
            bare.get("/examples")
    assert len(timers) == 2
    assert timers[0][2] != timers[1][2]


def test_the_real_timer_reports_the_held_back_count_after_the_window_closes(caplog, monkeypatch):
    import re
    import time

    monkeypatch.setattr(auth, "_now", time.monotonic)
    monkeypatch.setattr(auth, "REFUSAL_WINDOW_SECONDS", 0.5)
    monkeypatch.setattr(auth, "REFUSAL_LOG_LIMIT", 1)  # one line per window, so any window with two or more requests needs a summary
    auth.reset_refusal_window()
    total = 30

    def accounted_for():
        # Every refusal is either logged on its own line or counted in a "N more refusals" summary. How the
        # requests fall across the half-second windows depends on how fast this computer is, so the test
        # checks that nothing is lost instead of expecting one exact split.
        logged = sum(1 for r in refusals(caplog) if "service key refused" in r.getMessage())
        reported = sum(int(m.group(1)) for r in refusals(caplog) if (m := re.match(r"(\d+) more refusals", r.getMessage())))
        return logged + reported

    with caplog.at_level(logging.INFO):
        for _ in range(total):
            bare.get("/assignments")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and accounted_for() < total:
            time.sleep(0.05)
    assert accounted_for() == total, [r.getMessage() for r in refusals(caplog)]
    assert any("more refusals" in r.getMessage() for r in refusals(caplog)), "no summary line was written by the timer"
