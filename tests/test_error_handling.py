# In plain English: tests that every kind of failure gets a short, fixed reply and a safe log line. Whatever
# goes wrong inside the service (a bug, a database problem, a missing permission, a wrong address or a wrong
# method), the caller sees only a fixed sentence, never a stack trace, a database message or a piece of
# what somebody sent, and the log records which kind of error happened and on which route but not its text.
#
# Why it matters (OWASP A10, mishandling of exceptional conditions): a default error page can reveal the
# program's insides (CWE-209, 550, 756), an uncaught error can crash a request or leave things half done
# (CWE-248, 703, 754, 755) and a permission or database error must end safely and not open anything
# (CWE-274, 280). The log must not become a second leak either (OWASP A09).
import logging

import psycopg
import pytest
from fastapi.testclient import TestClient

from app import errors
from app.main import app
from conftest import AUTH_HEADERS

# The route these tests make fail on purpose, and the function behind it that they replace with one that fails.
ROUTE = "/assignments"
BEHIND_THE_ROUTE = "app.main.list_assignments"

SENTINEL = "STUDENT-TEXT-SENTINEL-4711"
client = TestClient(app, headers=AUTH_HEADERS)


def make_fail(monkeypatch, error):
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(BEHIND_THE_ROUTE, fail)


def error_logs(caplog):
    return [r for r in caplog.records if r.name == errors.LOGGER_NAME]


# ---------- Unexpected errors ----------

@pytest.mark.owasp("A10", 209, 550, 248, 703, 755)
def test_an_unexpected_error_gets_a_fixed_reply_with_nothing_from_inside(monkeypatch):
    make_fail(monkeypatch, RuntimeError(f"boom {SENTINEL} Traceback (most recent call last) File secret.py"))
    reply = client.get(ROUTE)
    assert reply.status_code == 500
    assert reply.headers["content-type"].startswith("application/json")
    assert reply.json() == {"problem": "Something went wrong"}
    for leaked in (SENTINEL, "Traceback", "RuntimeError", "secret.py", "boom"):
        assert leaked not in reply.text


@pytest.mark.owasp("A10", 209, 550, 248, 703, 755)
def test_an_unexpected_error_does_not_escape_to_the_server(monkeypatch):
    # If the error escaped, the web server would print its own traceback, with the message, in the log. This
    # test client re-raises anything that escapes, so a 500 reply with no exception means nothing escaped.
    make_fail(monkeypatch, ValueError(SENTINEL))
    strict_client = TestClient(app, headers=AUTH_HEADERS, raise_server_exceptions=True)
    assert strict_client.get(ROUTE).status_code == 500


@pytest.mark.owasp("A10", 209, 550)
def test_the_log_names_the_kind_of_error_and_the_route_but_never_its_text(monkeypatch, caplog):
    make_fail(monkeypatch, ValueError(f"bad value {SENTINEL}"))
    with caplog.at_level(logging.DEBUG):
        client.get(ROUTE)
    records = error_logs(caplog)
    assert len(records) == 1
    line = records[0].getMessage()
    assert "ValueError" in line and "GET" in line and "/assignments" in line
    assert SENTINEL not in line and "bad value" not in line
    assert records[0].exc_info is None  # no traceback is attached, because a traceback carries the message
    for record in caplog.records:
        assert SENTINEL not in record.getMessage() and not record.exc_info


@pytest.mark.owasp("A10", 209, 550)
def test_a_hostile_path_cannot_forge_or_split_the_error_log_line(monkeypatch, caplog):
    # The path is decoded before the service sees it, so %0d%0a arrives as a real line break. An error in
    # the service-key check (which runs for any address) makes the catch-all log that path.
    from app import auth

    def explode(*args, **kwargs):
        raise RuntimeError("x")

    monkeypatch.setattr(auth, "_note_refusal", explode)
    with caplog.at_level(logging.DEBUG):
        TestClient(app).get("/page%0d%0a2026-10-10%20ERROR%20forged%20line")
    line = error_logs(caplog)[0].getMessage()
    assert "\n" not in line and "\r" not in line and " forged" not in line and "page" in line


@pytest.mark.owasp("A10", 703, 754, 755)
def test_an_error_inside_the_service_key_check_is_caught_too(monkeypatch):
    # The catch-all must be the outermost layer, or an error in a layer outside it would escape.
    from app import auth

    def explode(*args, **kwargs):
        raise RuntimeError(SENTINEL)

    monkeypatch.setattr(auth, "_note_refusal", explode)
    reply = TestClient(app).get("/assignments")  # no key, so the refusal path runs
    assert reply.status_code == 500 and reply.json() == {"problem": "Something went wrong"}
    assert SENTINEL not in reply.text


# ---------- Database and permission errors ----------

@pytest.mark.owasp("A10", 274, 280)
@pytest.mark.parametrize(
    "error",
    [
        psycopg.errors.InsufficientPrivilege(f"permission denied for table {SENTINEL}"),
        psycopg.OperationalError(f"connection to server at db failed {SENTINEL}"),
        psycopg.errors.UndefinedTable(f"relation {SENTINEL} does not exist"),
    ],
)
def test_a_database_or_permission_error_ends_safely_with_a_fixed_reply(monkeypatch, caplog, error):
    make_fail(monkeypatch, error)
    with caplog.at_level(logging.DEBUG):
        reply = client.get(ROUTE)
    assert reply.status_code == 503
    assert reply.json() == {"ok": False}
    assert SENTINEL not in reply.text
    assert all(SENTINEL not in record.getMessage() for record in caplog.records)


@pytest.mark.owasp("A10", 274, 280, 754)
def test_a_database_error_is_recorded_by_kind_only(monkeypatch, caplog):
    make_fail(monkeypatch, psycopg.errors.InsufficientPrivilege(f"permission denied {SENTINEL}"))
    with caplog.at_level(logging.DEBUG):
        client.get(ROUTE)
    line = error_logs(caplog)[0].getMessage()
    assert "InsufficientPrivilege" in line and SENTINEL not in line


# ---------- Wrong addresses and wrong methods ----------

@pytest.mark.owasp("A10", 756)
def test_an_unknown_address_gets_a_fixed_not_found_reply_that_does_not_repeat_it():
    reply = client.get("/no-such-page-" + SENTINEL)
    assert reply.status_code == 404
    assert reply.headers["content-type"].startswith("application/json")
    assert reply.json() == {"problem": "Not found"}
    assert SENTINEL not in reply.text


@pytest.mark.owasp("A10", 756)
def test_a_wrong_method_gets_a_fixed_reply_and_keeps_the_allow_header():
    reply = client.post("/health")
    assert reply.status_code == 405
    assert reply.json() == {"problem": "Method not allowed"}
    assert "GET" in reply.headers["allow"]


@pytest.mark.owasp("A10", 756)
def test_the_framework_default_wording_never_appears():
    for reply in (client.get("/nothing"), client.post("/health"), client.get("/assignments/extra/segments/more")):
        assert "detail" not in reply.json()
        assert "Not Found" not in reply.text and "Method Not Allowed" not in reply.text


@pytest.mark.owasp("A10", 756)
def test_other_http_errors_get_fixed_generic_wording_without_the_original_text():
    from starlette.exceptions import HTTPException

    reply = errors_reply(HTTPException(status_code=418, detail=f"teapot {SENTINEL}"))
    assert reply.status_code == 418
    assert SENTINEL not in reply.body.decode() and "teapot" not in reply.body.decode()


def errors_reply(error):
    import asyncio

    return asyncio.run(errors.fixed_http_error(None, error))

@pytest.mark.owasp("A10", 248, 755)
def test_a_cancelled_task_or_shutdown_is_not_swallowed_by_the_catch_all():
    import asyncio

    async def cancelled(request):
        raise asyncio.CancelledError()

    class FakeRequest:  # only what the catch-all would read if it swallowed the error
        method = "GET"

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(errors.catch_everything(FakeRequest(), cancelled))



# ---------- What must keep working ----------

def test_a_bad_request_still_gets_the_short_422_reply():
    reply = client.get("/assignments?limit=0")  # the limit is below the allowed range
    assert reply.status_code == 422
    assert reply.json()["problems"][0]["reason"]


def test_a_normal_request_is_not_disturbed(monkeypatch):
    monkeypatch.setattr(BEHIND_THE_ROUTE, lambda *a, **k: [])
    reply = client.get(ROUTE)
    assert reply.status_code == 200 and reply.json() == []
