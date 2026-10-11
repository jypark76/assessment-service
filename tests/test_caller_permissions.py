# In plain English: tests that each caller has its own key and may use only the routes it needs. The service key
# check used to answer one question ("is this a trusted caller?"). Now it also answers "which caller, and may it
# use THIS route?". A key belongs to one named caller, a caller that holds a valid key but is not allowed on a
# route gets a fixed 403, and a route nobody has decided about is refused for everyone.
#
# Why it matters (OWASP A01, CWE-284 improper access control, CWE-285 improper authorization and CWE-863
# incorrect authorization): with one shared key, any caller that holds it could use every route. With named keys
# and a permission table, a leaked key can do only what its caller was allowed to do, and the log says which
# caller was refused.
#
# In this service the only web caller is frontend-service (the grader talks to it over Kafka), so the real table
# has no limited caller. To exercise the 403 path these tests add a TEST-ONLY caller, "report-viewer", that may
# only list assignments; it exists for the length of each test and never in the service.
#
# The expectations below are written out in full on purpose, separately from the table in app/auth.py. If the
# table is widened by mistake, or a route is added without a decision, these tests turn red.
import hashlib
import logging

import pytest
from fastapi.testclient import TestClient
from starlette.routing import Route

from app import auth
from app.main import app

REAL_TABLE = {name: (value if value == auth.ALL_ROUTES else set(value)) for name, value in auth.PERMISSIONS.items()}

FRONT_KEY = "frontend-key-0123456789abcdef0123456789abcdef"
VIEWER_KEY = "viewer-key-0123456789abcdef0123456789abcdef01"
OLD_KEY = "legacy-key-0123456789abcdef0123456789abcdef012"
SECOND_FRONT_KEY = "frontend-key-2-0123456789abcdef0123456789abcd"

CONFIG = f"frontend-service:{FRONT_KEY},report-viewer:{VIEWER_KEY}"
ZERO = "00000000-0000-0000-0000-000000000000"
OPEN_PATHS = {"/health", "/ready"}

# Every route of the service, written out. A new route must be added here AND given a decision in app/auth.py.
EXPECTED_ROUTES = {
    "POST /assignments", "GET /assignments", "GET /assignments/{assignment_id}",
    "POST /submissions", "GET /submissions", "GET /submissions/{submission_id}",
    "POST /submissions/{submission_id}/grades", "POST /submissions/{submission_id}/reviews",
    "GET /openapi.json", "HEAD /openapi.json", "GET /docs", "HEAD /docs",
    "GET /docs/oauth2-redirect", "HEAD /docs/oauth2-redirect", "GET /redoc", "HEAD /redoc",
}
# What each caller may use in the REAL service ("*" means every route).
REAL_ALLOWED = {"frontend-service": "*", "legacy": "*"}
# What each caller may use in these tests, including the test-only one.
EXPECTED_ALLOWED = {**REAL_ALLOWED, "report-viewer": {"GET /assignments"}}


def allowed(caller, route_key):
    permitted = EXPECTED_ALLOWED[caller]
    return permitted == "*" or route_key in permitted


def real_route_keys():
    found = set()
    for route in app.routes:
        if isinstance(route, Route) or hasattr(route, "methods"):
            if route.path in OPEN_PATHS:
                continue
            for method in route.methods:
                found.add(f"{method} {route.path}")
    return found


def concrete(path):
    out = path
    while "{" in out:
        start = out.index("{")
        out = out[:start] + ZERO + out[out.index("}") + 1:]
    return out


def call(route_key, key, extra_headers=None):
    method, path = route_key.split(" ", 1)
    headers = {"Authorization": f"Bearer {key}", **(extra_headers or {})}
    body = {"json": {}} if method == "POST" else {}
    return TestClient(app).request(method, concrete(path), headers=headers, **body)


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setitem(auth.PERMISSIONS, "report-viewer", {"GET /assignments"})  # the test-only caller
    monkeypatch.setenv("SERVICE_KEYS", CONFIG)
    auth.reset_refusal_window()
    return monkeypatch


# ---------- Reading the setting ----------

@pytest.mark.owasp("A01", 284, 285, 863)
def test_named_keys_are_read_with_their_caller_names():
    callers, problems = auth.parse_callers(CONFIG)
    assert problems == []
    assert sorted((name, key.decode()) for name, key in callers) == [("frontend-service", FRONT_KEY), ("report-viewer", VIEWER_KEY)]


@pytest.mark.owasp("A01", 284, 285, 863)
def test_a_plain_key_still_works_as_the_legacy_caller_so_nothing_breaks_during_the_switch():
    callers, problems = auth.parse_callers(OLD_KEY)
    assert problems == [] and [(name, key.decode()) for name, key in callers] == [("legacy", OLD_KEY)]
    callers, problems = auth.parse_callers(f"{OLD_KEY},{CONFIG}")
    assert problems == [] and {name for name, _ in callers} == {"legacy", "frontend-service", "report-viewer"}


@pytest.mark.owasp("A01", 284, 285, 863)
def test_one_caller_may_hold_two_keys_so_a_key_can_be_replaced_without_downtime():
    callers, problems = auth.parse_callers(f"frontend-service:{FRONT_KEY},frontend-service:{SECOND_FRONT_KEY}")
    assert problems == [] and len(callers) == 2
    for key in (FRONT_KEY, SECOND_FRONT_KEY):
        assert auth.authenticate(key.encode(), callers) == "frontend-service"


@pytest.mark.owasp("A01", 284, 285, 863)
@pytest.mark.parametrize(
    "raw",
    [
        f"Frontend-Service:{FRONT_KEY}",  # capital letters are not allowed in a name
        f"front end:{FRONT_KEY}",
        f"a:{FRONT_KEY}",  # a name needs at least two characters
        f"-front:{FRONT_KEY}",
        f"x" * 60 + f":{FRONT_KEY}",  # too long
        f"surprise-service:{FRONT_KEY}",  # a name this service has no permissions for
        f"grader-service:{VIEWER_KEY}",  # the grader uses Kafka here, so it has no web permissions at all
        f"frontend-service:{FRONT_KEY},report-viewer:{FRONT_KEY}",  # one key shared by two callers
        f"frontend-service:{FRONT_KEY},{FRONT_KEY}",  # the same key as a named caller and as legacy
    ],
)
def test_a_bad_setting_is_reported_and_the_service_stays_closed(raw, fresh):
    _, problems = auth.parse_callers(raw)
    assert problems, raw
    fresh.setenv("SERVICE_KEYS", raw)
    reply = TestClient(app).get("/assignments", headers={"Authorization": f"Bearer {FRONT_KEY}"})
    assert reply.status_code == 503 and reply.json() == {"problem": "Service key is not configured"}
    assert TestClient(app).get("/health").status_code == 200  # the health checks stay open


@pytest.mark.owasp("A01", 284, 285, 863)
def test_a_badly_formed_name_and_an_unknown_name_are_reported_as_different_problems():
    # Both are refused, but for different reasons; the name format is checked first, on its own.
    _, malformed = auth.parse_callers(f"Not A Name:{FRONT_KEY}")
    _, unknown = auth.parse_callers(f"surprise-service:{FRONT_KEY}")
    assert malformed == ["a caller name is not valid"]
    assert unknown == ["a caller name has no permissions in this service"]


@pytest.mark.owasp("A01", 284, 285, 863)
@pytest.mark.owasp("A07", 1391)
def test_a_key_that_is_too_short_is_ignored_not_used():
    callers, _ = auth.parse_callers(f"frontend-service:short,report-viewer:{VIEWER_KEY}")
    assert [name for name, _ in callers] == ["report-viewer"]


# ---------- Which caller may use which route ----------

@pytest.mark.owasp("A01", 284, 285, 863)
@pytest.mark.owasp("A06", 1125)
def test_the_routes_that_exist_are_exactly_the_routes_these_tests_know_about():
    assert real_route_keys() == EXPECTED_ROUTES


@pytest.mark.owasp("A01", 284, 285, 863)
def test_the_real_permission_table_matches_the_written_expectations():
    assert set(REAL_TABLE) == set(REAL_ALLOWED)
    for caller, permitted in REAL_ALLOWED.items():
        assert REAL_TABLE[caller] == (auth.ALL_ROUTES if permitted == "*" else set(permitted)), caller
    for caller, permitted in REAL_TABLE.items():
        if permitted != auth.ALL_ROUTES:
            assert permitted <= EXPECTED_ROUTES, (caller, permitted - EXPECTED_ROUTES)  # no entry for a route that does not exist


@pytest.mark.owasp("A01", 284, 285, 863)
@pytest.mark.parametrize("caller,key", [("frontend-service", FRONT_KEY), ("report-viewer", VIEWER_KEY)])
@pytest.mark.owasp("A06", 266, 269, 286)
def test_every_caller_gets_exactly_the_routes_it_is_allowed_on_every_route(caller, key):
    wrong = []
    for route_key in sorted(EXPECTED_ROUTES):
        status = call(route_key, key).status_code
        if allowed(caller, route_key):
            ok = status not in (401, 403)
        else:
            ok = status == 403
        if not ok:
            wrong.append((route_key, status))
    assert wrong == []


@pytest.mark.owasp("A01", 284, 285, 863)
def test_the_legacy_plain_key_keeps_full_access_until_it_is_removed(fresh):
    fresh.setenv("SERVICE_KEYS", f"{OLD_KEY},{CONFIG}")
    for route_key in sorted(EXPECTED_ROUTES):
        assert call(route_key, OLD_KEY).status_code not in (401, 403), route_key


@pytest.mark.owasp("A01", 284, 285, 863)
@pytest.mark.owasp("A07", 290, 302)
@pytest.mark.owasp("A06", 266, 269, 472, 807)
def test_a_caller_cannot_borrow_another_callers_rights_by_saying_so(fresh):
    for header in ("X-Caller", "X-Forwarded-User", "Caller", "X-Service-Name"):
        reply = call("POST /assignments", VIEWER_KEY, {header: "frontend-service"})
        assert reply.status_code == 403, header


@pytest.mark.owasp("A01", 284, 285, 863)
@pytest.mark.owasp("A07", 287)
@pytest.mark.owasp("A06", 454, 472, 807)
def test_the_key_decides_the_caller_and_a_key_from_nowhere_decides_nothing():
    assert call("GET /assignments", "not-a-configured-key-0123456789abcdef0123").status_code == 401
    assert call("POST /assignments", VIEWER_KEY).status_code == 403


@pytest.mark.owasp("A01", 862, 863)
def test_an_address_that_does_not_exist_still_gets_a_plain_not_found_for_a_valid_key():
    reply = call("GET /no-such-page", VIEWER_KEY)
    assert reply.status_code == 404 and reply.json() == {"problem": "Not found"}


@pytest.mark.owasp("A01", 862, 863)
def test_a_wrong_method_on_a_real_address_is_a_405_not_a_403():
    reply = call("DELETE /assignments", VIEWER_KEY)
    assert reply.status_code == 405


# ---------- The refusal ----------

@pytest.mark.owasp("A01", 284, 285, 863)
def test_a_caller_on_the_wrong_route_gets_one_fixed_reply_that_reveals_nothing():
    reply = call("POST /assignments", VIEWER_KEY)
    assert reply.status_code == 403
    assert reply.json() == {"problem": "This key is not allowed to use this route"}
    assert "www-authenticate" not in reply.headers
    for leaked in ("viewer", "frontend", "PERMISSIONS", "GET /assignments", VIEWER_KEY):
        assert leaked not in reply.text


@pytest.mark.owasp("A01", 284, 285, 863)
def test_the_log_names_the_caller_and_the_route_but_never_the_key(caplog):
    with caplog.at_level(logging.DEBUG):
        call("POST /assignments", VIEWER_KEY)
    lines = [r.getMessage() for r in caplog.records if r.name == auth.LOGGER_NAME]
    assert len(lines) == 1
    assert "reason=forbidden" in lines[0] and "caller=report-viewer" in lines[0] and "POST" in lines[0] and "/assignments" in lines[0]
    for record in caplog.records:
        assert VIEWER_KEY not in record.getMessage() and "Bearer" not in record.getMessage()
        assert hashlib.sha256(VIEWER_KEY.encode()).hexdigest() not in record.getMessage()


@pytest.mark.owasp("A01", 284, 285, 863)
def test_forbidden_attempts_share_the_flood_limit_with_other_refusals(caplog):
    with caplog.at_level(logging.INFO):
        for _ in range(auth.REFUSAL_LOG_LIMIT + 10):
            call("POST /assignments", VIEWER_KEY)
    lines = [r for r in caplog.records if r.name == auth.LOGGER_NAME]
    assert len(lines) == auth.REFUSAL_LOG_LIMIT


@pytest.mark.owasp("A01", 284, 285, 863)
@pytest.mark.owasp("A07", 303)
def test_every_configured_key_is_compared_so_timing_does_not_reveal_which_one_matched(monkeypatch):
    seen = []
    real = auth.hmac.compare_digest
    monkeypatch.setattr(auth.hmac, "compare_digest", lambda a, b: seen.append(1) or real(a, b))
    callers, _ = auth.parse_callers(f"{OLD_KEY},{CONFIG}")
    auth.authenticate(FRONT_KEY.encode(), callers)  # matches the second of three
    assert len(seen) == len(callers) == 3
