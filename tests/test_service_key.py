# In plain English: tests for the shared service key. Every route except the two health
# checks must refuse a caller that does not present the key. These tests need no database:
# the key is checked before any route code runs.
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.main import app
from conftest import TEST_KEY

import pytest

OPEN_PATHS = {"/health", "/ready"}
OTHER_KEY = "another-valid-key-0123456789abcdef012345"
bare = TestClient(app)


# In plain English: every real route of the service, found by asking the app itself, so a
# route added later is checked automatically and cannot be forgotten. Path placeholders
# get a made-up UUID.
def all_routes():
    found = []
    for route in app.routes:
        if isinstance(route, APIRoute):
            path = route.path.replace("{submission_id}", "11111111-1111-1111-1111-111111111111")
            path = path.replace("{assignment_id}", "11111111-1111-1111-1111-111111111111")
            for method in route.methods:
                found.append((method, path, route.path))
    return found


def protected_routes():
    return [(m, p) for m, p, template in all_routes() if template not in OPEN_PATHS]


def call(method, path, headers=None):
    return bare.request(method, path, headers=headers or {})


@pytest.mark.owasp("A01", 862, 749)
@pytest.mark.owasp("A07", 306)
def test_the_route_list_is_not_empty_and_includes_the_open_ones():
    templates = {template for _, _, template in all_routes()}
    assert OPEN_PATHS <= templates
    assert len(protected_routes()) >= 8


def test_the_health_checks_need_no_key():
    assert call("GET", "/health").status_code == 200
    assert call("GET", "/ready").status_code in (200, 503)  # 503 only if the database is down


BAD_HEADERS = {
    "no_header": None,
    "wrong_key": {"Authorization": f"Bearer {OTHER_KEY}"},
    "wrong_scheme": {"Authorization": f"Basic {TEST_KEY}"},
    "empty_bearer": {"Authorization": "Bearer "},
    "just_the_word": {"Authorization": "Bearer"},
    "key_without_scheme": {"Authorization": TEST_KEY},
    "key_with_extra_space": {"Authorization": f"Bearer  {TEST_KEY}"},
    "key_with_trailing_space": {"Authorization": f"Bearer {TEST_KEY} "},
    "shorter_prefix_of_key": {"Authorization": f"Bearer {TEST_KEY[:-1]}"},
    "longer_than_key": {"Authorization": f"Bearer {TEST_KEY}x"},
    "lowercase_scheme_wrong_key": {"Authorization": f"bearer {OTHER_KEY}"},
}


@pytest.mark.owasp("A01", 862, 424, 425)
@pytest.mark.owasp("A07", 287, 304, 305, 306)
def test_every_protected_route_refuses_every_kind_of_bad_header():
    for method, path in protected_routes():
        for name, headers in BAD_HEADERS.items():
            response = call(method, path, headers)
            assert response.status_code == 401, (method, path, name)
            assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.owasp("A01", 425)
def test_the_refusal_is_identical_for_every_failure_and_repeats_nothing():
    bodies = {call("GET", "/assignments", headers).text for headers in BAD_HEADERS.values()}
    assert len(bodies) == 1
    sent = {"Authorization": f"Bearer {OTHER_KEY}"}
    assert OTHER_KEY not in call("GET", "/assignments", sent).text


@pytest.mark.owasp("A07", 303)
def test_the_right_key_gets_past_the_guard():
    headers = {"Authorization": f"Bearer {TEST_KEY}"}
    # An empty body is turned away by the normal input checks (422), which proves the
    # request got past the key check and reached the route.
    assert call("POST", "/assignments", headers).status_code == 422
    # The scheme word is not case sensitive.
    assert call("POST", "/assignments", {"Authorization": f"bearer {TEST_KEY}"}).status_code == 422


@pytest.mark.owasp("A07", 303)
def test_several_keys_can_be_valid_at_once_so_a_key_can_be_rotated(monkeypatch):
    monkeypatch.setenv("SERVICE_KEYS", f"{OTHER_KEY}, {TEST_KEY}")
    assert call("POST", "/assignments", {"Authorization": f"Bearer {OTHER_KEY}"}).status_code == 422
    assert call("POST", "/assignments", {"Authorization": f"Bearer {TEST_KEY}"}).status_code == 422
    monkeypatch.setenv("SERVICE_KEYS", OTHER_KEY)
    assert call("POST", "/assignments", {"Authorization": f"Bearer {TEST_KEY}"}).status_code == 401


@pytest.mark.owasp("A10", 636)
@pytest.mark.owasp("A07", 1392, 1393)
def test_with_no_key_configured_the_service_refuses_instead_of_opening(monkeypatch):
    for value in (None, "", "   ", ",", "short"):
        if value is None:
            monkeypatch.delenv("SERVICE_KEYS")
        else:
            monkeypatch.setenv("SERVICE_KEYS", value)
        for method, path in protected_routes():
            response = call(method, path, {"Authorization": f"Bearer {TEST_KEY}"})
            assert response.status_code == 503, (value, method, path)
        assert "short" not in response.text
    # The health checks still answer, so Kubernetes can see the pod is alive.
    assert call("GET", "/health").status_code == 200


@pytest.mark.owasp("A07", 1391)
def test_a_short_key_is_not_accepted_even_if_it_matches(monkeypatch):
    monkeypatch.setenv("SERVICE_KEYS", "short")
    assert call("GET", "/assignments", {"Authorization": "Bearer short"}).status_code == 503
