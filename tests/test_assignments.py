# In plain English: these tests check the assignment routes of the service from the
# outside, the way a caller would use them, against the real app and a real Postgres.
# They cover:
#   1. creating an assignment and reading it back, and listing the newest ones;
#   2. an unknown assignment gives "not found", and a title already in use is refused;
#   3. bad input is refused with the field and the reason, and never the value sent;
#   4. the API has no way to change or remove an assignment.
#
# Every refusal is paired with a control: the same request done correctly must work.
# Bad values carry the marker SECRET-MARKER, and no reply may ever contain it.
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app

pytestmark = pytest.mark.usefixtures("require_test_database")

client = TestClient(app)


# In plain English: a correct request body. Titles must be unique, so each one gets a
# random title unless the test wants a specific one.
def good_body(title=None):
    return {
        "instructor_username": "instructor1",
        "title": title if title is not None else f"Essay {uuid.uuid4()}",
        "rubric": "Grade for clarity and evidence.",
    }


# In plain English: creates an assignment through the API and returns the reply.
def create(body=None):
    return client.post("/assignments", json=body or good_body())


# ---------------------------------------------------------------------------
# 1. Create, read back, list
# ---------------------------------------------------------------------------


# In plain English: a created assignment gets an ID from the service, and reading it
# back shows everything that was sent, including the rubric.
def test_create_then_read_back():
    body = good_body()
    created = create(body)
    assert created.status_code == 201
    assignment_id = created.json()["assignment_id"]
    uuid.UUID(assignment_id)

    fetched = client.get(f"/assignments/{assignment_id}")
    assert fetched.status_code == 200
    data = fetched.json()
    assert data["assignment_id"] == assignment_id
    assert data["title"] == body["title"]
    assert data["instructor_username"] == body["instructor_username"]
    assert data["rubric"] == body["rubric"]
    assert data["created_at"]


# In plain English: spaces at either end of a title are trimmed before it is stored.
def test_a_title_is_stored_without_outer_spaces():
    title = f"Padded {uuid.uuid4()}"
    created = create(good_body(title=f"  {title}  "))
    assert created.status_code == 201

    fetched = client.get(f"/assignments/{created.json()['assignment_id']}")
    assert fetched.json()["title"] == title


# In plain English: the list shows the newest first, leaves the rubric out, and obeys
# the limit. Two assignments are created, and the second must come first.
def test_the_list_is_newest_first_without_rubrics_and_obeys_the_limit():
    first = create().json()["assignment_id"]
    second = create().json()["assignment_id"]

    listing = client.get("/assignments", params={"limit": 100})
    assert listing.status_code == 200
    items = listing.json()
    ids = [item["assignment_id"] for item in items]
    assert ids.index(second) < ids.index(first)
    assert all("rubric" not in item for item in items)
    assert {"assignment_id", "title", "instructor_username", "created_at"} <= set(items[0])

    newest_only = client.get("/assignments", params={"limit": 1}).json()
    assert [item["assignment_id"] for item in newest_only] == [second]
    assert len(client.get("/assignments").json()) <= 50


# In plain English: a limit outside 1 to 100, or one that is not a number, is refused.
# The limit of 100 is the control, and it works.
def test_a_bad_list_limit_is_refused():
    assert client.get("/assignments", params={"limit": 100}).status_code == 200
    for bad_limit in ("0", "101", "abc"):
        response = client.get("/assignments", params={"limit": bad_limit})
        assert response.status_code == 422
        assert [problem["field"] for problem in response.json()["problems"]] == ["query.limit"]


# ---------------------------------------------------------------------------
# 2. Not found and duplicates
# ---------------------------------------------------------------------------


# In plain English: an ID nobody created gives "not found" and the reply does not repeat
# the ID. An ID that is not a UUID at all is refused as bad input. A real ID is the
# control and works.
def test_an_unknown_assignment_is_not_found():
    real = create().json()["assignment_id"]
    assert client.get(f"/assignments/{real}").status_code == 200

    unknown = str(uuid.uuid4())
    response = client.get(f"/assignments/{unknown}")
    assert response.status_code == 404
    assert unknown not in response.text

    garbage = client.get("/assignments/SECRET-MARKER-12345")
    assert garbage.status_code == 422
    assert "SECRET-MARKER" not in garbage.text


# In plain English: a title already in use is refused with fixed wording, even when it
# differs only by capital letters or outer spaces. The reply never quotes the title.
# The first use of the title is the control and works.
def test_a_title_in_use_is_refused_without_repeating_it():
    title = f"SECRET-MARKER-{uuid.uuid4()}"
    assert create(good_body(title=title)).status_code == 201

    for look_alike in (title, title + " ", title.lower()):
        response = create(good_body(title=look_alike))
        assert response.status_code == 409
        assert response.json() == {"problem": "An assignment with this title already exists"}
        assert "SECRET-MARKER" not in response.text
        assert "secret-marker" not in response.text


# ---------------------------------------------------------------------------
# 3. Bad input
# ---------------------------------------------------------------------------


# In plain English: each bad request is refused with 422 naming only the field. The
# marker inside the bad value must never come back, and neither may the name of an
# invented field. The correct request first is the control and works.
def test_bad_input_names_the_field_and_never_the_value():
    assert create().status_code == 201

    long_marker = "SECRET-MARKER-" + "x" * 300
    cases = [
        ({"title": "   "}, "body.title"),
        ({"title": long_marker}, "body.title"),
        ({"title": 12345}, "body.title"),
        ({"instructor_username": ""}, "body.instructor_username"),
        ({"instructor_username": "   "}, "body.instructor_username"),
        ({"instructor_username": "SECRET-MARKER-" + "i" * 100}, "body.instructor_username"),
        ({"rubric": "   "}, "body.rubric"),
        ({"rubric": "SECRET-MARKER-" + "x" * 10_000}, "body.rubric"),
    ]
    for change, expected_field in cases:
        body = good_body()
        body.update(change)
        response = client.post("/assignments", json=body)
        assert response.status_code == 422, change
        assert [problem["field"] for problem in response.json()["problems"]] == [expected_field]
        assert "SECRET-MARKER" not in response.text

    missing = good_body()
    del missing["title"]
    response = client.post("/assignments", json=missing)
    assert response.status_code == 422
    assert [problem["field"] for problem in response.json()["problems"]] == ["body.title"]

    invented = good_body()
    invented["SECRET-MARKER-12345"] = "x"
    response = client.post("/assignments", json=invented)
    assert response.status_code == 422
    assert [problem["field"] for problem in response.json()["problems"]] == ["body"]
    assert "SECRET-MARKER" not in response.text


# In plain English: the limits are exact. A 200 character title, a 100 character
# instructor name and a 10,000 character rubric are all accepted, which shows the
# refusals above come from the limits and not from something else.
def test_the_limits_are_exact():
    body = {
        "instructor_username": "i" * 100,
        "title": (str(uuid.uuid4()) + "t" * 200)[:200],
        "rubric": "r" * 10_000,
    }
    assert create(body).status_code == 201


# ---------------------------------------------------------------------------
# 4. No way to change or remove
# ---------------------------------------------------------------------------


# In plain English: the API offers no way to change or delete an assignment. Reading it
# works (the control), and every attempt to change or remove it is turned away with
# "method not allowed".
def test_there_is_no_way_to_change_or_remove_an_assignment():
    assignment_id = create().json()["assignment_id"]
    assert client.get(f"/assignments/{assignment_id}").status_code == 200

    assert client.put(f"/assignments/{assignment_id}", json=good_body()).status_code == 405
    assert client.patch(f"/assignments/{assignment_id}", json={"title": "x"}).status_code == 405
    assert client.delete(f"/assignments/{assignment_id}").status_code == 405
