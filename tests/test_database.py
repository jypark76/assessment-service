# In plain English: these tests run the real service against a real Postgres
# database, so they check the parts the other tests cannot: that the service's
# limited login really works, and that it really is limited.
#
# SAFETY: once the service has tables, its login cannot delete, so tests cannot
# clean up after themselves and will leave rows behind. That is fine for a
# throwaway database and a disaster for a real one. So these tests refuse to run
# unless the database is named "assessment_test". The pipeline creates a fresh one
# for every run and throws it away afterwards. To run these on your own computer,
# start a temporary Postgres container yourself (see the README) and point the
# DB_* settings at it.
import os

import psycopg
import pytest
from fastapi.testclient import TestClient

from app.db import connect
from app.main import app

client = TestClient(app)


# In plain English: runs before every test in this file. With no database
# settings at all, the tests quietly skip, so a normal run on your laptop still
# works. In the pipeline REQUIRE_DB=1 is set, and then a missing database is a
# failure, because a test that silently skips proves nothing. If the settings
# point at any database other than "assessment_test", it refuses to run.
@pytest.fixture(autouse=True)
def require_test_database():
    if not os.environ.get("DB_HOST"):
        if os.environ.get("REQUIRE_DB") == "1":
            pytest.fail("REQUIRE_DB is set but no database settings were given")
        pytest.skip("no test database configured")
    if os.environ.get("DB_NAME") != "assessment_test":
        pytest.fail("refusing to run: DB_NAME must be 'assessment_test', never a real database")


# In plain English: with the right password the service says it is ready.
def test_ready_with_a_working_login():
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"ok": True}


# In plain English: the ready check must be able to fail. With a wrong password
# it must answer 503 and say nothing about why. The test first proves the right
# password works, so a 503 can only be caused by the wrong password and not by a
# database that was never reachable at all.
def test_ready_fails_quietly_with_a_wrong_password(monkeypatch):
    assert client.get("/ready").status_code == 200
    monkeypatch.setenv("DB_PASSWORD", "not-the-password")
    response = client.get("/ready")
    assert response.status_code == 503
    assert response.json() == {"ok": False}


# In plain English: the service's login really is limited. First it proves the test
# is running as that limited login and that connecting works, so the refusal below
# means "not allowed" and not "login missing". Then it tries to create a table, which
# a login that is only allowed to use the database must be refused.
def test_limited_login_connects_but_cannot_create_tables():
    with connect() as connection:
        who = connection.execute("SELECT current_user").fetchone()[0]
    assert who == "assessment_app"

    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with connect() as connection:
            connection.execute("CREATE TABLE should_not_exist (id int)")
