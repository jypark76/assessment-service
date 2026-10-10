# In plain English: shared setup for the tests that need a real database. It holds the
# one safety guard in a single place, so it can never drift apart between test files.
#
# The guard: with no database settings at all, the tests quietly skip, so a normal run
# on your laptop still works. In the pipeline REQUIRE_DB=1 is set, and then a missing
# database is a failure, because a test that silently skips proves nothing. If the
# settings point at any database other than "assessment_test", the tests refuse to run,
# because the service's login cannot delete, so test rows are left behind and that is
# only acceptable in a throwaway database.
import os

import pytest


# In plain English: a test file asks for this guard by listing it in its
# "pytestmark" line near the top. Tests that need no database simply do not.
@pytest.fixture
def require_test_database():
    if not os.environ.get("DB_HOST"):
        if os.environ.get("REQUIRE_DB") == "1":
            pytest.fail("REQUIRE_DB is set but no database settings were given")
        pytest.skip("no test database configured")
    if os.environ.get("DB_NAME") != "assessment_test":
        pytest.fail("refusing to run: DB_NAME must be 'assessment_test', never a real database")


# In plain English: the shared service key for tests. The service refuses every call that
# does not carry a key, so the test setup configures one and hands each test client the
# matching header. The key is a made-up value that exists only in tests.
TEST_KEY = "test-only-key-0123456789abcdef0123456789"
AUTH_HEADERS = {"Authorization": f"Bearer {TEST_KEY}"}
os.environ["SERVICE_KEYS"] = TEST_KEY
