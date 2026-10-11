# In plain English: tests that the service can read its secrets (the service keys and the database password)
# from files that Kubernetes mounts, instead of from environment variables. A setting called NAME_FILE names the
# file; if it is not set, the plain NAME setting is used, which keeps local runs and the tests simple.
#
# Why it matters (OWASP A02, CWE-526, sensitive information in environment variables): every process in the
# container, every crash report and every "show me the settings" page can see the environment, so a password
# there tends to leak. A mounted file is visible only to the process that opens it, and a changed Secret reaches
# the file without restarting the pod.
#
# The file reader is the one place in app/ allowed to open a file. It may open only a path inside /etc/secrets,
# never a path with "..", and a file it cannot read stops the service (it never falls back to something open).
import logging

import pytest
from fastapi.testclient import TestClient

from app import auth, db, secret_files
from app.main import app

FRONT_KEY = "frontend-key-0123456789abcdef0123456789abcdef"
PATH = "/etc/secrets/service-key/keys"


@pytest.fixture
def files(monkeypatch):
    """A pretend disk: a dictionary of path -> text, in place of real files."""
    disk = {}

    def fake_read(path):
        if path not in disk:
            raise FileNotFoundError(path)
        return disk[path]

    monkeypatch.setattr(secret_files, "_read_text", fake_read)
    return disk


# ---------- Reading ----------

@pytest.mark.owasp("A02", 526)
def test_without_a_file_setting_the_plain_setting_is_used(monkeypatch):
    monkeypatch.delenv("THING_FILE", raising=False)
    monkeypatch.setenv("THING", "from-the-environment")
    assert secret_files.read_secret("THING") == "from-the-environment"


@pytest.mark.owasp("A02", 526)
def test_nothing_set_gives_nothing(monkeypatch):
    monkeypatch.delenv("THING_FILE", raising=False)
    monkeypatch.delenv("THING", raising=False)
    assert secret_files.read_secret("THING") is None


@pytest.mark.owasp("A02", 526)
def test_the_file_is_used_when_it_is_named_and_wins_over_the_plain_setting(monkeypatch, files):
    files["/etc/secrets/thing/value"] = "from-the-file"
    monkeypatch.setenv("THING_FILE", "/etc/secrets/thing/value")
    monkeypatch.setenv("THING", "from-the-environment")
    assert secret_files.read_secret("THING") == "from-the-file"


@pytest.mark.owasp("A02", 526)
@pytest.mark.parametrize("stored,expected", [("abc\n", "abc"), ("abc\r\n", "abc"), ("abc", "abc"), ("abc \n", "abc "), (" abc", " abc"), ("", ""), ("\n", "")])
def test_only_the_final_line_break_is_removed(monkeypatch, files, stored, expected):
    files["/etc/secrets/thing/value"] = stored
    monkeypatch.setenv("THING_FILE", "/etc/secrets/thing/value")
    assert secret_files.read_secret("THING") == expected


@pytest.mark.owasp("A02", 526)
def test_a_file_that_cannot_be_read_stops_the_service_and_never_falls_back(monkeypatch, files):
    monkeypatch.setenv("THING_FILE", "/etc/secrets/thing/missing")
    monkeypatch.setenv("THING", "a-value-that-must-not-be-used")
    with pytest.raises(RuntimeError) as problem:
        secret_files.read_secret("THING")
    assert "THING" in str(problem.value) and "must-not-be-used" not in str(problem.value) and "missing" not in str(problem.value)


# ---------- Which paths are allowed ----------

@pytest.mark.owasp("A02", 526)
@pytest.mark.parametrize(
    "path",
    [
        "/etc/secrets/thing/value",
        "/etc/secrets/value",
        "/etc/secrets/a/b/c/d",
    ],
)
def test_paths_inside_the_secrets_folder_are_allowed(monkeypatch, files, path):
    files[path] = "ok"
    monkeypatch.setenv("THING_FILE", path)
    assert secret_files.read_secret("THING") == "ok"


@pytest.mark.owasp("A02", 526)
@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "/etc/secrets",  # the folder itself, not a file inside it
        "/etc/secrets/",
        "/etc/secretsX/value",
        "/etc/secrets/../passwd",
        "/etc/secrets/thing/../../passwd",
        "etc/secrets/value",  # relative
        "./etc/secrets/value",
        "//etc/secrets/value",
        "/proc/self/environ",
        "/app/model_cache/anything",
        "   ",
    ],
)
def test_any_other_path_is_refused_before_a_file_is_opened(monkeypatch, files, path):
    files[path] = "should-never-be-read"
    monkeypatch.setenv("THING_FILE", path)
    with pytest.raises(RuntimeError):
        secret_files.read_secret("THING")


# ---------- In use: the service keys ----------

@pytest.mark.owasp("A02", 526)
@pytest.mark.parametrize("path", ["/etc/secrets/thing/value\x00/etc/passwd", "/etc/secrets/thing\x00", "", "  "])
def test_a_path_with_a_null_character_or_no_text_is_not_allowed(path):
    # The operating system will not even let a null character be set in an environment variable, so the check
    # is tested directly.
    assert secret_files._is_allowed(path) is False


@pytest.mark.owasp("A02", 526)
@pytest.mark.owasp("A04", 320)
def test_the_service_key_is_read_from_the_mounted_file(monkeypatch, files):
    monkeypatch.delenv("SERVICE_KEYS", raising=False)
    monkeypatch.setenv("SERVICE_KEYS_FILE", PATH)
    files[PATH] = f"frontend-service:{FRONT_KEY}\n"
    reply = TestClient(app).get("/openapi.json", headers={"Authorization": f"Bearer {FRONT_KEY}"})
    assert reply.status_code == 200
    assert TestClient(app).get("/openapi.json").status_code == 401


@pytest.mark.owasp("A02", 526)
@pytest.mark.owasp("A04", 320)
def test_a_changed_secret_takes_effect_without_a_restart(monkeypatch, files):
    monkeypatch.delenv("SERVICE_KEYS", raising=False)
    monkeypatch.setenv("SERVICE_KEYS_FILE", PATH)
    other = "frontend-key-2-0123456789abcdef0123456789abcd"
    files[PATH] = f"frontend-service:{FRONT_KEY}"
    client = TestClient(app)
    assert client.get("/openapi.json", headers={"Authorization": f"Bearer {FRONT_KEY}"}).status_code == 200
    files[PATH] = f"frontend-service:{other}"  # Kubernetes updates the file; no restart
    assert client.get("/openapi.json", headers={"Authorization": f"Bearer {FRONT_KEY}"}).status_code == 401
    assert client.get("/openapi.json", headers={"Authorization": f"Bearer {other}"}).status_code == 200


@pytest.mark.owasp("A02", 526)
def test_an_unreadable_key_file_leaves_the_service_closed(monkeypatch, files, caplog):
    monkeypatch.delenv("SERVICE_KEYS", raising=False)
    monkeypatch.setenv("SERVICE_KEYS_FILE", "/etc/secrets/service-key/missing")
    reply = TestClient(app).get("/openapi.json", headers={"Authorization": f"Bearer {FRONT_KEY}"})
    assert reply.status_code == 503 and reply.json() == {"problem": "Service key is not configured"}
    assert TestClient(app).get("/health").status_code == 200


@pytest.mark.owasp("A02", 526)
def test_a_key_file_with_a_path_outside_the_secrets_folder_leaves_the_service_closed(monkeypatch, files):
    monkeypatch.delenv("SERVICE_KEYS", raising=False)
    monkeypatch.setenv("SERVICE_KEYS_FILE", "/etc/passwd")
    files["/etc/passwd"] = f"frontend-service:{FRONT_KEY}"
    assert TestClient(app).get("/openapi.json", headers={"Authorization": f"Bearer {FRONT_KEY}"}).status_code == 503


# ---------- In use: the database password ----------

@pytest.mark.owasp("A02", 526)
def test_the_database_password_is_read_from_the_mounted_file(monkeypatch, files):
    for name, setting in (("DB_HOST", "localhost"), ("DB_NAME", "x"), ("DB_USER", "x")):
        monkeypatch.setenv(name, setting)
    monkeypatch.delenv("DB_PASSWORD", raising=False)
    monkeypatch.setenv("DB_PASSWORD_FILE", "/etc/secrets/db/app-password")
    files["/etc/secrets/db/app-password"] = "the-file-password\n"
    seen = {}
    monkeypatch.setattr(db.psycopg, "connect", lambda **kwargs: seen.update(kwargs) or "connection")
    assert db.connect() == "connection"
    assert seen["password"] == "the-file-password"


@pytest.mark.owasp("A02", 526)
@pytest.mark.owasp("A07", 258)
@pytest.mark.parametrize("stored", ["", "\n"])
def test_an_empty_password_file_stops_the_service_before_it_connects(monkeypatch, files, stored):
    for name, setting in (("DB_HOST", "localhost"), ("DB_NAME", "x"), ("DB_USER", "x")):
        monkeypatch.setenv(name, setting)
    monkeypatch.delenv("DB_PASSWORD", raising=False)
    monkeypatch.setenv("DB_PASSWORD_FILE", "/etc/secrets/db/app-password")
    files["/etc/secrets/db/app-password"] = stored
    monkeypatch.setattr(db.psycopg, "connect", lambda **kwargs: pytest.fail("it tried to connect without a password"))
    with pytest.raises(RuntimeError, match="DB_PASSWORD"):
        db.connect()


@pytest.mark.owasp("A02", 526)
def test_the_secret_value_never_appears_in_an_error_or_a_log(monkeypatch, files, caplog):
    value = "marker-value-0123456789abcdef"
    files["/etc/secrets/thing/value"] = value
    monkeypatch.setenv("THING_FILE", "/etc/secrets/thing/value")
    with caplog.at_level(logging.DEBUG):
        assert secret_files.read_secret("THING") == value
    assert all(value not in record.getMessage() for record in caplog.records)
    monkeypatch.setenv("THING_FILE", "/etc/secrets/thing/other")
    with pytest.raises(RuntimeError) as problem:
        secret_files.read_secret("THING")
    assert value not in str(problem.value)
