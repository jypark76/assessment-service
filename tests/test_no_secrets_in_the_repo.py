# In plain English: tests that nothing secret is saved in this repo. The repo is PUBLIC, so a key, a password
# or a private key committed by mistake is visible to the whole world and stays in the history even after it
# is deleted. These tests read every file, including comments, and fail on anything that looks like a real
# secret, on any file that is named like a secret, on any Kubernetes Secret manifest and on a .gitignore that
# has stopped blocking secret files.
#
# Why it matters (OWASP A01): sensitive information in source code (CWE-540), in comments (CWE-615) and in
# files that outsiders can reach (CWE-538). GitHub's push protection catches many keys, but it is a setting
# somebody can switch off; this test lives in the repo and runs on every pull request.
#
# The checker proves itself: each kind of planted secret must be caught. The planted values are built from
# pieces below, so this file does not contain a complete secret that it would then flag in itself.
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Folders that are not part of the repo's own files (tools, caches, private notes that are never committed).
SKIPPED_FOLDERS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", ".model_cache", "model_cache", "docs-private"}
MAX_BYTES = 1_000_000

# In plain English: the shapes of real secrets. Each is a name and a pattern.
PATTERNS = {
    "a private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "an AWS access key id": re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"),
    "an Anthropic API key": re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    "an OpenAI-style API key": re.compile(r"\bsk-(proj-)?[A-Za-z0-9_\-]{32,}"),
    "a GitHub token": re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})"),
    "a Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    "a Google API key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "a live payment key": re.compile(r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}"),
    "a signed token (JWT)": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "a password inside an address": re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@'\"<>]+:[^/\s:@'\"<>$]{3,}@"),
    "a long bearer token": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{24,}"),
    "a secret written into code": re.compile(r"(?i)\b(password|passwd|secret|api[_\-]?key|access[_\-]?key|auth[_\-]?token)\b[\"']?\s*[:=]\s*[\"'][^\"'\s{$<]{8,}[\"']"),
}

# In plain English: values that look like secrets but are made-up test values, each tied to the one file that
# may contain it. Add to this list only for a value that is clearly fake and exists only in tests.
ALLOWED_FAKES = {}

SECRET_FILE_NAMES = (
    re.compile(r"^\.env($|\.)"),
    re.compile(r"\.(pem|key|p12|pfx|jks|keystore)$"),
    re.compile(r"^id_(rsa|dsa|ecdsa|ed25519)"),
    re.compile(r"^kubeconfig"),
    re.compile(r"(?i)secret.*\.ya?ml$"),
)
REQUIRED_IGNORES = [".env", "*.pem", "*.key", "*secret*.yaml", "kubeconfig*"]


def repo_files():
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if any(part in SKIPPED_FOLDERS for part in relative.parts):
            continue
        if path.is_file():
            yield path, relative.as_posix()


# In plain English: returns the names of the patterns found in a piece of text, one entry per line that matched.
def find_secrets(text):
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        for name, pattern in PATTERNS.items():
            if pattern.search(line):
                found.append((name, number))
    return found


def readable_text_files():
    for path, relative in repo_files():
        if path.stat().st_size > MAX_BYTES:
            continue
        try:
            yield relative, path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # a binary file: nothing to read as text


# ---------- The real repo ----------

@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.owasp("A07", 259, 798)
def test_no_file_in_the_repo_holds_a_secret():
    problems = []
    for relative, text in readable_text_files():
        for name, line in find_secrets(text):
            if (relative, name) not in ALLOWED_FAKES:
                problems.append(f"{relative}:{line}: {name}")
    assert problems == []


@pytest.mark.owasp("A01", 540, 615, 538)
def test_the_scan_really_reads_the_repo():
    names = {relative for relative, _ in readable_text_files()}
    assert "pytest.ini" in names
    assert len(names) >= 8, names


@pytest.mark.owasp("A01", 538)
def test_no_file_is_named_like_a_secret():
    named = [relative for _, relative in repo_files() if any(rule.search(Path(relative).name) for rule in SECRET_FILE_NAMES)]
    assert named == []


@pytest.mark.owasp("A01", 538, 540)
@pytest.mark.owasp("A07", 259, 798)
def test_no_kubernetes_secret_manifest_is_saved_even_as_a_template():
    problems = [relative for relative, text in readable_text_files() if relative.endswith((".yaml", ".yml")) and re.search(r"(?m)^kind:\s*Secret\s*$", text)]
    assert problems == []


@pytest.mark.owasp("A01", 538, 540)
def test_gitignore_still_blocks_secret_files():
    lines = {line.strip() for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")}
    assert set(REQUIRED_IGNORES) <= lines, sorted(set(REQUIRED_IGNORES) - lines)


@pytest.mark.owasp("A01", 538)
@pytest.mark.parametrize("name", [".env", ".env.local", "server.pem", "signing.key", "keystore.p12", "id_rsa", "id_ed25519", "kubeconfig", "kubeconfig-local", "db-secret.yaml", "my_secrets.yml"])
def test_the_file_name_rules_recognise_the_usual_secret_files(name):
    # The rules are a list; emptying it would make "no file is named like a secret" pass without checking anything.
    assert any(rule.search(name) for rule in SECRET_FILE_NAMES), name


@pytest.mark.owasp("A01", 538)
@pytest.mark.parametrize("name", ["main.py", "README.md", "requirements.txt", "tests.yml", "kustomization.yaml", "configmap.yaml", "environment.py"])
def test_the_file_name_rules_leave_ordinary_files_alone(name):
    assert not any(rule.search(name) for rule in SECRET_FILE_NAMES), name


@pytest.mark.owasp("A01", 538, 540)
def test_the_required_ignore_list_names_the_essentials():
    assert {".env", "*.pem", "*.key", "*secret*.yaml", "kubeconfig*"} <= set(REQUIRED_IGNORES)


@pytest.mark.owasp("A01", 540, 615)
def test_every_allowed_fake_is_still_needed():
    for (relative, name), reason in ALLOWED_FAKES.items():
        path = ROOT / relative
        if not path.exists():
            continue  # this repo does not have that file
        hits = [pattern_name for pattern_name, _ in find_secrets(path.read_text(encoding="utf-8"))]
        assert name in hits, f"{relative}: the allowance for '{name}' ({reason}) is no longer needed; remove it"


# ---------- The check proves itself ----------

def made(*pieces):
    return "".join(pieces)


PLANTED = {
    "a private key": made("-----BEGIN ", "RSA PRIVATE", " KEY-----"),
    "an AWS access key id": made("AKIA", "ABCDEFGHIJKLMNOP"),
    "an Anthropic API key": made("sk-", "ant-", "api03-", "abcdefghijklmnopqrstuvwx"),
    "an OpenAI-style API key": made("sk-", "abcdefghijklmnopqrstuvwxyz012345"),
    "a GitHub token": made("ghp", "_", "abcdefghijklmnopqrstuvwxyz0123456789"),
    "a Slack token": made("xox", "b-", "1234567890-abcdefghij"),
    "a Google API key": made("AI", "zaSyA-", "1234567890abcdefghijklmnopqrstu"),
    "a live payment key": made("sk", "_live_", "abcdefghijklmnopqrstu"),
    "a signed token (JWT)": made("ey", "JhbGciOiJIUzI1NiJ9", ".ey", "JzdWIiOiIxMjM0NTY3ODkwIn0", ".abcdefghijklmnop"),
    "a password inside an address": made("postgresql", "://user:", "hunter2pw", "@db.example"),
    "a long bearer token": made("Authorization: ", "Bearer", " abcdefghijklmnopqrstuvwxyz012345"),
    "a secret written into code": made("pass", "word = ", "'hunter2hunter2'"),
}


@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.parametrize("label", sorted(PLANTED))
def test_every_kind_of_planted_secret_is_caught(label):
    names = [name for name, _ in find_secrets(f"value = {PLANTED[label]}\n")]
    assert label in names, (label, names)


@pytest.mark.owasp("A01", 615)
def test_a_secret_hidden_in_a_comment_is_caught():
    source = "def f():\n    # old key, remove later: " + PLANTED["an AWS access key id"] + "\n    return 1\n"
    assert [name for name, _ in find_secrets(source)] == ["an AWS access key id"]


@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.parametrize(
    "harmless",
    [
        "Authorization: Bearer <the key>",
        "header = f'Bearer {key}'",
        "password = os.environ['DB_PASSWORD']",
        "DB_PASSWORD: ${{ env.APP_PASSWORD }}",
        "secretKeyRef: {name: service-keys}",
        "# the key is created by hand with kubectl",
        "postgresql://user:$PASSWORD@host/db",
        "short = 'abc'",
    ],
)
def test_ordinary_text_about_secrets_is_not_flagged(harmless):
    assert find_secrets(harmless + "\n") == []
