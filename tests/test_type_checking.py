# In plain English: a guardrail that runs a type checker (mypy) over the whole application every time the tests
# run. It catches a call made with the wrong number or kind of arguments, a value of the wrong kind passed on, a
# misspelled attribute, and similar slips, before the program ever runs. Without it such a mistake only shows up
# when that exact line is reached, which for a rarely used error path can be in production.
#
# The tests below check four things:
#   1. the real application passes the checker;
#   2. the checker really does catch a wrong call (so the first check cannot pass by looking at nothing);
#   3. its settings cannot be quietly loosened (no skipped files, no blanket "ignore errors");
#   4. the number of places where a check is switched off with "type: ignore" is fixed, so a new one is a
#      deliberate decision made in a pull request, never a quiet edit.
#
# Why it matters (OWASP A06, insecure design): CWE-628, a function called with incorrectly specified arguments.
import ast
import configparser
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"
CONFIG = ROOT / "mypy.ini"
# The places where a check is switched off on purpose: file name -> how many. Each has a comment saying why.
ALLOWED_TYPE_IGNORES = {"main.py": 1}


def run_mypy(*arguments, cwd=ROOT):
    return subprocess.run(
        [sys.executable, "-m", "mypy", *arguments], capture_output=True, text=True, cwd=cwd, timeout=600
    )


@pytest.mark.owasp("A06", 628)
def test_the_application_passes_the_type_checker():
    result = run_mypy()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Success: no issues found in" in result.stdout


@pytest.mark.owasp("A06", 628)
@pytest.mark.parametrize(
    "label, source",
    [
        ("too many arguments", "def f(a: int) -> int:\n    return a\n\nf(1, 2)\n"),
        ("the wrong kind of argument", "def f(a: int) -> int:\n    return a\n\nf('x')\n"),
        ("a missing argument", "def f(a: int, b: int) -> int:\n    return a + b\n\nf(1)\n"),
        ("a misspelled keyword", "def f(a: int) -> int:\n    return a\n\nf(b=1)\n"),
        ("a call inside a function with no annotations", "def f(a: int) -> int:\n    return a\n\ndef g():\n    return f(1, 2)\n"),
    ],
)
def test_the_checker_really_catches_a_wrong_call(tmp_path, label, source):
    sample = tmp_path / "sample.py"
    sample.write_text(source, encoding="utf-8")
    result = run_mypy("--config-file", str(CONFIG), str(sample), cwd=tmp_path)
    assert result.returncode == 1, f"not caught: {label}\n{result.stdout}"


@pytest.mark.owasp("A06", 628)
def test_the_checker_settings_cannot_be_loosened_quietly():
    parser = configparser.ConfigParser()
    parser.read(CONFIG, encoding="utf-8")
    assert parser.sections() == ["mypy"], "per-file or per-module exceptions are not allowed"
    settings = parser["mypy"]
    assert settings["files"].strip() == "app"
    assert settings.getboolean("check_untyped_defs") is True
    assert settings.getboolean("warn_unused_ignores") is True
    assert settings.getboolean("no_implicit_optional") is True
    for loosening in ("ignore_errors", "ignore_missing_imports", "follow_imports", "exclude", "disable_error_code"):
        assert loosening not in settings, loosening


@pytest.mark.owasp("A06", 628)
def test_the_places_where_a_check_is_switched_off_are_exactly_the_agreed_ones():
    found = {}
    for path in sorted(APP.rglob("*.py")):
        count = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if "# type: ignore" in line or "# mypy:" in line)
        if count:
            found[path.name] = count
    assert found == ALLOWED_TYPE_IGNORES
    for path in APP.rglob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"))  # every file is real Python the checker can read
