# In plain English: tests that our own code can never quietly keep using something that Python or a library
# has announced it will remove. When code in the app/ folder calls a deprecated function, Python raises a
# "deprecation warning". The test settings (pytest.ini) turn such a warning from OUR code into a test
# failure, so the build goes red the day it first happens and not the day the function disappears.
#
# Why it matters (OWASP A03, CWE-447 use of an obsolete function): retired functions stop getting fixes,
# including security fixes, and one day they are removed and the service breaks. Warnings from other
# people's libraries are NOT turned into failures, because we cannot fix those; only a warning raised from
# our app/ code counts.
#
# These tests run pytest itself on a small throwaway project that uses this repo's real pytest.ini, so they
# prove the real setting does what it says.
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent

# A stand-in for somebody else's library: it announces that old() is deprecated. stacklevel=2 blames the
# CALLER, which is how real libraries and Python itself report deprecations.
LIBRARY = (
    "import warnings\n\n"
    "def old():\n    warnings.warn('old() is deprecated', DeprecationWarning, stacklevel=2)\n\n"
    "def soon():\n    warnings.warn('soon() will be deprecated', PendingDeprecationWarning, stacklevel=2)\n\n"
    "def noisy_inside():\n    warnings.warn('noise inside the library itself', DeprecationWarning, stacklevel=1)\n"
)


# In plain English: builds the throwaway project and runs pytest on it. "files" maps a path to its text.
def run_sample(tmp_path, files):
    shutil.copy(HERE.parent / "pytest.ini", tmp_path / "pytest.ini")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "conftest.py").write_text("", encoding="utf-8")
    (tmp_path / "libcode.py").write_text(LIBRARY, encoding="utf-8")
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=tmp_path, capture_output=True, text=True, timeout=120)


CALLS_APP = "from app.thing import run\n\n\ndef test_it():\n    run()\n"


# ---------- Our own code calling something deprecated fails the build ----------

@pytest.mark.owasp("A03", 447)
def test_a_deprecated_call_from_our_code_fails_the_build(tmp_path):
    result = run_sample(tmp_path, {"app/__init__.py": "", "app/thing.py": "from libcode import old\n\n\ndef run():\n    old()\n", "tests/test_it.py": CALLS_APP})
    out = result.stdout + result.stderr
    assert result.returncode != 0, out
    assert "DeprecationWarning" in out and "old() is deprecated" in out


@pytest.mark.owasp("A03", 447)
def test_a_real_python_deprecation_in_our_code_fails_the_build(tmp_path):
    # datetime.utcnow() is deprecated since Python 3.12, a function that is easy to use by habit.
    body = "import datetime\n\n\ndef run():\n    return datetime.datetime.utcnow()\n"
    result = run_sample(tmp_path, {"app/__init__.py": "", "app/thing.py": body, "tests/test_it.py": CALLS_APP})
    assert result.returncode != 0, result.stdout
    assert "utcnow" in result.stdout + result.stderr


@pytest.mark.owasp("A03", 447)
def test_a_warning_about_a_coming_deprecation_also_fails_the_build(tmp_path):
    result = run_sample(tmp_path, {"app/__init__.py": "", "app/thing.py": "from libcode import soon\n\n\ndef run():\n    soon()\n", "tests/test_it.py": CALLS_APP})
    assert result.returncode != 0, result.stdout
    assert "PendingDeprecationWarning" in result.stdout + result.stderr


@pytest.mark.owasp("A03", 447)
def test_a_deprecated_call_made_while_a_module_loads_fails_the_build(tmp_path):
    result = run_sample(tmp_path, {"app/__init__.py": "", "app/thing.py": "from libcode import old\n\nold()\n\n\ndef run():\n    pass\n", "tests/test_it.py": CALLS_APP})
    assert result.returncode != 0, result.stdout


@pytest.mark.owasp("A03", 447)
def test_a_deprecated_call_deep_inside_the_app_package_fails_the_build(tmp_path):
    files = {
        "app/__init__.py": "",
        "app/inner/__init__.py": "",
        "app/inner/deep.py": "from libcode import old\n\n\ndef run():\n    old()\n",
        "tests/test_it.py": "from app.inner.deep import run\n\n\ndef test_it():\n    run()\n",
    }
    result = run_sample(tmp_path, files)
    assert result.returncode != 0, result.stdout


# ---------- Things that must NOT fail the build ----------

@pytest.mark.owasp("A03", 447)
def test_a_clean_app_passes(tmp_path):
    result = run_sample(tmp_path, {"app/__init__.py": "", "app/thing.py": "def run():\n    return 1\n", "tests/test_it.py": CALLS_APP})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.owasp("A03", 447)
def test_a_warning_blamed_on_somebody_elses_code_does_not_fail_the_build(tmp_path):
    # The warning is raised inside the library itself, which we cannot fix.
    body = "from libcode import noisy_inside\n\n\ndef run():\n    noisy_inside()\n"
    result = run_sample(tmp_path, {"app/__init__.py": "", "app/thing.py": body, "tests/test_it.py": CALLS_APP})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.owasp("A03", 447)
def test_deprecated_calls_in_the_tests_themselves_do_not_fail_the_build(tmp_path):
    files = {"app/__init__.py": "", "app/thing.py": "def run():\n    return 1\n", "tests/test_it.py": "from libcode import old\n\n\ndef test_it():\n    old()\n"}
    result = run_sample(tmp_path, files)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.owasp("A03", 447)
def test_a_package_whose_name_only_starts_with_app_is_not_ours(tmp_path):
    files = {
        "application/__init__.py": "",
        "application/thing.py": "from libcode import old\n\n\ndef run():\n    old()\n",
        "tests/test_it.py": "from application.thing import run\n\n\ndef test_it():\n    run()\n",
    }
    result = run_sample(tmp_path, files)
    assert result.returncode == 0, result.stdout + result.stderr
