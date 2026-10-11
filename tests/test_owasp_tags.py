# In plain English: tests for the OWASP tags that mark which tests prove which weaknesses. The
# pipeline will report coverage from these tags, so a wrong tag must stop the run instead of quietly
# showing a guardrail as covered. These tests prove the checker accepts good tags and refuses every
# kind of bad one, and that the real tags in this repo all pass.
import pytest

import owasp_tags


class FakeMark:
    def __init__(self, args, kwargs=None):
        self.args, self.kwargs = args, kwargs or {}


class FakeItem:
    nodeid = "tests/test_fake.py::test_fake"

    def __init__(self, marks):
        self.marks = marks

    def iter_markers(self, name):
        return iter(self.marks if name == "owasp" else [])


@pytest.mark.parametrize("args", [("A01", 22), ("A05", 89, 74, 76), ("A10", 1), ("A09", 778, 221, 223)])
def test_good_tags_are_accepted(args):
    owasp_tags.check_owasp_args(args)


@pytest.mark.parametrize(
    "args",
    [
        (),
        ("A05",),  # no CWE number
        (89,),  # no category
        ("A00", 89),
        ("A11", 89),
        ("a05", 89),  # category must be written exactly
        ("A5", 89),
        ("A05 ", 89),
        ("A05\n", 89),  # a trailing newline must not slip past the pattern
        ("A05", "89"),  # a number written as text
        ("A05", 89.0),
        ("A05", True),  # True is a number in Python, but not a CWE
        ("A05", 0),
        ("A05", -3),
        ("A05", 89, 89),  # repeated
        (5, 89),
    ],
)
def test_bad_tags_are_refused(args):
    with pytest.raises(ValueError):
        owasp_tags.check_owasp_args(args)


def test_the_run_check_names_the_test_with_the_bad_tag():
    items = [FakeItem([FakeMark(("A05", 89))]), FakeItem([FakeMark(("A99", 89))])]
    with pytest.raises(ValueError, match="tests/test_fake.py::test_fake"):
        owasp_tags.check_items(items)


def test_a_tag_with_keyword_values_is_refused():
    with pytest.raises(ValueError, match="keyword"):
        owasp_tags.check_items([FakeItem([FakeMark(("A05", 89), {"cwe": 89})])])


def test_every_real_tag_in_this_repo_is_valid():
    # Reads the test files themselves, so the answer is the same however the tests are run.
    import ast
    from pathlib import Path

    found = 0
    for path in sorted(Path(__file__).resolve().parent.glob("test_*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.FunctionDef):
                continue
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and ast.unparse(decorator.func) == "pytest.mark.owasp":
                    assert not decorator.keywords, (path.name, node.name)
                    owasp_tags.check_owasp_args(tuple(ast.literal_eval(a) for a in decorator.args))
                    found += 1
    assert found, "no test carries an owasp tag"


# ---------- The real run stops on a bad tag ----------
# These run pytest itself on a throwaway project that uses this repo's real conftest.py, pytest.ini and
# tag checker, so they prove the hook is wired in and a misspelled marker is refused.

# In plain English: this run's own settings with the pipeline's coverage variables removed, so a sample
# run can never switch on the coverage check or write into the real run's summary page.
def clean_environment():
    import os

    return {k: v for k, v in os.environ.items() if k not in ("OWASP_ENFORCE_COVERAGE", "GITHUB_STEP_SUMMARY")}


def run_pytest_on(tmp_path, test_text):
    import shutil
    import subprocess
    import sys
    from pathlib import Path

    here = Path(__file__).resolve().parent
    (tmp_path / "tests").mkdir()
    shutil.copy(here.parent / "pytest.ini", tmp_path / "pytest.ini")
    shutil.copy(here / "conftest.py", tmp_path / "tests" / "conftest.py")
    shutil.copy(here / "owasp_tags.py", tmp_path / "tests" / "owasp_tags.py")
    shutil.copy(here / "owasp_report.py", tmp_path / "tests" / "owasp_report.py")
    (tmp_path / "tests" / "test_sample.py").write_text(test_text, encoding="utf-8")
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=tmp_path, capture_output=True, text=True, timeout=120, env=clean_environment())


GOOD_SAMPLE = 'import pytest\n\n@pytest.mark.owasp("A05", 89)\ndef test_a():\n    pass\n'


def test_the_run_passes_with_a_good_tag(tmp_path):
    result = run_pytest_on(tmp_path, GOOD_SAMPLE)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_run_stops_on_a_bad_tag(tmp_path):
    result = run_pytest_on(tmp_path, GOOD_SAMPLE.replace('"A05"', '"A55"'))
    assert result.returncode != 0
    assert "bad owasp tag" in result.stdout + result.stderr
    assert "test_sample.py::test_a" in result.stdout + result.stderr


def test_the_run_stops_on_a_misspelled_marker(tmp_path):
    result = run_pytest_on(tmp_path, GOOD_SAMPLE.replace("mark.owasp", "mark.owsap"))
    assert result.returncode != 0
    assert "owsap" in result.stdout + result.stderr
