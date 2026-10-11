# In plain English: tests for the OWASP coverage report and the check that guards it. The report must
# show which weaknesses have a passing test, must fail the pipeline when a claimed guardrail loses its
# test (deleted, skipped or failing) or when a tag is used without being declared, and must never list
# anything that is not covered, because this repo is public.
import ast
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import owasp_report

HERE = Path(__file__).resolve().parent


# ---------- Reading expected-coverage.txt ----------

def test_the_expected_file_is_read_line_by_line_ignoring_comments_and_blanks():
    text = "# a comment\n\nA05 89 SQL Injection\n  A09   778   Insufficient Logging  \nA01 22\n"
    assert owasp_report.parse_expected(text) == [("A05", 89, "SQL Injection"), ("A09", 778, "Insufficient Logging"), ("A01", 22, "")]


@pytest.mark.parametrize(
    "text",
    ["A05\n", "A55 89 x\n", "A05 eighty x\n", "A05 0 x\n", "A05 -1 x\n", "A05 89 x\nA05 89 again\n", "A05 8.9 x\n", "A05\t89\tx\nA5 90 y\n"],
)
def test_a_bad_expected_line_is_refused_and_names_its_line(text):
    with pytest.raises(ValueError, match="expected-coverage.txt line"):
        owasp_report.parse_expected(text)


# ---------- Building the table ----------

def test_rows_count_each_outcome_and_list_only_tagged_cwes():
    tags = {"t1": [("A05", 89), ("A05", 74)], "t2": [("A05", 89)], "t3": [("A09", 778)], "t4": [("A05", 20)], "t5": [("A05", 610)]}
    statuses = {"t1": "passed", "t2": "failed", "t3": "passed", "t4": "skipped"}  # t5 never ran
    rows = {(r["category"], r["cwe"]): r for r in owasp_report.build_rows(tags, statuses, {("A05", 89): "SQL"})}
    assert set(rows) == {("A05", 89), ("A05", 74), ("A09", 778), ("A05", 20), ("A05", 610)}  # nothing untagged appears
    assert (rows[("A05", 89)]["tests"], rows[("A05", 89)]["passed"], rows[("A05", 89)]["failed"], rows[("A05", 89)]["result"]) == (2, 1, 1, "FAILING")
    assert rows[("A05", 89)]["name"] == "SQL"
    assert rows[("A05", 74)]["result"] == "Covered"
    assert rows[("A09", 778)]["result"] == "Covered"
    assert rows[("A05", 20)]["result"].startswith("Not proven") and rows[("A05", 20)]["skipped"] == 1
    assert rows[("A05", 610)]["result"].startswith("Not proven") and rows[("A05", 610)]["skipped"] == 1  # a test that did not run


def test_one_passing_test_is_enough_when_another_for_the_same_cwe_is_skipped():
    rows = owasp_report.build_rows({"t1": [("A05", 89)], "t2": [("A05", 89)]}, {"t1": "passed", "t2": "skipped"}, {})
    assert rows[0]["result"] == "Covered" and rows[0]["skipped"] == 1


# ---------- The checks that fail a run ----------

def make_rows(*pairs_and_outcomes):
    tags, statuses = {}, {}
    for i, (pair, outcome) in enumerate(pairs_and_outcomes):
        tags[f"t{i}"] = [pair]
        if outcome:
            statuses[f"t{i}"] = outcome
    return owasp_report.build_rows(tags, statuses, {})


def test_no_problems_when_every_listed_cwe_has_a_passing_test_and_nothing_else_is_tagged():
    rows = make_rows((("A05", 89), "passed"), (("A09", 778), "passed"))
    assert owasp_report.find_problems([("A05", 89, ""), ("A09", 778, "")], rows) == []


def test_a_listed_cwe_with_no_tagged_test_is_a_problem():
    problems = owasp_report.find_problems([("A05", 89, ""), ("A05", 74, "")], make_rows((("A05", 89), "passed")))
    assert len(problems) == 1 and "CWE-74" in problems[0] and "no test carries its tag" in problems[0]


def test_a_listed_cwe_whose_only_test_was_skipped_is_a_problem():
    problems = owasp_report.find_problems([("A05", 89, "")], make_rows((("A05", 89), "skipped")))
    assert len(problems) == 1 and "no test for it passed" in problems[0]


def test_a_listed_cwe_with_a_failing_test_is_a_problem():
    problems = owasp_report.find_problems([("A05", 89, "")], make_rows((("A05", 89), "failed"), (("A05", 89), "passed")))
    assert len(problems) == 1 and "failing" in problems[0]


def test_a_tagged_cwe_that_is_not_listed_is_a_problem():
    problems = owasp_report.find_problems([("A05", 89, "")], make_rows((("A05", 89), "passed"), (("A05", 74), "passed")))
    assert len(problems) == 1 and "CWE-74" in problems[0] and "not listed" in problems[0]


def test_the_same_cwe_in_two_categories_is_checked_per_category():
    problems = owasp_report.find_problems([("A05", 117, "")], make_rows((("A09", 117), "passed")))
    assert len(problems) == 2  # A05 117 has no test, A09 117 is not listed


# ---------- What is shown ----------

def test_the_markdown_shows_covered_rows_and_nothing_untagged():
    rows = make_rows((("A05", 89), "passed"), (("A05", 74), "passed"))
    text = owasp_report.render_markdown("some-service", rows, [])
    assert "some-service" in text and "CWE-89" in text and "CWE-74" in text and "2 of 2" in text
    assert "A05 Injection" in text
    for other in ("A01", "A02", "A03", "A04", "A06", "A07", "A08", "A09", "A10"):
        assert other not in text, other
    assert "Coverage check failed" not in text


def test_the_markdown_lists_problems_and_handles_an_empty_repo():
    text = owasp_report.render_markdown("x", make_rows((("A05", 89), "failed")), ["CWE-89 (A05) has a failing test"])
    assert "### Coverage check failed" in text and "- CWE-89 (A05) has a failing test" in text and "FAILING" in text
    assert "No guardrail tests" in owasp_report.render_markdown("x", [], [])


# ---------- A real run on throwaway projects ----------
# These run pytest itself on a small project that uses this repo's real conftest.py, pytest.ini and
# report code, so they prove the plug-in is wired in, writes the summary page and fails the run.

GOOD = 'import pytest\n\n@pytest.mark.owasp("A05", 89)\ndef test_a():\n    pass\n'
EXPECTED_89 = "A05 89 SQL Injection\n"


def run_sample(tmp_path, tests_text=GOOD, expected=EXPECTED_89, enforce=True, summary_text=None):
    (tmp_path / "tests").mkdir()
    shutil.copy(HERE.parent / "pytest.ini", tmp_path / "pytest.ini")
    for name in ("conftest.py", "owasp_tags.py", "owasp_report.py"):
        shutil.copy(HERE / name, tmp_path / "tests" / name)
    (tmp_path / "tests" / "test_sample.py").write_text(tests_text, encoding="utf-8")
    if expected is not None:
        (tmp_path / "expected-coverage.txt").write_text(expected, encoding="utf-8")
    summary = tmp_path / "summary.md"
    if summary_text is not None:
        summary.write_text(summary_text, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k not in ("OWASP_ENFORCE_COVERAGE", "GITHUB_STEP_SUMMARY")}
    if enforce:
        env["OWASP_ENFORCE_COVERAGE"] = "1"
    env["GITHUB_STEP_SUMMARY"] = str(summary)
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=tmp_path, capture_output=True, text=True, timeout=120, env=env)
    return result, (summary.read_text(encoding="utf-8") if summary.exists() else None)


def test_a_good_run_passes_and_writes_the_table_to_the_summary_page(tmp_path):
    result, summary = run_sample(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "CWE-89" in summary and "SQL Injection" in summary and "Covered" in summary
    assert "OWASP guardrail coverage" in result.stdout  # the terminal shows it too


def test_the_summary_is_added_to_the_end_of_what_the_page_already_has(tmp_path):
    result, summary = run_sample(tmp_path, summary_text="EARLIER-STEP-OUTPUT\n")
    assert result.returncode == 0
    assert summary.startswith("EARLIER-STEP-OUTPUT\n") and "CWE-89" in summary


def test_with_the_check_off_nothing_is_written_and_nothing_can_fail(tmp_path):
    result, summary = run_sample(tmp_path, expected=None, enforce=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert summary is None
    assert "CWE-89" in result.stdout  # still shown in the terminal


def test_deleting_a_guardrail_test_fails_the_run(tmp_path):
    result, summary = run_sample(tmp_path, tests_text="def test_a():\n    pass\n")
    assert result.returncode != 0
    assert "CWE-89" in result.stdout and "no test carries its tag" in result.stdout
    assert "Coverage check failed" in summary


def test_skipping_a_guardrail_test_fails_the_run(tmp_path):
    skipped = GOOD.replace("def test_a", '@pytest.mark.skip(reason="later")\ndef test_a')
    result, summary = run_sample(tmp_path, tests_text=skipped)
    assert result.returncode != 0
    assert "no test for it passed" in result.stdout
    assert "Not proven" in summary


def test_a_test_that_skips_itself_while_running_fails_the_run(tmp_path):
    skipped = GOOD.replace("    pass\n", '    pytest.skip("not today")\n')
    result, _ = run_sample(tmp_path, tests_text=skipped)
    assert result.returncode != 0 and "no test for it passed" in result.stdout


def test_a_failing_guardrail_test_is_shown_as_failing(tmp_path):
    result, summary = run_sample(tmp_path, tests_text=GOOD.replace("    pass\n", "    assert False\n"))
    assert result.returncode != 0
    assert "FAILING" in summary


def test_a_failing_teardown_counts_as_failing(tmp_path):
    text = (
        "import pytest\n\n@pytest.fixture\ndef broken():\n    yield\n    raise RuntimeError('cleanup failed')\n\n"
        '@pytest.mark.owasp("A05", 89)\ndef test_a(broken):\n    pass\n'
    )
    result, summary = run_sample(tmp_path, tests_text=text)
    assert result.returncode != 0
    assert "FAILING" in summary


def test_a_tag_that_is_not_declared_fails_the_run(tmp_path):
    text = GOOD + '\n@pytest.mark.owasp("A05", 74)\ndef test_b():\n    pass\n'
    result, _ = run_sample(tmp_path, tests_text=text)
    assert result.returncode != 0
    assert "CWE-74" in result.stdout and "not listed" in result.stdout


def test_a_missing_expected_file_fails_the_run_when_the_check_is_on(tmp_path):
    result, _ = run_sample(tmp_path, expected=None)
    assert result.returncode != 0 and "expected-coverage.txt is missing" in result.stdout


def test_a_broken_expected_file_fails_the_run_when_the_check_is_on(tmp_path):
    result, _ = run_sample(tmp_path, expected="A05 eighty-nine x\n")
    assert result.returncode != 0 and "expected-coverage.txt line 1" in result.stdout


def test_the_summary_never_lists_categories_with_no_tests(tmp_path):
    _, summary = run_sample(tmp_path)
    for other in ("A01", "A02", "A03", "A04", "A06", "A07", "A08", "A09", "A10"):
        assert other not in summary, other


def test_each_tag_is_reported_under_its_own_category_even_when_a_cwe_is_in_two(tmp_path):
    text = (
        "import pytest\n\n"
        '@pytest.mark.owasp("A05", 89, 117)\ndef test_a():\n    pass\n\n'
        '@pytest.mark.owasp("A09", 778, 117)\ndef test_b():\n    pass\n'
    )
    expected = "A05 89 x\nA05 117 x\nA09 778 x\nA09 117 x\n"
    result, summary = run_sample(tmp_path, tests_text=text, expected=expected)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "| A05 Injection | CWE-89 |" in summary and "| A05 Injection | CWE-117 |" in summary
    assert "| A09 Security Logging and Alerting Failures | CWE-778 |" in summary
    assert "| A09 Security Logging and Alerting Failures | CWE-117 |" in summary
    assert "A09 Security Logging and Alerting Failures | CWE-89 |" not in summary


# ---------- This repo's own list ----------

def test_this_repos_expected_file_matches_its_real_tags_exactly():
    found = set()
    for path in sorted(HERE.glob("test_*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.FunctionDef):
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call) and ast.unparse(decorator.func) == "pytest.mark.owasp":
                        args = [ast.literal_eval(a) for a in decorator.args]
                        found |= {(args[0], number) for number in args[1:]}
    listed = {(category, number) for category, number, _ in owasp_report.parse_expected((HERE.parent / "expected-coverage.txt").read_text(encoding="utf-8"))}
    assert listed == found
