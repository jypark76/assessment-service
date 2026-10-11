# In plain English: the coverage report for the OWASP tags. After the tests run, it shows which OWASP
# weaknesses (CWEs) have at least one passing test, in the terminal and, in the pipeline, as a table
# on the run's summary page.
#
# It also guards the claims. The file expected-coverage.txt lists the CWEs this repo says it covers.
# When the pipeline turns checking on (OWASP_ENFORCE_COVERAGE=1), the run fails if a listed CWE has no
# passing test (someone deleted or skipped the guardrail) or if a test is tagged with a CWE that is
# not listed (a claim nobody wrote down on purpose). A test that was skipped counts as no proof.
#
# This repo is public, so the table shows only what is covered and never lists what is not.
import os
from collections import defaultdict
from pathlib import Path

import pytest

import owasp_tags

EXPECTED_FILE = "expected-coverage.txt"
ENFORCE_VARIABLE = "OWASP_ENFORCE_COVERAGE"
SUMMARY_VARIABLE = "GITHUB_STEP_SUMMARY"

CATEGORY_NAMES = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

# From best to worst, so a test with a failed teardown counts as failed even though its body passed.
SEVERITY = {"passed": 0, "skipped": 1, "failed": 2}


# In plain English: reads expected-coverage.txt. Each line is a category, a CWE number and then the
# CWE's name for people to read, for example "A05 89 Improper Neutralization of Special Elements...".
# Blank lines and lines starting with # are ignored. A bad line raises a ValueError that names it.
def parse_expected(text):
    entries, seen = [], set()
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        try:
            if len(parts) < 2:
                raise ValueError("a line needs a category and a CWE number")
            key = (parts[0], int(parts[1]))
            owasp_tags.check_owasp_args(key)
            if key in seen:
                raise ValueError("this CWE is listed twice")
        except ValueError as problem:
            raise ValueError(f"{EXPECTED_FILE} line {number}: {problem}") from None
        seen.add(key)
        entries.append((key[0], key[1], parts[2] if len(parts) == 3 else ""))
    return entries


# In plain English: turns what happened into table rows. "tags" maps each test to the (category, CWE)
# pairs it carries. "statuses" maps each test that ran to passed, skipped or failed. A row exists only
# for a CWE that at least one test carries, so nothing that is not covered is ever listed.
def build_rows(tags, statuses, names):
    counts = defaultdict(lambda: {"passed": 0, "skipped": 0, "failed": 0, "not run": 0})
    for test, pairs in tags.items():
        outcome = statuses.get(test, "not run")
        for pair in pairs:
            counts[pair][outcome] += 1
    rows = []
    for (category, number), c in sorted(counts.items()):
        total = sum(c.values())
        if c["failed"]:
            result = "FAILING"
        elif c["passed"]:
            result = "Covered"
        else:
            result = "Not proven (no test passed)"
        rows.append(
            {"category": category, "cwe": number, "name": names.get((category, number), ""), "tests": total,
             "passed": c["passed"], "failed": c["failed"], "skipped": c["skipped"] + c["not run"], "result": result}
        )
    return rows


# In plain English: the checks that fail a run. "expected" is the list from expected-coverage.txt and
# "rows" is the table. Returns a list of sentences, empty when everything agrees.
def find_problems(expected, rows):
    problems = []
    by_pair = {(r["category"], r["cwe"]): r for r in rows}
    listed = {(category, number) for category, number, _name in expected}
    for category, number, _name in expected:
        row = by_pair.get((category, number))
        if row is None:
            problems.append(f"CWE-{number} ({category}) is listed in {EXPECTED_FILE} but no test carries its tag")
        elif row["failed"]:
            problems.append(f"CWE-{number} ({category}) has a failing test")
        elif not row["passed"]:
            problems.append(f"CWE-{number} ({category}) is listed in {EXPECTED_FILE} but no test for it passed")
    for category, number in sorted(set(by_pair) - listed):
        problems.append(f"CWE-{number} ({category}) is tagged on a test but not listed in {EXPECTED_FILE}")
    return problems


# In plain English: the table as markdown, for the pipeline's run summary page.
def render_markdown(title, rows, problems):
    out = [f"## OWASP guardrail coverage: {title}", ""]
    if not rows:
        out.append("No guardrail tests in this repo carry an OWASP tag yet.")
    else:
        covered = sum(1 for r in rows if r["result"] == "Covered")
        out += [f"**{covered} of {len(rows)} tagged CWEs covered by passing tests.**", ""]
        out += ["| Category | CWE | Weakness | Tests | Passed | Failed | Skipped | Result |", "|---|---|---|---:|---:|---:|---:|---|"]
        for r in rows:
            category = f"{r['category']} {CATEGORY_NAMES[r['category']]}"
            out.append(f"| {category} | CWE-{r['cwe']} | {r['name']} | {r['tests']} | {r['passed']} | {r['failed']} | {r['skipped']} | {r['result']} |")
    if problems:
        out += ["", "### Coverage check failed", ""] + [f"- {p}" for p in problems]
    return "\n".join(out) + "\n"


# In plain English: the same information as plain lines for the terminal.
def render_text(rows, problems):
    lines = []
    for r in rows:
        lines.append(f"{r['category']}  CWE-{r['cwe']:<5} tests={r['tests']} passed={r['passed']} failed={r['failed']} skipped={r['skipped']}  {r['result']}")
    if not rows:
        lines.append("no test carries an OWASP tag")
    lines += [f"PROBLEM: {p}" for p in problems]
    return lines


# In plain English: the plug-in itself. pytest calls its methods as the run goes along.
class OwaspReport:
    def __init__(self, config):
        self.config = config
        self.tags = {}  # test id -> list of (category, CWE) pairs
        self.statuses = {}  # test id -> "passed", "skipped" or "failed"
        self.rows, self.problems = [], []

    def pytest_collection_modifyitems(self, items):
        for item in items:
            pairs = []
            for mark in item.iter_markers("owasp"):
                try:
                    owasp_tags.check_owasp_args(mark.args)
                except ValueError:
                    continue  # conftest.py stops the run for a malformed tag; here we just skip it
                pairs += [(mark.args[0], number) for number in mark.args[1:]]
            if pairs:
                self.tags[item.nodeid] = pairs

    def pytest_runtest_logreport(self, report):
        if report.nodeid not in self.tags:
            return
        if report.when == "call":
            outcome = report.outcome
        elif report.outcome == "passed":
            return
        else:
            outcome = "failed" if report.outcome == "failed" else "skipped"
        if outcome not in SEVERITY:
            return
        old = self.statuses.get(report.nodeid)
        if old is None or SEVERITY[outcome] > SEVERITY[old]:
            self.statuses[report.nodeid] = outcome

    def pytest_sessionfinish(self, session, exitstatus):
        enforce = os.environ.get(ENFORCE_VARIABLE) == "1"
        expected, names = [], {}
        expected_path = Path(self.config.rootpath) / EXPECTED_FILE
        if expected_path.exists():
            try:
                expected = parse_expected(expected_path.read_text(encoding="utf-8"))
            except ValueError as problem:
                self.problems.append(str(problem))
            names = {(category, number): name for category, number, name in expected}
        elif enforce:
            self.problems.append(f"{EXPECTED_FILE} is missing")
        self.rows = build_rows(self.tags, self.statuses, names)
        if enforce:
            self.problems += find_problems(expected, self.rows)
            if self.problems and session.exitstatus == pytest.ExitCode.OK:
                session.exitstatus = pytest.ExitCode.TESTS_FAILED
            summary = os.environ.get(SUMMARY_VARIABLE)
            if summary:
                with open(summary, "a", encoding="utf-8") as handle:
                    handle.write(render_markdown(Path(self.config.rootpath).name, self.rows, self.problems) + "\n")

    def pytest_terminal_summary(self, terminalreporter):
        terminalreporter.write_sep("=", "OWASP guardrail coverage")
        for line in render_text(self.rows, self.problems):
            terminalreporter.write_line(line)
