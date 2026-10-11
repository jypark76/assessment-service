# In plain English: docs/design-rules.md is the written list of the secure-design rules this service follows, each
# with the test that proves it. This test keeps that list honest: every rule must name a test that really exists in
# this repo, and the list may not shrink below the agreed size without someone noticing. If a test is renamed or
# deleted, the rule loses its proof and this goes red, so the page can never claim a rule the tests no longer prove.
#
# Why it matters (OWASP A06, insecure design): CWE-657, violation of secure design principles. A design principle
# only counts if something checks it.
import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "design-rules.md"
MINIMUM_RULES = 17
TEST_REFERENCE = re.compile(r"`(tests/[a-z0-9_]+\.py)::([A-Za-z0-9_]+)`")


# In plain English: reads the page text and returns (rule row, file, test name) for every rule row, plus a list of
# plain sentences, one per problem found.
def check_rules(text, root):
    rows = [line for line in text.splitlines() if line.startswith("|") and not line.startswith("|---") and "Rule" not in line.split("|")[1]]
    problems, references = [], []
    if len(rows) < MINIMUM_RULES:
        problems.append(f"only {len(rows)} rules are listed; at least {MINIMUM_RULES} are required")
    seen = set()
    for row in rows:
        rule = row.split("|")[1].strip()
        match = TEST_REFERENCE.search(row)
        if not match:
            problems.append(f"rule '{rule}' names no test")
            continue
        file_name, test_name = match.groups()
        references.append((rule, file_name, test_name))
        if rule in seen:
            problems.append(f"rule '{rule}' is listed twice")
        seen.add(rule)
        path = root / file_name
        if not path.exists():
            problems.append(f"rule '{rule}': the file {file_name} does not exist")
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        if test_name not in names:
            problems.append(f"rule '{rule}': {file_name} has no test called {test_name}")
    return problems, references


@pytest.mark.owasp("A06", 657)
def test_every_design_rule_names_a_test_that_exists():
    assert DOC.exists(), "docs/design-rules.md is missing"
    problems, references = check_rules(DOC.read_text(encoding="utf-8"), ROOT)
    assert problems == [], "\n".join(problems)
    assert len(references) >= MINIMUM_RULES


@pytest.mark.owasp("A06", 657)
def test_the_rules_cover_the_agreed_principles():
    text = DOC.read_text(encoding="utf-8").lower()
    for principle in ("deny by default", "fail closed", "least privilege", "identity from the key alone", "no default secrets", "secrets as files", "validate at every boundary", "reveal nothing", "internal only", "hardened pods", "pinned supply chain", "pinned images", "reviewed cryptography", "no dangerous functions", "checked calls", "settings fixed at deploy", "no uploads"):
        assert principle in text, principle


@pytest.mark.owasp("A06", 657)
def test_the_check_really_finds_a_missing_test(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("def test_real():\n    pass\n", encoding="utf-8")
    header = "| Rule | Meaning | Test |\n|---|---|---|\n"
    rows = lambda count, test="`tests/test_a.py::test_real`": "".join(f"| rule {i} | x | {test} |\n" for i in range(count))
    assert check_rules(header + rows(MINIMUM_RULES), tmp_path)[0] == []
    assert check_rules(header + rows(MINIMUM_RULES - 1), tmp_path)[0], "too few rules not caught"
    assert check_rules(header + rows(MINIMUM_RULES, "`tests/test_a.py::test_gone`"), tmp_path)[0], "missing test not caught"
    assert check_rules(header + rows(MINIMUM_RULES, "`tests/test_b.py::test_real`"), tmp_path)[0], "missing file not caught"
    assert check_rules(header + rows(MINIMUM_RULES, "no test written here"), tmp_path)[0], "no test named not caught"
    assert check_rules(header + rows(MINIMUM_RULES) + rows(1), tmp_path)[0], "a duplicate rule not caught"
