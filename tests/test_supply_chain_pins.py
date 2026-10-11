# In plain English: tests for the last links of the software supply chain: the base image under our code, the
# GitHub Actions that run our checks, the robot that proposes updates (Dependabot) and the scanner that
# looks inside the built image for known security flaws.
#
# Why it matters (OWASP A03): a name like "python:3.12-slim" or "actions/checkout@v4" is only a label, and
# whoever controls the label can change what it points to (this really happened to the Trivy GitHub Action
# in March 2026, when its version tags were rewritten to point at code that stole secrets). A digest or a
# commit number cannot be moved, so we pin to those, let Dependabot propose updates when we want them, and
# scan the finished image so flaws in the system packages under our code do not go unseen.
#
# These tests only read files, so they need no network.
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
DOCKERFILES = [path for path in (ROOT / "Dockerfile", ROOT / "ci" / "scanner" / "Dockerfile") if path.exists()]
HAS_IMAGE = (ROOT / "Dockerfile").exists()
LOCKS = list(ROOT.glob("requirements*.txt"))


def need_image():
    if not HAS_IMAGE:
        pytest.skip("this repo builds no image")


# ---------- Pinned images and pinned Actions ----------

@pytest.mark.owasp("A03", 1357)
def test_every_base_image_is_pinned_by_digest_and_keeps_a_readable_version():
    need_image()
    froms = []
    for dockerfile in DOCKERFILES:
        for line in dockerfile.read_text(encoding="utf-8").splitlines():
            if line.strip().upper().startswith("FROM "):
                froms.append((dockerfile.name, line.strip()))
    assert froms
    for name, line in froms:
        image = [part for part in line.split()[1:] if not part.startswith("--")][0]
        assert re.fullmatch(r"[A-Za-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}", image), f"{name}: {line}"
        assert ":latest@" not in image, f"{name}: {line}"


@pytest.mark.owasp("A03", 1357)
def test_every_github_action_is_pinned_to_a_commit_with_its_version_in_a_comment():
    found = 0
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        for number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
            match = re.match(r"^\s*-?\s*uses:\s*(\S+)(?:\s+#\s*(.*))?$", line)
            if not match:
                continue
            found += 1
            where = f"{workflow.name}:{number}: {line.strip()}"
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", match.group(1)), where
            assert match.group(2) and re.match(r"v\d+\.\d+\.\d+", match.group(2)), f"{where} (the version must follow in a comment)"
    assert found, "no workflow uses an action, so there was nothing to check"


# ---------- Dependabot proposes updates ----------

def dependabot():
    path = ROOT / ".github" / "dependabot.yml"
    assert path.exists(), ".github/dependabot.yml is missing"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.owasp("A03", 1104, 1329)
def test_dependabot_is_set_up_for_every_kind_of_dependency_this_repo_has():
    document = dependabot()
    assert document["version"] == 2
    entries = document["updates"]
    wanted = {("github-actions", "/")}
    if LOCKS:
        wanted.add(("pip", "/"))
    for dockerfile in DOCKERFILES:
        folder = "/" + dockerfile.parent.relative_to(ROOT).as_posix().strip(".")
        wanted.add(("docker", folder.rstrip("/") or "/"))
    have = {(entry["package-ecosystem"], entry["directory"]) for entry in entries}
    assert wanted <= have, f"missing: {sorted(wanted - have)}"


@pytest.mark.owasp("A03", 1104, 1329)
def test_dependabot_checks_often_and_is_never_switched_off_or_told_to_ignore_everything():
    for entry in dependabot()["updates"]:
        label = f"{entry['package-ecosystem']} {entry['directory']}"
        assert entry["schedule"]["interval"] in ("daily", "weekly"), label
        assert entry.get("open-pull-requests-limit", 5) > 0, label
        for rule in entry.get("ignore", []):
            assert rule.get("dependency-name") not in ("*", None), f"{label} ignores everything"
            assert "update-types" in rule or "versions" in rule, f"{label} ignores a dependency completely"


@pytest.mark.owasp("A03", 1104, 1329)
def test_every_directory_dependabot_watches_exists():
    for entry in dependabot()["updates"]:
        assert (ROOT / entry["directory"].lstrip("/")).is_dir(), entry["directory"]


# ---------- The image scan ----------

def scan_workflow():
    need_image()
    path = WORKFLOWS / "image-scan.yml"
    assert path.exists(), "the image-scan workflow is missing"
    text = path.read_text(encoding="utf-8")
    return text, yaml.safe_load(text)


def run_steps(document):
    return [step for job in document["jobs"].values() for step in job["steps"] if "run" in step]


@pytest.mark.owasp("A03", 1035, 1395)
def test_the_image_is_scanned_on_every_pull_request_on_main_and_every_week():
    _, document = scan_workflow()
    triggers = document.get(True) or document.get("on")
    assert {"pull_request", "push", "schedule"} <= set(triggers), triggers
    assert triggers["schedule"] and all(len(entry["cron"].split()) == 5 for entry in triggers["schedule"])


@pytest.mark.owasp("A03", 1035, 1395)
def test_the_scan_looks_inside_the_image_we_build_and_fails_on_fixable_high_flaws():
    _, document = scan_workflow()
    runs = [step["run"] for step in run_steps(document)]
    assert any(run.strip().startswith("docker build") and "-t service-under-scan:ci" in run and run.strip().endswith(" .") for run in runs), "the workflow does not build this repo's image"
    assert any("docker build" in run and "ci/scanner" in run for run in runs), "the workflow does not build the pinned scanner"
    scans = [run for run in runs if "docker:service-under-scan:ci" in run]
    assert len(scans) == 1, scans
    scan = scans[0]
    assert "--fail-on high" in scan, scan
    assert "--only-fixed" in scan, scan  # fail only on flaws somebody has already fixed upstream
    assert "/var/run/docker.sock" in scan and "image-scanner:ci" in scan


@pytest.mark.owasp("A03", 1035, 1395)
def test_the_scan_can_never_pass_by_doing_nothing_or_failing_quietly():
    text, document = scan_workflow()
    for forbidden in ("continue-on-error", "|| true", "||true", "set +e", "--fail-on none"):
        assert forbidden not in text, forbidden
    for job in document["jobs"].values():
        assert "if" not in job
        for step in job["steps"]:
            assert "if" not in step or step["name"].startswith("Prove the scanner"), step
    assert run_steps(document)


@pytest.mark.owasp("A03", 1035, 1395)
def test_a_canary_proves_the_scanner_still_catches_a_known_flaw():
    # A scanner whose flaw database is out of date keeps exiting with success while missing new flaws.
    # So every run first scans a tiny list that names a known-vulnerable library and must see it fail.
    text, document = scan_workflow()
    canary = [step for step in run_steps(document) if "sbom:/canary/sbom.json" in step["run"]]
    assert len(canary) == 1
    command = canary[0]["run"]
    assert "--fail-on high" in command and "exit 1" in command
    # Grype exits with 2 when it finds a flaw at the chosen level; any other code means the scanner is broken.
    assert "|| status=$?" in command and '"$status" -ne 2' in command
    sbom = (ROOT / "ci" / "canary" / "sbom.json").read_text(encoding="utf-8")
    assert "pkg:pypi/urllib3@1.26.4" in sbom


@pytest.mark.owasp("A03", 1035, 1395)
def test_the_scanner_is_a_pinned_image_that_dependabot_keeps_current():
    need_image()
    scanner = (ROOT / "ci" / "scanner" / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^FROM anchore/grype:v\d+\.\d+\.\d+@sha256:[0-9a-f]{64}\s*$", scanner, re.M), scanner
    assert ("docker", "/ci/scanner") in {(entry["package-ecosystem"], entry["directory"]) for entry in dependabot()["updates"]}


@pytest.mark.owasp("A03", 1035, 1395)
def test_every_exception_to_the_scan_names_one_flaw_and_gives_a_reason_and_a_date():
    need_image()
    config = ROOT / ".grype.yaml"
    assert config.exists(), ".grype.yaml is missing"
    lines = config.read_text(encoding="utf-8").splitlines()
    document = yaml.safe_load("\n".join(lines)) or {}
    ignores = document.get("ignore") or []
    for index, line in enumerate(lines):
        if re.match(r"^\s*-\s*vulnerability:", line):
            above = " ".join(lines[max(0, index - 3):index])
            assert re.search(r"\d{4}-\d{2}-\d{2}", above) and "#" in above, f"exception without a dated reason: {line.strip()}"
    for rule in ignores:
        assert re.fullmatch(r"(CVE-\d{4}-\d{4,}|GHSA(-[a-z0-9]{4}){3}|DSA-[\w-]+)", str(rule.get("vulnerability", ""))), rule
        assert set(rule) <= {"vulnerability", "package", "fix-state"}, rule
