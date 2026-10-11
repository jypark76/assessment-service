# In plain English: tests that the outside libraries are locked and checked. Every library the service
# (and its tests, and the scanner) installs must be pinned to one exact version AND one exact set of file
# hashes, nothing may be installed any other way, and a scanner must check those exact versions against
# the public list of known security problems on every pull request and once a week.
#
# Why it matters (OWASP A03, software supply chain): a library can be swapped on the download site, a
# look-alike name can be slipped in, or a safe version can later be found to have a known flaw. A hash
# makes the install fail if even one byte differs from what we locked (CWE-1357 relying on a component
# that cannot be trusted), and the scanner catches known flaws (CWE-1035 and CWE-1395 depending on
# components with known vulnerabilities). These tests read files only, so they need no network.
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
LOCKS = [name for name in ("requirements.txt", "requirements-dev.txt", "requirements-audit.txt") if (ROOT / name).exists()]
INPUTS = {lock: lock.replace(".txt", ".in") for lock in LOCKS}

HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}")
PIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,._-]+\])?==[A-Za-z0-9.!+_-]+( ;.*)?$")


# In plain English: reads a requirements file and returns its real entries as (text before the hashes,
# the list of hashes), joining the lines that end in a backslash and dropping comments and blank lines.
def read_entries(path):
    entries, pending = [], ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pending += " " + line.rstrip("\\").strip() if pending else line.rstrip("\\").strip()
        if not line.endswith("\\"):
            entries.append(pending.strip())
            pending = ""
    assert not pending, f"{path.name} ends in the middle of an entry"
    return entries


# In plain English: splits one joined entry into its requirement text and its hashes.
def split_entry(entry):
    hashes = HASH.findall(entry)
    requirement = HASH.sub("", entry).strip()
    return requirement, hashes


def name_of(requirement):
    return re.split(r"[\[=<>!~; ]", requirement, maxsplit=1)[0].lower().replace("_", "-").replace(".", "-")


def test_there_is_a_lock_file_to_check():
    assert LOCKS, "no requirements lock file was found"
    assert "requirements-dev.txt" in LOCKS and "requirements-audit.txt" in LOCKS


@pytest.mark.owasp("A03", 1357)
@pytest.mark.parametrize("lock", LOCKS)
def test_every_library_in_a_lock_is_pinned_exactly_and_has_hashes(lock):
    entries = read_entries(ROOT / lock)
    assert entries, f"{lock} is empty"
    for entry in entries:
        requirement, hashes = split_entry(entry)
        assert PIN.match(requirement), f"{lock}: '{requirement}' is not pinned to one exact version with =="
        assert hashes, f"{lock}: '{requirement}' has no hash"
        assert len(set(hashes)) == len(hashes), f"{lock}: '{requirement}' repeats a hash"


@pytest.mark.owasp("A03", 1357)
@pytest.mark.parametrize("lock", LOCKS)
def test_a_lock_cannot_pull_from_anywhere_else(lock):
    # No other download site, no links to files or repositories, no editable installs, no stray options.
    for entry in read_entries(ROOT / lock):
        assert not entry.startswith("-"), f"{lock}: option line '{entry[:60]}'"
        requirement = split_entry(entry)[0]
        for forbidden in ("://", " @ ", "git+", "file:", "index-url", "find-links"):
            assert forbidden not in requirement, f"{lock}: '{requirement}'"


@pytest.mark.owasp("A03", 1357)
@pytest.mark.parametrize("lock", LOCKS)
def test_every_library_asked_for_is_in_the_lock_and_the_lock_has_nothing_unexplained(lock):
    asked = set()
    for entry in read_entries(ROOT / INPUTS[lock]):
        if entry.startswith("-"):
            continue  # -r and -c lines point at other files
        asked.add(name_of(entry))
    locked = {name_of(split_entry(entry)[0]) for entry in read_entries(ROOT / lock)}
    assert asked, f"{INPUTS[lock]} asks for nothing"
    assert asked <= locked, f"missing from {lock}: {sorted(asked - locked)}"


@pytest.mark.owasp("A03", 1357)
@pytest.mark.parametrize("lock", LOCKS)
def test_pip_itself_is_pinned_with_the_libraries(lock):
    assert "pip" in {name_of(split_entry(e)[0]) for e in read_entries(ROOT / lock)}


@pytest.mark.owasp("A03", 1357)
def test_the_test_libraries_use_the_same_versions_as_the_service():
    if "requirements.txt" not in LOCKS:
        pytest.skip("this repo has no service lock")
    service = {name_of(split_entry(e)[0]): split_entry(e)[0] for e in read_entries(ROOT / "requirements.txt")}
    dev = {name_of(split_entry(e)[0]): split_entry(e)[0] for e in read_entries(ROOT / "requirements-dev.txt")}
    for name, requirement in service.items():
        assert dev.get(name) == requirement, (name, requirement, dev.get(name))


# ---------- Every install uses the lock and checks the hashes ----------

def install_commands(text):
    # Every "pip install ..." command in a file, with a trailing backslash-joined continuation folded in.
    joined = re.sub(r"\\\r?\n\s*", " ", text)
    return [m.group(0) for m in re.finditer(r"pip install[^\n]*", joined)]


@pytest.mark.owasp("A03", 1357)
def test_the_dockerfile_installs_only_from_the_lock_with_hashes_checked():
    dockerfile = ROOT / "Dockerfile"
    if not dockerfile.exists():
        pytest.skip("this repo builds no image")
    commands = install_commands(dockerfile.read_text(encoding="utf-8"))
    assert commands, "the Dockerfile installs nothing"
    for command in commands:
        assert "--require-hashes" in command, command
        assert "--no-deps" in command, command
        assert re.search(r"-r requirements\.txt\b", command), command


@pytest.mark.owasp("A03", 1357)
def test_every_install_in_every_workflow_checks_the_hashes_of_a_lock():
    found = 0
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        for command in install_commands(workflow.read_text(encoding="utf-8")):
            found += 1
            assert "--require-hashes" in command, f"{workflow.name}: {command}"
            assert re.search(r"-r requirements[a-z-]*\.txt\b", command), f"{workflow.name}: {command}"
    assert found, "no workflow installs anything, so the check found nothing to look at"


# ---------- The scanner ----------

def audit_workflow():
    path = WORKFLOWS / "dependency-audit.yml"
    assert path.exists(), "the dependency-audit workflow is missing"
    return path.read_text(encoding="utf-8"), yaml.safe_load(path.read_text(encoding="utf-8"))


def audit_commands(document):
    commands = []
    for job in document["jobs"].values():
        for step in job["steps"]:
            if "pip-audit" in step.get("run", ""):
                commands.append(step["run"].strip())
    return commands


@pytest.mark.owasp("A03", 1035, 1395)
def test_the_audit_runs_on_every_pull_request_on_main_and_every_week():
    _, document = audit_workflow()
    triggers = document.get(True) or document.get("on")  # YAML reads a bare "on" as True
    assert {"pull_request", "push", "schedule"} <= set(triggers), triggers
    crons = [entry["cron"] for entry in triggers["schedule"]]
    assert crons and all(len(cron.split()) == 5 for cron in crons)


@pytest.mark.owasp("A03", 1035, 1395)
def test_the_audit_checks_every_lock_file_with_the_strict_flags():
    _, document = audit_workflow()
    commands = audit_commands(document)
    audited = set()
    for command in commands:
        assert command.startswith("pip-audit "), command
        for flag in ("--require-hashes", "--disable-pip", "--strict"):
            assert flag in command, (flag, command)
        audited.update(re.findall(r"-r (\S+)", command))
    assert audited == set(LOCKS), f"audited {sorted(audited)} but the locks are {sorted(LOCKS)}"


@pytest.mark.owasp("A03", 1035, 1395)
def test_the_audit_can_never_pass_by_doing_nothing_or_failing_quietly():
    text, document = audit_workflow()
    assert "continue-on-error" not in text
    assert "|| true" not in text and "||true" not in text
    assert "set +e" not in text
    for job in document["jobs"].values():
        assert "if" not in job and "continue-on-error" not in job
        for step in job["steps"]:
            assert "if" not in step, step  # no step may be switched off by a condition
            assert "continue-on-error" not in step
    assert audit_commands(document), "the workflow runs no pip-audit command"


@pytest.mark.owasp("A03", 1035, 1395)
def test_the_scanner_itself_is_installed_from_its_own_locked_list():
    _, document = audit_workflow()
    runs = [step.get("run", "") for job in document["jobs"].values() for step in job["steps"]]
    installs = [run for run in runs if "pip install" in run]
    assert installs and all("--require-hashes" in run and "-r requirements-audit.txt" in run for run in installs), installs
    audit = read_entries(ROOT / "requirements-audit.txt")
    assert "pip-audit" in {name_of(split_entry(e)[0]) for e in audit}
