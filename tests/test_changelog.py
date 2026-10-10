# In plain English: these tests check the list of database changes (the Liquibase
# "changelog" in db/changelog) BEFORE anything runs. Each change is a small SQL file,
# and one root file lists them in order. Liquibase only runs what the root file
# lists, so a change file that is missing from the list would silently never run.
# These tests need no database and no Docker.
import re
from pathlib import Path

import yaml

CHANGELOG = Path(__file__).resolve().parent.parent / "db" / "changelog"
ROOT_FILE = CHANGELOG / "changelog-root.yaml"


# In plain English: the SQL change files, in the order their numbers say.
def migration_files():
    return sorted(CHANGELOG.glob("*.sql"))


# In plain English: the files the root changelog lists, in the order it lists them.
def listed_files():
    root = yaml.safe_load(ROOT_FILE.read_text(encoding="utf-8"))
    return [entry["include"]["file"] for entry in root["databaseChangeLog"]]


# In plain English: every change file must be on the root list, and in number order.
# A file missing from the list would never run anywhere, and nothing would complain.
# This is the same mistake as a test-file list that goes stale.
def test_the_root_changelog_lists_every_migration_in_order():
    on_disk = [path.name for path in migration_files()]
    assert on_disk, "there are no migration files at all"
    assert listed_files() == on_disk


# In plain English: each change file must be in Liquibase's SQL format: the first
# line says so, and each change has an author and an ID. IDs must be unique, and the
# ID must start with the file's own number, so a file and its change cannot drift apart.
def test_every_migration_is_a_well_formed_liquibase_file():
    assert migration_files(), "there are no migration files to check"
    seen = set()
    for path in migration_files():
        text = path.read_text(encoding="utf-8")
        assert text.startswith("--liquibase formatted sql"), path.name
        ids = re.findall(r"^--changeset\s+\S+:(\S+)", text, flags=re.MULTILINE)
        assert ids, f"{path.name} has no changeset"
        for change_id in ids:
            assert change_id not in seen, f"duplicate change id {change_id}"
            seen.add(change_id)
            assert change_id.startswith(path.name.split("-")[0]), (path.name, change_id)


# In plain English: change 0001 must really do what this step promises: create the table
# that records which approved submissions have been sent on, make the submission ID its
# key (so one submission is recorded once), and give the service's login only the right
# to read and add rows, never to change or delete them.
def test_migration_0001_creates_the_sent_table_with_insert_and_select_only():
    text = (CHANGELOG / "0001-add-approval-sends.sql").read_text(encoding="utf-8")
    assert "CREATE TABLE approval_sends" in text
    assert "submission_id" in text and "PRIMARY KEY" in text
    assert "GRANT SELECT, INSERT ON approval_sends TO assessment_app" in text
    assert "UPDATE" not in text.replace("-- ", "").split("GRANT")[1]
    assert "DELETE" not in text.split("GRANT")[1]


# In plain English: the repo is public, so the change files must never hold a
# password. The migration job gets the admin password from the Kubernetes Secret.
def test_the_changelog_holds_no_passwords():
    for path in CHANGELOG.iterdir():
        assert "password" not in path.read_text(encoding="utf-8").lower(), path.name


# In plain English: change 0002 must create the table that records which grading jobs have
# been sent. A job is the submission AND its version, so both are in the key, and the service
# login may only read and add rows.
def test_migration_0002_creates_the_job_table_keyed_by_submission_and_version():
    text = (CHANGELOG / "0002-add-grading-job-sends.sql").read_text(encoding="utf-8")
    assert "CREATE TABLE grading_job_sends" in text
    assert "PRIMARY KEY (submission_id, version)" in text
    assert "GRANT SELECT, INSERT ON grading_job_sends TO assessment_app" in text
    assert "UPDATE" not in text.split("GRANT")[1]
    assert "DELETE" not in text.split("GRANT")[1]
