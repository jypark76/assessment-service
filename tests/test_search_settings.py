# In plain English: these tests check HOW the search talks to the database, without
# needing a database. A recording stand-in for the connection captures every
# statement the search sends, in order, and hands back the answers we script for it.
#
# What they pin down:
#   - the search switches on pgvector's "keep looking" mode (iterative scan) first;
#   - it then asks one quick question: "does this assignment have any examples?";
#   - if yes, the search stays INSIDE that assignment;
#   - if no, the search looks across ALL assignments (the cold-start fallback);
#   - every result says which assignment it came from and whether that is the same
#     assignment that was asked about (the same_assignment flag).
import uuid

import app.examples as examples
from app.examples import SearchRequest, search_examples


# In plain English: a pretend database connection. "has_examples" is the answer it
# gives to the "does this assignment have any examples?" question. "rows" is what it
# hands back for the actual search. Both are scripted by each test.
class RecordingConnection:
    def __init__(self, has_examples=True, rows=None):
        self.statements = []
        self.has_examples = has_examples
        self.rows = rows or []
        self._answer = []

    def __enter__(self):
        return self

    def __exit__(self, *details):
        return False

    def execute(self, sql, params=None):
        self.statements.append(sql)
        if "EXISTS" in sql:
            self._answer = [(self.has_examples,)]
        else:
            self._answer = self.rows
        return self

    def fetchone(self):
        return self._answer[0] if self._answer else None

    def fetchall(self):
        return self._answer


# In plain English: sets up the pretend connection and a pretend embedding, runs one
# search for a random assignment, and gives back what the search returned and what
# the recorder saw.
def run_search(monkeypatch, has_examples=True, rows=None, fallback=False):
    recorder = RecordingConnection(has_examples=has_examples, rows=rows)
    monkeypatch.setattr(examples, "connect", lambda: recorder)
    monkeypatch.setattr(examples, "embed_text", lambda text: [0.0] * 384)
    request = {"assignment_id": uuid.uuid4(), "query_text": "cells produce energy"}
    if fallback:
        request["fallback_to_all"] = True
    results = search_examples(SearchRequest(**request))
    return results, recorder


# In plain English: one fake search result row, in the order the search selects its
# columns: example id, assignment id, student work, grade, reasoning, similarity.
def fake_row(assignment_id):
    return (uuid.uuid4(), assignment_id, "The mitochondria makes energy.", "A", "Clear.", 0.8123)


def test_search_turns_on_iterative_scan_before_it_queries(monkeypatch):
    _, recorder = run_search(monkeypatch)

    assert recorder.statements[0] == "SET LOCAL hnsw.iterative_scan = strict_order"
    assert recorder.statements[1].lstrip().startswith("SELECT")


# In plain English: before searching, the service must ask whether the assignment
# has any examples at all. That question decides which search runs.
def test_search_first_asks_whether_the_assignment_has_examples(monkeypatch):
    _, recorder = run_search(monkeypatch)

    assert "EXISTS" in recorder.statements[1]


# In plain English: when the assignment has examples, the search stays inside it.
def test_search_stays_inside_the_assignment_when_it_has_examples(monkeypatch):
    _, recorder = run_search(monkeypatch, has_examples=True)

    final_search = recorder.statements[-1]
    assert "WHERE assignment_id" in final_search
    assert len(recorder.statements) == 3


# In plain English: when the assignment has none, the search must NOT be limited to
# it, so a brand-new assignment still gets examples from the others.
def test_search_looks_across_all_assignments_when_it_has_none_and_the_caller_asks(monkeypatch):
    _, recorder = run_search(monkeypatch, has_examples=False, fallback=True)

    final_search = recorder.statements[-1]
    assert "WHERE assignment_id" not in final_search
    assert "ORDER BY embedding" in final_search
    assert len(recorder.statements) == 3


# In plain English: every result names its own assignment and says whether it is the
# assignment that was asked about. Examples found inside the assignment are flagged
# true.
def test_results_from_inside_the_assignment_are_flagged_true(monkeypatch):
    results, _ = run_search(monkeypatch, has_examples=True, rows=[fake_row(uuid.uuid4())])

    assert results[0]["same_assignment"] is True
    assert "assignment_id" in results[0]


# In plain English: examples borrowed from other assignments are flagged false, so the
# grader can say "this came from a different assignment".
def test_results_from_other_assignments_are_flagged_false(monkeypatch):
    other = uuid.uuid4()
    results, _ = run_search(monkeypatch, has_examples=False, rows=[fake_row(other)], fallback=True)

    assert results[0]["same_assignment"] is False
    assert results[0]["assignment_id"] == str(other)


# In plain English: the wall. An assignment the service has never seen (a typo, a made-up
# ID, or a real new assignment whose caller did not ask to borrow) must get NOTHING back,
# even if other assignments hold examples. The pretend database is scripted to hand back
# a row if a search ran, so an empty answer proves no search ran at all: only the setting
# and the "does it have examples?" question were sent.
def test_search_returns_nothing_for_an_assignment_with_no_examples_unless_asked(monkeypatch):
    results, recorder = run_search(
        monkeypatch, has_examples=False, rows=[fake_row(uuid.uuid4())], fallback=False
    )

    assert results == []
    assert len(recorder.statements) == 2


# In plain English: asking to borrow never overrides an assignment's own examples. With
# the flag on and examples of its own, the search still stays inside the assignment.
def test_asking_to_borrow_does_not_override_the_assignments_own_examples(monkeypatch):
    _, recorder = run_search(monkeypatch, has_examples=True, fallback=True)

    assert "WHERE assignment_id" in recorder.statements[-1]
