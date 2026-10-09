# In plain English: these tests run the real service against a real Postgres
# database, so they check the parts the other tests cannot: saving, listing and
# searching for real, and that the service's limited login really cannot change
# or delete anything.
#
# SAFETY: the service's login cannot delete, so these tests cannot clean up after
# themselves. Every test adds rows with a brand new random assignment ID and
# leaves them behind. That is fine for a throwaway database and a disaster for a
# real one. So the tests refuse to run unless the database is named
# "assessment_test". The pipeline creates a fresh one for every run and throws it
# away afterwards. To run these on your own computer, start a temporary Postgres
# container yourself (see the README) and point the DB_* settings at it.
import os
import random
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient

from app.db import connect
from app.embeddings import embed_text
from app.examples import _vector_text
from app.main import app

client = TestClient(app)


# In plain English: runs before every test in this file. With no database
# settings at all, the tests quietly skip, so a normal run on your laptop still
# works. In the pipeline REQUIRE_DB=1 is set, and then a missing database is a
# failure, because a test that silently skips proves nothing. If the settings
# point at any database other than "assessment_test", it refuses to run.
@pytest.fixture(autouse=True)
def require_test_database():
    if not os.environ.get("DB_HOST"):
        if os.environ.get("REQUIRE_DB") == "1":
            pytest.fail("REQUIRE_DB is set but no database settings were given")
        pytest.skip("no test database configured")
    if os.environ.get("DB_NAME") != "assessment_test":
        pytest.fail("refusing to run: DB_NAME must be 'assessment_test', never a real database")


# In plain English: saves one example through the real web address and returns
# its ID. It also checks the save worked.
def save(assignment_id, student_work, grade="A", reasoning="Correct."):
    response = client.post(
        "/examples",
        json={
            "assignment_id": assignment_id,
            "student_work": student_work,
            "grade": grade,
            "reasoning": reasoning,
        },
    )
    assert response.status_code == 201
    return response.json()["example_id"]


# In plain English: a brand new assignment ID, so one test's rows never mix
# with another test's.
def new_assignment():
    return str(uuid.uuid4())


# In plain English: with the right password the service says it is ready.
def test_ready_with_a_working_login():
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"ok": True}


# In plain English: the ready check must be able to fail. With a wrong password
# it must answer 503 and say nothing about why. The test first proves the right
# password works, so a 503 can only be caused by the wrong password and not by a
# database that was never reachable at all.
def test_ready_fails_quietly_with_a_wrong_password(monkeypatch):
    assert client.get("/ready").status_code == 200
    monkeypatch.setenv("DB_PASSWORD", "not-the-password")
    response = client.get("/ready")
    assert response.status_code == 503
    assert response.json() == {"ok": False}


# In plain English: a saved example is really in the database, with its 384
# meaning numbers.
def test_save_stores_a_384_number_embedding():
    example_id = save(new_assignment(), "The mitochondria makes energy for the cell.")
    with connect() as connection:
        row = connection.execute(
            "SELECT vector_dims(embedding) FROM examples WHERE example_id = %s",
            (uuid.UUID(example_id),),
        ).fetchone()
    assert row[0] == 384


# In plain English: listing returns what was saved, leaves out the numbers, and
# returns nothing for a different assignment.
def test_list_returns_saved_examples_only_for_that_assignment():
    assignment = new_assignment()
    example_id = save(assignment, "Plants make food from sunlight.", "B")
    listed = client.get("/examples", params={"assignment_id": assignment}).json()
    assert [item["example_id"] for item in listed] == [example_id]
    assert "embedding" not in listed[0]
    other = client.get("/examples", params={"assignment_id": new_assignment()}).json()
    assert other == []


# In plain English: the point of the whole service. A question about cells and
# energy must find the mitochondria example before the sunlight one.
def test_search_ranks_the_closest_meaning_first():
    assignment = new_assignment()
    mitochondria = save(assignment, "The mitochondria makes energy for the cell.", "A")
    sunlight = save(assignment, "Plants make food from sunlight.", "B")
    results = client.post(
        "/examples/search",
        json={"assignment_id": assignment, "query_text": "cells produce energy"},
    ).json()
    assert [item["example_id"] for item in results] == [mitochondria, sunlight]
    assert results[0]["similarity"] > results[1]["similarity"]


# In plain English: when an assignment has its own examples, search stays inside it.
# Two assignments hold near identical text, and a search in one must never return the
# other's example. (An assignment with NO examples is different: it falls back to the
# others, and the tests at the end of this file cover that.)
def test_search_never_returns_another_assignments_examples():
    first = new_assignment()
    second = new_assignment()
    mine = save(first, "The mitochondria makes energy for the cell.")
    theirs = save(second, "The mitochondria makes energy for the cell.")
    results = client.post(
        "/examples/search",
        json={"assignment_id": first, "query_text": "cells produce energy"},
    ).json()
    assert [item["example_id"] for item in results] == [mine]
    assert theirs not in [item["example_id"] for item in results]


# In plain English: the service's login can read and add but can never change or
# remove an example. First it proves the test really is running as that limited
# login and that reading works, so the refusals below mean "not allowed" and not
# "login missing". Then it tries to change and to delete, and both must be
# refused, and the example must still be intact.
def test_service_login_cannot_update_or_delete():
    assignment = new_assignment()
    save(assignment, "The mitochondria makes energy for the cell.", "A")
    assignment_uuid = uuid.UUID(assignment)

    with connect() as connection:
        who = connection.execute("SELECT current_user").fetchone()[0]
        count = connection.execute(
            "SELECT count(*) FROM examples WHERE assignment_id = %s", (assignment_uuid,)
        ).fetchone()[0]
    assert who == "assessment_app"
    assert count == 1

    for statement in (
        "DELETE FROM examples WHERE assignment_id = %s",
        "UPDATE examples SET grade = 'F' WHERE assignment_id = %s",
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with connect() as connection:
                connection.execute(statement, (assignment_uuid,))

    listed = client.get("/examples", params={"assignment_id": assignment}).json()
    assert len(listed) == 1
    assert listed[0]["grade"] == "A"


# In plain English: why search needs pgvector's "keep looking" mode. The search
# index (HNSW) only looks at about 40 candidates across ALL assignments and filters
# afterwards. So a small assignment surrounded by many closer rows from another
# assignment comes back empty. This test builds exactly that situation: 60 close
# rows in one assignment and one far row in another. The ordinary assignment index
# would normally rescue the query, so the filter is written in a way that index
# cannot be used, which leaves the HNSW index as the only fast path. It checks the
# plan really uses the HNSW index, shows that WITHOUT iterative scan the small
# assignment is lost, and that WITH it the row is found.
def test_filtered_index_search_needs_iterative_scan_to_find_a_small_assignment():
    crowded = new_assignment()
    small = new_assignment()
    close_vector = _vector_text(embed_text("cells produce energy"))
    far_vector = _vector_text(embed_text("Plants make food from sunlight."))
    insert = (
        "INSERT INTO examples (assignment_id, student_work, grade, reasoning, embedding) "
        "VALUES (%s, %s, 'A', 'r', %s::vector)"
    )
    # 60 close rows, each nudged by a tiny different amount. Identical copies make
    # the index build a strange graph, so every row gets its own small difference.
    close_numbers = embed_text("cells produce energy")
    noise = random.Random(1234)
    with connect() as connection:
        for _ in range(60):
            nudged = [number + noise.uniform(-0.01, 0.01) for number in close_numbers]
            connection.execute(insert, (uuid.UUID(crowded), "close", _vector_text(nudged)))
        connection.execute(insert, (uuid.UUID(small), "far", far_vector))

    query = (
        "SELECT example_id FROM examples "
        f"WHERE assignment_id::text = '{small}' "
        f"ORDER BY embedding <=> '{close_vector}'::vector LIMIT 3"
    )

    def run(iterative):
        with connect() as connection:
            connection.execute("SET LOCAL enable_seqscan = off")
            # Look at only 10 candidates instead of the usual 40, so the effect
            # shows up reliably with just 60 close rows.
            connection.execute("SET LOCAL hnsw.ef_search = 10")
            if iterative:
                connection.execute("SET LOCAL hnsw.iterative_scan = strict_order")
            plan = "\n".join(row[0] for row in connection.execute("EXPLAIN " + query).fetchall())
            rows = connection.execute(query).fetchall()
        return plan, rows

    plan, rows = run(iterative=False)
    assert "examples_embedding_idx" in plan
    assert rows == []

    plan, rows = run(iterative=True)
    assert "examples_embedding_idx" in plan
    assert len(rows) == 1


# In plain English: the tests below cover the fallback: what a search does when the
# assignment asked about has no examples of its own. That search looks across EVERY
# example in the database, including the ones other tests saved. So the history and
# geography topics are used by only one test each, and the checks look at the example's
# text and flags, not its id, which keeps them reliable on a database that still holds
# rows from earlier runs.
def search(assignment_id, query_text, limit=None, fallback=False):
    body = {"assignment_id": assignment_id, "query_text": query_text}
    if limit is not None:
        body["limit"] = limit
    if fallback:
        body["fallback_to_all"] = True
    return client.post("/examples/search", json=body).json()


# In plain English: the cold-start case. History 102 is brand new and has no examples,
# but History 101 has one. A reworded question about the French Revolution must still
# find History 101's example, say it came from elsewhere, and score it high. For
# reference the real model scores this pair at about 0.91, and about 0.40 against
# unrelated biology.
def test_new_assignment_borrows_examples_from_another_assignment():
    history_101 = new_assignment()
    history_102 = new_assignment()
    save(history_101, "The French Revolution began in 1789.", "A")

    results = search(history_102, "When did the French Revolution start?", fallback=True)

    assert results[0]["student_work"] == "The French Revolution began in 1789."
    assert results[0]["same_assignment"] is False
    assert results[0]["assignment_id"] != history_102
    assert results[0]["similarity"] > 0.8
    assert all(item["same_assignment"] is False for item in results)


# In plain English: the old rule. Biology 101 holds the BETTER match for the question
# (score about 0.88). Biology 102 holds its own, weaker example (about 0.69). Because
# Biology 102 has an example of its own, only that one may come back, flagged true, and
# Biology 101's better match must be ignored.
def test_assignment_with_its_own_examples_ignores_better_matches_elsewhere():
    biology_101 = new_assignment()
    biology_102 = new_assignment()
    save(biology_101, "The mitochondria makes energy for the cell.", "A")
    own = save(biology_102, "Plants make food from sunlight.", "B")

    results = search(biology_102, "cells produce energy", fallback=True)

    assert [item["example_id"] for item in results] == [own]
    assert results[0]["same_assignment"] is True
    assert results[0]["assignment_id"] == biology_102
    assert results[0]["similarity"] < 0.8


# In plain English: the fallback respects the limit and ranks best first. Geography 101
# holds three river examples and Geography 102 holds none. Asking for 2 about the
# longest river in Africa must return exactly 2, with the Nile example first (about
# 0.90, against about 0.63 for the Amazon one), all flagged false.
def test_fallback_respects_the_limit_and_ranks_best_first():
    geography_101 = new_assignment()
    geography_102 = new_assignment()
    save(geography_101, "The Nile is the longest river in Africa.", "A")
    save(geography_101, "The Amazon carries more water than any other river.", "B")
    save(geography_101, "Rivers flow downhill toward the sea.", "C")

    results = search(geography_102, "Which river is the longest in Africa?", limit=2, fallback=True)

    assert len(results) == 2
    assert results[0]["student_work"] == "The Nile is the longest river in Africa."
    assert results[0]["similarity"] > 0.8
    assert results[0]["similarity"] >= results[1]["similarity"]
    assert all(item["same_assignment"] is False for item in results)


# In plain English: the wall, tested for real. An assignment ID the service has never seen
# must get NOTHING back unless the caller explicitly asks to borrow, even though another
# assignment holds a perfect match. With the flag on, the same search borrows it and
# says so.
def test_unknown_assignment_gets_nothing_unless_the_caller_asks_to_borrow():
    other = new_assignment()
    unknown = new_assignment()
    save(other, "The Magna Carta was signed in 1215.", "A")

    without_flag = search(unknown, "When was the Magna Carta signed?")
    with_flag = search(unknown, "When was the Magna Carta signed?", fallback=True)

    assert without_flag == []
    assert with_flag[0]["student_work"] == "The Magna Carta was signed in 1215."
    assert with_flag[0]["same_assignment"] is False
