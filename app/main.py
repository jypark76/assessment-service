# In plain English: this is the front door of the knowledge service. It answers
# "are you alive?" and "are you ready to work?", and it lets callers save a
# graded example, list the saved ones and find the most similar ones.
from uuid import UUID

import psycopg
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.db import database_is_ready
from app.examples import (
    NewExample,
    SearchRequest,
    list_examples,
    save_example,
    search_examples,
)

# Create the web application. The title and version show up on the automatic
# documentation page FastAPI builds at /docs.
app = FastAPI(title="Knowledge service", version="0.5.1")


# In plain English: the kinds of error whose built-in wording is safe, because it
# only describes the rule and never quotes what the caller sent. "value_error" is
# our own check for unstorable text, with fixed wording of our own.
SAFE_ERROR_KINDS = {
    "missing",
    "extra_forbidden",
    "string_too_short",
    "string_too_long",
    "greater_than_equal",
    "less_than_equal",
    "int_parsing",
    "int_type",
    "string_type",
    "value_error",
}

# In plain English: the built-in wording for a bad UUID quotes the offending
# character, so these kinds get fixed wording instead.
FIXED_REASONS = {
    "uuid_parsing": "Input should be a valid UUID",
    "uuid_type": "Input should be a valid UUID",
    "uuid_version": "Input should be a valid UUID",
}


# In plain English: picks the reason to show for one problem. Fixed wording for the
# kinds that could quote the caller, the built-in wording for the kinds known to be
# safe, and a plain "Invalid value" for anything we have not checked one by one.
def safe_reason(item):
    kind = item["type"]
    if kind in FIXED_REASONS:
        return FIXED_REASONS[kind]
    if kind in SAFE_ERROR_KINDS:
        return item["msg"]
    return "Invalid value"


# In plain English: picks the field name to show for one problem. Normally that
# is the path to the field, like "body.student_work". For an unexpected extra
# field the last part of the path is the name the CALLER chose, which is caller
# data too, so it is left off and the reply names only the place ("body").
def safe_field(item):
    parts = item["loc"]
    if item["type"] == "extra_forbidden":
        parts = parts[:-1]
    return ".".join(str(part) for part in parts)


# In plain English: when a request is turned away for bad input, FastAPI would
# normally repeat the bad value back to the caller. We don't want pieces of
# someone's data bouncing around in error messages (or ending up in logs). So
# this replaces that reply with a short one: only WHICH field was wrong and
# WHY, never what the caller typed. The status stays 422 ("bad input").
@app.exception_handler(RequestValidationError)
def bad_input(request: Request, error: RequestValidationError):
    problems = [
        {"field": safe_field(item), "reason": safe_reason(item)}
        for item in error.errors()
    ]
    return JSONResponse(status_code=422, content={"problems": problems})


# In plain English: a simple "are you alive?" check. If this address answers
# {"ok": true}, the service process is up. It does not look at the database.
# Kubernetes will later use it to decide whether to restart the service.
@app.get("/health")
def health():
    return {"ok": True}


# In plain English: an "are you ready to work?" check. It answers {"ok": true}
# only if the database is reachable too. If the database is down it answers
# with a plain 503 error and no details. Kubernetes will later use this to
# decide whether to send requests to this copy of the service.
@app.get("/ready")
def ready():
    if database_is_ready():
        return {"ok": True}
    return JSONResponse(status_code=503, content={"ok": False})


# In plain English: saves one new graded example. FastAPI first checks the
# request against the NewExample rules and turns bad requests away on its own
# (error 422) before any of our code runs. If the database has a problem, the
# caller gets a plain 503 with no details about why.
@app.post("/examples", status_code=201)
def create_example(example: NewExample):
    try:
        return {"example_id": save_example(example)}
    except psycopg.Error:
        return JSONResponse(status_code=503, content={"ok": False})


# In plain English: lists the saved examples for one assignment. The
# assignment_id must be a real UUID or FastAPI turns the request away (422).
@app.get("/examples")
def get_examples(assignment_id: UUID):
    try:
        return list_examples(assignment_id)
    except psycopg.Error:
        return JSONResponse(status_code=503, content={"ok": False})


# In plain English: finds the saved examples closest in meaning to some text. It
# searches inside the assignment. Only when the caller sets fallback_to_all does an
# assignment with no examples of its own borrow from every assignment. Bad input is turned away by FastAPI (422) before our
# code runs; a database problem gives a plain 503 with no details. This is a
# POST only because the text to compare can be long, not because it saves
# anything.
@app.post("/examples/search")
def search(request: SearchRequest):
    try:
        return search_examples(request)
    except psycopg.Error:
        return JSONResponse(status_code=503, content={"ok": False})
