# In plain English: this is the front door of the assessment service. It answers two
# questions, "are you alive?" and "are you ready to work?", and it offers the
# assignment routes (create one, read one, list the newest) and the submission routes
# (send one in, read one back with its history). Grades and reviews come in later steps.
from uuid import UUID

from fastapi import FastAPI, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.assignments import (
    NewAssignment,
    TitleInUse,
    create_assignment,
    get_assignment,
    list_assignments,
)
from app.db import database_is_ready
from app.submissions import (
    AssignmentNotFound,
    IdUsedForOtherContent,
    NewSubmission,
    create_submission,
    get_submission,
)

# Create the web application. The title and version show up on the automatic
# documentation page FastAPI builds at /docs.
app = FastAPI(title="Assessment service", version="0.3.0")


# In plain English: the kinds of error whose built-in wording is safe, because it
# only describes the rule and never quotes what the caller sent. "value_error" is
# for our own checks, which always use fixed wording of our own.
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
# is the path to the field, like "body.assignment_id". For an unexpected extra
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


# In plain English: creates an assignment and answers 201 with the saved assignment,
# including the ID the service gave it. If the title is already in use, it answers 409
# with fixed wording that does not quote the title.
@app.post("/assignments", status_code=201)
def add_assignment(body: NewAssignment):
    try:
        return create_assignment(body)
    except TitleInUse:
        return JSONResponse(
            status_code=409,
            content={"problem": "An assignment with this title already exists"},
        )


# In plain English: lists the newest assignments first, without their rubrics. The
# caller can ask for 1 to 100 of them, and gets 50 if it does not say.
@app.get("/assignments")
def assignment_list(limit: int = Query(50, ge=1, le=100)):
    return list_assignments(limit)


# In plain English: reads one assignment, rubric included. An ID that does not exist
# answers 404, and the reply does not repeat the ID.
@app.get("/assignments/{assignment_id}")
def assignment_detail(assignment_id: UUID):
    found = get_assignment(assignment_id)
    if found is None:
        return JSONResponse(status_code=404, content={"problem": "Assignment not found"})
    return found


# In plain English: sends a student's work in as version 1. A new submission answers
# 201. The same request sent again (same ID, same content) answers 200 with the
# original and creates nothing. An ID already used for different content answers 409,
# and an assignment that does not exist answers 404. The replies use fixed wording and
# never repeat what the caller sent.
@app.post("/submissions")
def add_submission(body: NewSubmission):
    try:
        saved, created = create_submission(body)
    except AssignmentNotFound:
        return JSONResponse(status_code=404, content={"problem": "Assignment not found"})
    except IdUsedForOtherContent:
        return JSONResponse(
            status_code=409,
            content={"problem": "This submission ID is already used for different content"},
        )
    return JSONResponse(status_code=201 if created else 200, content=jsonable_encoder(saved))


# In plain English: reads a submission with its history, one entry per version. An ID
# that does not exist answers 404, and the reply does not repeat the ID.
@app.get("/submissions/{submission_id}")
def submission_detail(submission_id: UUID):
    found = get_submission(submission_id)
    if found is None:
        return JSONResponse(status_code=404, content={"problem": "Submission not found"})
    return found


# In plain English: an "are you ready to work?" check. It answers {"ok": true}
# only if the database is reachable too. If the database is down it answers
# with a plain 503 error and no details. Kubernetes will later use this to
# decide whether to send requests to this copy of the service.
@app.get("/ready")
def ready():
    if database_is_ready():
        return {"ok": True}
    return JSONResponse(status_code=503, content={"ok": False})
