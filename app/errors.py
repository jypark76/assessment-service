# In plain English: what the service does when something goes wrong inside it. Every failure ends in a short,
# fixed reply and one safe log line, so nothing about the program's insides reaches the caller or the log.
#
#   - an unexpected error (a bug)           -> 500 with a fixed sentence
#   - a database or permission error        -> 503 with {"ok": false}, the same reply the routes already give
#   - a wrong address, a wrong method, etc. -> the right status code with a fixed sentence of our own
#
# The log line names only the KIND of error, the method and the route (cleaned so a caller cannot forge a
# log line). It never carries the error's message, because a message can contain what a caller sent, and it
# never carries a traceback, which carries the message too. (OWASP A10: CWE-209, 248, 274, 280, 550, 703,
# 754, 755 and 756; the log rules are OWASP A09.)
import logging

import psycopg
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.auth import PATH_LOG_LENGTH, _safe_text

LOGGER_NAME = "service-errors"
log = logging.getLogger(LOGGER_NAME)

# In plain English: the fixed sentence for each kind of reply. Any status not listed gets the plain one.
FIXED_PROBLEMS = {
    400: "Bad request",
    404: "Not found",
    405: "Method not allowed",
    413: "Request too large",
    415: "Unsupported media type",
    429: "Too many requests",
}
PLAIN_PROBLEM = "The request could not be completed"
UNEXPECTED_PROBLEM = "Something went wrong"


# In plain English: the route, cleaned for the log. Only safe characters are kept and the length is capped.
def _route_text(request: Request):
    return _safe_text(request.url.path, PATH_LOG_LENGTH)


# In plain English: wraps every request. If anything raises an error that no route handled, it ends here
# with a fixed reply. It must be the OUTERMOST layer (added after the service-key check in app/main.py), so
# an error in any layer inside it is caught too. It catches Exception only, never BaseException, so a
# shutdown or a cancelled task is not swallowed.
async def catch_everything(request: Request, call_next):
    try:
        return await call_next(request)
    except psycopg.Error as error:
        log.error("database error %s on %s %s", type(error).__name__, _safe_text(request.method, 10), _route_text(request))
        return JSONResponse(status_code=503, content={"ok": False})
    except Exception as error:
        log.error("unexpected error %s on %s %s", type(error).__name__, _safe_text(request.method, 10), _route_text(request))
        return JSONResponse(status_code=500, content={"problem": UNEXPECTED_PROBLEM})


# In plain English: replaces the framework's own error pages (wrong address, wrong method and so on) with
# a fixed sentence of ours. The status code and any headers the framework asked for (such as Allow on a 405)
# are kept; the framework's wording is dropped because it can include the caller's text.
async def fixed_http_error(request, error: StarletteHTTPException):
    return JSONResponse(
        status_code=error.status_code,
        content={"problem": FIXED_PROBLEMS.get(error.status_code, PLAIN_PROBLEM)},
        headers=error.headers,
    )
