# In plain English: the shared service key. Every route except the health checks needs the
# header "Authorization: Bearer <key>". The key is a long secret that only trusted callers
# (the other services) know. It comes from the setting SERVICE_KEYS, which Kubernetes fills
# from a Secret. More than one key may be listed, separated by commas, so a key can be
# replaced without downtime: add the new one, switch the callers over, remove the old one.
#
# What it promises:
#   - A call without the right key gets 401 with the same fixed reply every time, so the
#     reply never says what was wrong and never repeats what was sent.
#   - If no usable key is configured the service answers 503 and stays closed. It never
#     falls back to "open".
#   - A key shorter than 32 characters is not usable, so a weak key cannot be set by mistake.
#   - Keys are compared in constant time, so timing reveals nothing about a near miss.
#   - New routes are protected by default. Only the paths listed in OPEN_PATHS are open.
#   - Every refusal is logged with its reason, the method and the route, so someone trying keys or
#     calling with a wrong one can be noticed. The line never holds the key, the header or anything a
#     caller can use to forge a log line, and a flood of refusals is summarized instead of logged one
#     by one. The summary is written when the next window starts or, if the refusals stop, by a timer
#     when the window closes, so the count is never left unreported.
#
# What it is not: one shared key says "a trusted caller", not "which person". Real user
# login comes later.
import hmac
import logging
import os
import re
import threading
import time

from fastapi import Request
from fastapi.responses import JSONResponse

MIN_KEY_LENGTH = 32

LOGGER_NAME = "service-key"
log = logging.getLogger(LOGGER_NAME)

# At most this many refusals are logged one by one in each window. The rest are counted and
# reported in one line when the next window starts, so an attack cannot fill the log.
REFUSAL_LOG_LIMIT = 20
REFUSAL_WINDOW_SECONDS = 60
PATH_LOG_LENGTH = 100

# Kubernetes' own probes cannot send a key, so the two health checks stay open.
OPEN_PATHS = {"/health", "/ready"}


# In plain English: reads the configured keys fresh on every call (so tests and key
# rotation take effect at once) and keeps only the usable ones.
def configured_keys():
    raw = os.environ.get("SERVICE_KEYS", "")
    keys = [part.strip() for part in raw.split(",")]
    return [key.encode("utf-8") for key in keys if len(key) >= MIN_KEY_LENGTH]


# In plain English: pulls the key out of "Bearer <key>". Anything that does not have
# exactly that shape gives nothing.
def presented_key(header):
    if header is None:
        return None
    parts = header.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        return None
    return parts[1].encode("utf-8")


# In plain English: true only if the presented key equals one of the configured keys.
# It checks all of them, without stopping at the first match, to keep the timing even.
def key_is_valid(presented, keys):
    if presented is None:
        return False
    matched = False
    for key in keys:
        if hmac.compare_digest(presented, key):
            matched = True
    return matched


_lock = threading.Lock()
_window_start = None
_logged_in_window = 0
_held_back = 0
_window_id = 0  # changes with every new window, so an old timer can tell it is out of date
_timer_set = False


# In plain English: the clock the refusal log uses. Tests replace it to move time forward.
def _now():
    return time.monotonic()


# In plain English: forgets the current window. Used by tests.
def reset_refusal_window():
    global _window_start, _logged_in_window, _held_back, _timer_set
    with _lock:
        _window_start, _logged_in_window, _held_back, _timer_set = None, 0, 0, False


# In plain English: keeps only plain, harmless characters and cuts the text short, so nothing a caller
# sends (a line break, a fake log line, a very long path) can change what the log line says.
def _safe_text(text, longest):
    return re.sub(r"[^A-Za-z0-9/_.~%\-]", "?", text)[:longest]


# In plain English: starts a one-shot timer that calls "function" with the window's number after
# "delay" seconds. It is a background thread that never keeps the program alive. Tests replace this
# function to capture the timer instead of waiting for it.
def _start_timer(delay, function, window_id):
    timer = threading.Timer(delay, function, args=(window_id,))
    timer.daemon = True
    timer.start()


# In plain English: what the timer does when its window closes. If refusals were held back in that
# window and nobody has reported them yet, it reports the count now. If a newer window has already
# started, or the count was already reported, it does nothing.
def _flush_window(window_id):
    global _window_start, _logged_in_window, _held_back, _timer_set
    with _lock:
        if window_id != _window_id or _held_back == 0:
            return
        held = _held_back
        _window_start, _logged_in_window, _held_back, _timer_set = None, 0, 0, False
    log.warning("%s more refusals in the previous %s seconds were not logged one by one", held, REFUSAL_WINDOW_SECONDS)


# In plain English: records one refusal, within the limit for the current window. When a new window
# starts, first says how many refusals the previous one held back.
def _note_refusal(reason, request):
    global _window_start, _logged_in_window, _held_back, _window_id, _timer_set
    held = 0
    timer = None
    with _lock:
        now = _now()
        if _window_start is None or now - _window_start >= REFUSAL_WINDOW_SECONDS:
            held = _held_back
            _window_start, _logged_in_window, _held_back = now, 0, 0
            _window_id += 1
            _timer_set = False
        allowed = _logged_in_window < REFUSAL_LOG_LIMIT
        if allowed:
            _logged_in_window += 1
        else:
            _held_back += 1
            if not _timer_set:
                _timer_set = True
                timer = (max(0.0, _window_start + REFUSAL_WINDOW_SECONDS - now), _window_id)
    if timer:
        _start_timer(timer[0], _flush_window, timer[1])
    if held:
        log.warning("%s more refusals in the previous %s seconds were not logged one by one", held, REFUSAL_WINDOW_SECONDS)
    if allowed:
        raw_path = (request.scope.get("raw_path") or request.url.path.encode("utf-8", "replace")).decode("latin-1")
        log.warning(
            "service key refused: reason=%s method=%s path=%s",
            reason,
            _safe_text(request.method, 10),
            _safe_text(raw_path, PATH_LOG_LENGTH),
        )


# In plain English: the guard that runs in front of every request (installed in main.py).
# It lets the open paths through, refuses with 503 when no key is configured, refuses
# with 401 when the key is missing or wrong, and otherwise lets the request continue.
async def require_service_key(request: Request, call_next):
    if request.url.path in OPEN_PATHS:
        return await call_next(request)
    keys = configured_keys()
    if not keys:
        _note_refusal("not_configured", request)
        return JSONResponse(status_code=503, content={"problem": "Service key is not configured"})
    header = request.headers.get("authorization")
    presented = presented_key(header)
    if not key_is_valid(presented, keys):
        _note_refusal("missing" if header is None else ("malformed" if presented is None else "wrong"), request)
        return JSONResponse(
            status_code=401,
            content={"problem": "A valid service key is required"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await call_next(request)
