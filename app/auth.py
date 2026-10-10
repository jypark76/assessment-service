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
#
# What it is not: one shared key says "a trusted caller", not "which person". Real user
# login comes later.
import hmac
import os

from fastapi import Request
from fastapi.responses import JSONResponse

MIN_KEY_LENGTH = 32

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


# In plain English: the guard that runs in front of every request (installed in main.py).
# It lets the open paths through, refuses with 503 when no key is configured, refuses
# with 401 when the key is missing or wrong, and otherwise lets the request continue.
async def require_service_key(request: Request, call_next):
    if request.url.path in OPEN_PATHS:
        return await call_next(request)
    keys = configured_keys()
    if not keys:
        return JSONResponse(status_code=503, content={"problem": "Service key is not configured"})
    if not key_is_valid(presented_key(request.headers.get("authorization")), keys):
        return JSONResponse(
            status_code=401,
            content={"problem": "A valid service key is required"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await call_next(request)
