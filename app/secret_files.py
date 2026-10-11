# In plain English: reads a secret (the service keys, the database password) either from a file that Kubernetes
# mounts, or from a plain setting. A setting called NAME_FILE names the file; if it is not set, the setting NAME
# is used, which keeps local runs and tests simple. Kubernetes keeps a mounted Secret up to date, so a changed
# Secret reaches the file without restarting the pod.
#
# This is the only place in app/ that opens a file, and it is strict:
#   - the path must be inside /etc/secrets (where the Secrets are mounted), written without "..", so a wrong or
#     tampered setting can never make the service read some other file;
#   - if the file cannot be read the service stops (RuntimeError), it never falls back to something open;
#   - only the final line break is removed from the text, nothing else;
#   - the text is returned, never logged, and never put in an error message.
import os
from pathlib import PurePosixPath

SECRET_FOLDER = ("/", "etc", "secrets")


# In plain English: the one place a file is opened. Tests replace it so they need no real files.
def _read_text(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


# In plain English: true only for a path with at least one name below /etc/secrets and no "..". A path that does
# not start with "/etc/secrets" (a relative path, another folder, a look-alike such as /etc/secretsX) fails the
# first test, and PurePosixPath has already folded any "." parts away.
def _is_allowed(path_text):
    if not path_text.strip() or "\x00" in path_text:
        return False
    parts = PurePosixPath(path_text).parts
    return parts[:3] == SECRET_FOLDER and len(parts) > 3 and ".." not in parts


# In plain English: returns the secret called NAME, from the file named by NAME_FILE if that is set, otherwise from
# the setting NAME (or None if neither is set).
def read_secret(name):
    path_text = os.environ.get(f"{name}_FILE")
    if not path_text:
        return os.environ.get(name)
    if not _is_allowed(path_text):
        raise RuntimeError(f"{name}_FILE must name a file inside /etc/secrets")
    try:
        text = _read_text(path_text)
    except OSError:
        raise RuntimeError(f"The secret file for {name} could not be read") from None
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n"):
        return text[:-1]
    return text
