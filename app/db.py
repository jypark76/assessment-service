# In plain English: this file is the service's connection to its own database.
# It reads the database address, name, login and password from settings (called
# environment variables) that are handed to the box when it starts. Nothing
# secret is ever written in the code, because this repo is public.
import os

import psycopg


# In plain English: reads one required setting and stops with a clear message
# if it is missing. Failing early is better than a confusing error later.
def _required(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required setting: {name}")
    return value


# In plain English: opens a connection to the database using the settings. The
# password is only passed along, never printed or logged anywhere.
def connect():
    return psycopg.connect(
        host=_required("DB_HOST"),
        port=int(os.environ.get("DB_PORT", "5432")),
        dbname=_required("DB_NAME"),
        user=_required("DB_USER"),
        password=_required("DB_PASSWORD"),
        connect_timeout=3,
    )


# In plain English: asks the database a trivial question ("what is 1?") to
# prove it is reachable and our login works. Returns True if it answered and
# False if anything went wrong. The details of what went wrong are kept out of
# the result on purpose, so a caller outside the box learns nothing about the
# database's address or login.
def database_is_ready():
    try:
        with connect() as connection:
            connection.execute("SELECT 1")
        return True
    except Exception:
        return False
