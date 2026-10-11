# In plain English: a guardrail that keeps this service from ever reaching a place chosen by someone
# else. The service must not open connections to addresses it was handed in a request or a message, and
# the Kafka topics it reads and writes must be fixed names written in the code or taken from settings,
# never built from a message.
#
# Why it matters: if a request or message could pick the address or the topic, an attacker could make
# the service call an internal system, leak data to their own server or read someone else's topic
# (OWASP A05 CWE-610 "externally controlled reference to a resource", and the server-side request
# forgery family in A01).
#
# It reads the program text (it never runs it). Its own tests feed it small bad and good programs, so it
# cannot pass by finding nothing.
import ast
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "app"

# Modules that open connections to other machines. This service talks only to its database (through
# psycopg, configured by settings) and to Kafka (through confluent_kafka, configured by settings).
# Anything else in app/ must be a deliberate decision, so adding it must change this list.
OUTBOUND_MODULES = {
    "requests", "httpx", "urllib", "urllib3", "http", "socket", "aiohttp", "websockets", "ftplib", "smtplib",
    "telnetlib", "xmlrpc", "poplib", "imaplib", "paramiko", "grpc",
}

# Calls whose first argument names a Kafka topic.
TOPIC_CALLS = {"produce", "subscribe"}


# In plain English: reads one program's text and returns plain sentences, one per problem, each with
# its line number.
def find_unfixed_destinations(source, name="<code>"):
    tree = ast.parse(source)
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in OUTBOUND_MODULES:
                    problems.append(f"{name}:{node.lineno}: imports '{alias.name}', which opens connections to other machines")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in OUTBOUND_MODULES:
                problems.append(f"{name}:{node.lineno}: imports from '{node.module}', which opens connections to other machines")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in TOPIC_CALLS:
            if not node.args:
                continue
            first = node.args[0]
            options = first.elts if isinstance(first, (ast.List, ast.Tuple)) else [first]
            for option in options:
                fixed = isinstance(option, ast.Name) or (isinstance(option, ast.Constant) and isinstance(option.value, str))
                if not fixed:
                    problems.append(f"{name}:{node.lineno}: the topic given to '{node.func.attr}' is computed, not a fixed name")
    return problems


def app_files():
    return sorted(APP.rglob("*.py"))


# In plain English: the real check. Every Python file in app/ must be clean.
def test_application_code_reaches_only_fixed_destinations():
    files = app_files()
    assert files, "no application files were found to check"
    problems = []
    for path in files:
        problems.extend(find_unfixed_destinations(path.read_text(encoding="utf-8"), f"app/{path.relative_to(APP).as_posix()}"))
    assert problems == [], "\n".join(problems)


# In plain English: the Kafka topic names themselves are fixed words in the code and match the written
# contracts, so a topic can only ever be one we agreed.
def test_the_topic_names_are_fixed_words():
    expected = {
        "results_consumer.py": ['TOPIC = "grading-results"', 'DEAD_LETTER_TOPIC = "grading-results.dead-letter"'],
        "sender.py": ['TOPIC = "approved-examples"'],
        "job_sender.py": ['TOPIC = "grading-jobs"'],
    }
    for name, lines in expected.items():
        text = (APP / name).read_text(encoding="utf-8")
        for line in lines:
            assert line in text, (name, line)


def test_the_check_covers_the_real_application_files():
    names = {path.name for path in app_files()}
    assert {"main.py", "auth.py", "db.py", "results_consumer.py", "sender.py", "job_sender.py"} <= names


# ---------------------------------------------------------------------------
# Self-tests: the check must complain about each bad program and stay quiet for good ones.
# ---------------------------------------------------------------------------

BAD_PROGRAMS = {
    "requests": "import requests\nrequests.get('http://x')\n",
    "requests with a nickname": "import requests as r\n",
    "from requests import": "from requests import get\n",
    "httpx": "import httpx\n",
    "urllib.request": "import urllib.request\n",
    "from urllib import": "from urllib import request\n",
    "http.client": "import http.client\n",
    "socket": "import socket\n",
    "smtplib": "import smtplib\n",
    "aiohttp": "import aiohttp\n",
    "an f-string topic": "def f(p, m):\n    p.produce(f'topic-{m}', key=b'k')\n",
    "a topic from a function call": "def f(p, m):\n    p.produce(m.topic(), key=b'k')\n",
    "a topic from a dictionary": "def f(p, m):\n    p.produce(m['topic'])\n",
    "a topic joined from text": "def f(p, m):\n    p.produce('a-' + m)\n",
    "a subscribe list with a computed item": "def f(c, m):\n    c.subscribe([m.topic])\n",
}

GOOD_PROGRAMS = {
    "a fixed topic name": "def f(p):\n    p.produce('approved-examples', key=b'k')\n",
    "a named constant": "TOPIC = 'x'\ndef f(c):\n    c.subscribe([TOPIC])\n",
    "a topic given as a parameter name": "def f(p, topic):\n    p.produce(topic, key=b'k')\n",
    "the database driver": "import psycopg\n",
    "the kafka client": "from confluent_kafka import Consumer\n",
    "the word in a comment": "# we never import requests or socket here\nx = 1\n",
    "the word in a string": "text = 'import requests'\n",
}


def test_every_bad_program_is_caught():
    for label, source in BAD_PROGRAMS.items():
        assert find_unfixed_destinations(source), f"not caught: {label}"


def test_every_good_program_passes():
    for label, source in GOOD_PROGRAMS.items():
        assert find_unfixed_destinations(source) == [], f"wrongly flagged: {label}: {find_unfixed_destinations(source)}"
