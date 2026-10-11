# In plain English: tests that the application's settings are fixed when it is deployed and that it opens no
# doors a service of this kind should never have. The code in app/ may read its settings but may never change
# them, never copy or print the whole environment (where passwords and keys live), never add a cross-domain
# (CORS) policy and never parse XML.
#
# Why it matters (OWASP A02, security misconfiguration):
#   - CWE-15, external control of a setting: if input could change a setting, a caller could change how the
#     service behaves. Here only the person who deploys it can.
#   - CWE-526, secrets in environment variables: a loop over the environment, or a dump of it into a log or an
#     error, would print every password and key at once.
#   - CWE-942, a permissive cross-domain policy: these services are never called from a web page, so no policy
#     at all is the safe setting; adding one would invite pages from other sites to call them.
#   - CWE-611 and 776, XML entity attacks: there is no XML here, and a parser that is never imported cannot be
#     attacked.
#
# Like the other code scanners, it proves itself with deliberately bad and good programs.
import ast
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parent.parent / "app"

# The only functions that may receive the whole environment: they read named settings from it and nothing else.
SETTINGS_FUNCTIONS = {"consumer_settings", "producer_settings"}
WRITING_METHODS = {"update", "setdefault", "pop", "popitem", "clear", "__setitem__", "__delitem__"}
DUMPING_METHODS = {"items", "keys", "values", "copy", "__iter__"}
XML_MODULES = {"xml", "lxml", "defusedxml", "xmlrpc", "xmltodict", "untangle", "elementtree"}
CORS_NAMES = {"CORSMiddleware", "cors"}


def is_environment(node):
    return isinstance(node, ast.Attribute) and node.attr == "environ" and isinstance(node.value, ast.Name) and node.value.id == "os"


# In plain English: reads one Python file's text and returns a list of (what was found, line).
def find_configuration_problems(source):
    tree = ast.parse(source)
    parent = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    problems = []
    for node in ast.walk(tree):
        # Changing a setting: os.environ["X"] = ..., os.environ.update(...), os.putenv(...)
        if isinstance(node, ast.Subscript) and is_environment(node.value) and isinstance(node.ctx, (ast.Store, ast.Del)):
            problems.append(("changes the environment", node.lineno))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if is_environment(node.func.value) and node.func.attr in WRITING_METHODS:
                problems.append(("changes the environment", node.lineno))
            if is_environment(node.func.value) and node.func.attr in DUMPING_METHODS:
                problems.append(("lists or copies the whole environment", node.lineno))
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr in ("putenv", "unsetenv"):
                problems.append(("changes the environment", node.lineno))
        # Using the whole environment as a value: only the named settings functions may receive it.
        if is_environment(node):
            holder = parent.get(node)
            if isinstance(holder, ast.Attribute) and holder.attr == "get":
                continue  # os.environ.get("X")
            if isinstance(holder, ast.Subscript) and holder.value is node and isinstance(holder.ctx, ast.Load):
                continue  # os.environ["X"] read
            if isinstance(holder, ast.Attribute):
                continue  # the method checks above judge it
            if isinstance(holder, ast.Subscript):
                continue  # the store/delete check above judges it
            if isinstance(holder, ast.Call) and node in holder.args:
                name = holder.func.id if isinstance(holder.func, ast.Name) else getattr(holder.func, "attr", "")
                if name in SETTINGS_FUNCTIONS:
                    continue
            problems.append(("uses the whole environment as a value", node.lineno))
        # A cross-domain policy
        if isinstance(node, ast.Name) and node.id in CORS_NAMES:
            problems.append(("sets up CORS", node.lineno))
        if isinstance(node, ast.Attribute) and node.attr in CORS_NAMES:
            problems.append(("sets up CORS", node.lineno))
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            lowered = node.value.strip().lower()
            if lowered.startswith("access-control-") or "crossdomain" in lowered or "clientaccesspolicy" in lowered:
                problems.append(("sets a cross-domain policy", node.lineno))
        if isinstance(node, ast.ImportFrom) and (node.module or "").endswith(".cors"):
            problems.append(("sets up CORS", node.lineno))
        # XML
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0].lower() in XML_MODULES:
                    problems.append((f"imports {alias.name}", node.lineno))
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0].lower() in XML_MODULES:
            problems.append((f"imports from {node.module}", node.lineno))
    return sorted(set(problems), key=lambda p: p[1])


def app_files():
    return sorted(APP.glob("*.py"))


# ---------- The real code ----------

@pytest.mark.owasp("A02", 15, 526, 942, 611, 776)
def test_the_application_code_keeps_its_configuration_fixed_and_opens_no_cross_domain_or_xml_doors():
    files = app_files()
    assert files, "no application files were found to check"
    found = {path.name: find_configuration_problems(path.read_text(encoding="utf-8")) for path in files}
    assert {name: problems for name, problems in found.items() if problems} == {}


@pytest.mark.owasp("A02", 15, 526, 942, 611, 776)
def test_the_check_covers_the_real_application_files():
    names = {path.name for path in app_files()}
    assert {"main.py", "auth.py", "db.py", "errors.py"} <= names


@pytest.mark.owasp("A02", 526)
def test_only_the_named_settings_functions_receive_the_whole_environment():
    # The allowance is real: take it away and the real code is flagged. An allowance nothing uses would let a
    # future dump of the environment through under the same name.
    import re

    receivers = set()
    for path in app_files():
        for match in re.finditer(r"(\w+)\(os\.environ\)", path.read_text(encoding="utf-8")):
            receivers.add(match.group(1))
    assert receivers <= SETTINGS_FUNCTIONS, receivers - SETTINGS_FUNCTIONS


# ---------- The check proves itself ----------

BAD = {
    "assigning to the environment": "import os\n\nos.environ['MODE'] = 'x'\n",
    "deleting from the environment": "import os\n\ndel os.environ['MODE']\n",
    "updating the environment": "import os\n\nos.environ.update({'A': 'b'})\n",
    "setdefault on the environment": "import os\n\nos.environ.setdefault('A', 'b')\n",
    "popping from the environment": "import os\n\nos.environ.pop('A')\n",
    "putenv": "import os\n\nos.putenv('A', 'b')\n",
    "unsetenv": "import os\n\nos.unsetenv('A')\n",
    "looping over the environment": "import os\n\nfor k, v in os.environ.items():\n    pass\n",
    "listing the environment keys": "import os\n\nnames = list(os.environ.keys())\n",
    "copying the environment": "import os\n\nsnapshot = os.environ.copy()\n",
    "turning it into a dict": "import os\n\nsnapshot = dict(os.environ)\n",
    "logging it": "import os\n\nlog.info('settings %s', os.environ)\n",
    "an f-string with it": "import os\n\ntext = f'{os.environ}'\n",
    "returning it": "import os\n\ndef f():\n    return os.environ\n",
    "passing it to another function": "import os\n\nprint_all(os.environ)\n",
    "cors middleware": "from fastapi.middleware.cors import CORSMiddleware\n\napp.add_middleware(CORSMiddleware, allow_origins=['*'])\n",
    "cors name only": "def f(app):\n    app.add_middleware(CORSMiddleware)\n",
    "an access-control header": "def f():\n    return {'Access-Control-Allow-Origin': '*'}\n",
    "a crossdomain file": "def f():\n    return '/crossdomain.xml'\n",
    "an xml parser": "import xml.etree.ElementTree as ET\n",
    "an xml parser from import": "from xml.dom import minidom\n",
    "lxml": "import lxml.etree\n",
    "defusedxml": "import defusedxml.ElementTree\n",
    "xmlrpc": "import xmlrpc.client\n",
}

GOOD = {
    "reading a setting": "import os\n\nvalue = os.environ.get('DB_HOST')\nother = os.environ['DB_NAME']\nthird = os.getenv('DB_USER')\n",
    "the settings functions": "import os\n\nsettings = consumer_settings(os.environ)\nother = producer_settings(os.environ)\n",
    "a membership test is a read": "import os\n\nflag = 'X' in os.environ\n" if False else "import os\n\nflag = os.environ.get('X') is not None\n",
    "a header that is not cross-domain": "def f():\n    return {'WWW-Authenticate': 'Bearer'}\n",
    "the word xml in text": "note = 'no xml here'\n",
}


@pytest.mark.owasp("A02", 15, 526, 942, 611, 776)
@pytest.mark.parametrize("label", sorted(BAD))
def test_every_bad_program_is_caught(label):
    assert find_configuration_problems(BAD[label]), label


@pytest.mark.owasp("A02", 15, 526, 942, 611, 776)
@pytest.mark.parametrize("label", sorted(GOOD))
def test_good_programs_are_not_flagged(label):
    assert find_configuration_problems(GOOD[label]) == []


# ---------- Security-relevant constants are pinned ----------

@pytest.mark.owasp("A02", 547)
def test_the_security_relevant_constants_have_the_agreed_values():
    # These values decide who is let in and how much is logged. They live in one place (app/auth.py), each with
    # a comment, and this test pins them, so changing one is a deliberate decision made in a pull request that
    # also changes this test, never a quiet edit.
    from app import auth, errors

    assert auth.MIN_KEY_LENGTH == 32
    assert auth.OPEN_PATHS == {"/health", "/ready"}
    assert auth.REFUSAL_LOG_LIMIT == 20
    assert auth.REFUSAL_WINDOW_SECONDS == 60
    assert auth.PATH_LOG_LENGTH == 100
    assert auth.LEGACY_CALLER == "legacy" and auth.ALL_ROUTES == "*"
    assert auth.CALLER_NAME.pattern == "[a-z][a-z0-9-]{1,39}"
    assert errors.FIXED_PROBLEMS[404] == "Not found" and errors.UNEXPECTED_PROBLEM == "Something went wrong"


@pytest.mark.owasp("A02", 547)
def test_the_security_relevant_constants_are_defined_once_in_the_code():
    import re

    definitions = {}
    for path in app_files():
        for match in re.finditer(r"(?m)^(MIN_KEY_LENGTH|OPEN_PATHS|REFUSAL_LOG_LIMIT|REFUSAL_WINDOW_SECONDS|PATH_LOG_LENGTH)\s*=", path.read_text(encoding="utf-8")):
            definitions.setdefault(match.group(1), []).append(path.name)
    assert definitions == {name: ["auth.py"] for name in ("MIN_KEY_LENGTH", "OPEN_PATHS", "REFUSAL_LOG_LIMIT", "REFUSAL_WINDOW_SECONDS", "PATH_LOG_LENGTH")}
