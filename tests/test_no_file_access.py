# In plain English: tests that the application code never touches the file system, serves files or redirects a
# caller somewhere else. The services only talk to their database and to Kafka, so there is no reason for
# code in app/ to open a file, build a path, make a temporary file, list a folder, send a file back or send a
# "go to this address" reply. If a future change does, these tests turn red and somebody has to decide on
# purpose.
#
# Why it matters (OWASP A01): code that opens a file whose name comes from a caller is how path traversal,
# link following and temporary-file attacks work (CWE-22, 23, 36, 59, 61, 65, 377, 379), code that serves
# files can expose a folder or a listing (CWE-219, 548, 552) and a redirect to an address a caller chose is an
# open redirect (CWE-601). Today the code reads only environment variables, so all of these hold by being
# true; this test keeps them true.
#
# Like the other scanners, it proves itself: a list of deliberately bad programs must each be caught and a
# list of good ones must not be.
import ast
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parent.parent / "app"

# Modules that exist to work with files or folders.
FILE_MODULES = {"pathlib", "shutil", "tempfile", "glob", "fnmatch", "zipfile", "tarfile", "mmap", "fileinput", "filecmp", "linecache"}
# The only things the code may use from the os module: reading environment variables.
OS_ALLOWED = {"environ", "getenv"}
# Names that read, write, serve or redirect.
BANNED_NAMES = {"open", "Path", "PurePath", "FileResponse", "StaticFiles", "RedirectResponse", "send_file", "send_from_directory"}
# Method names that touch files or folders.
BANNED_METHODS = {"read_text", "write_text", "read_bytes", "write_bytes", "mkdir", "rmdir", "unlink", "iterdir", "rglob", "symlink_to", "hardlink_to", "touch", "chmod", "rename", "resolve"}


# In plain English: reads one Python file's text and returns a list of (what was found, line) for every use of
# the file system, file serving or redirects.
def find_file_access(source):
    tree = ast.parse(source)
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in FILE_MODULES:
                    problems.append((f"imports {alias.name}", node.lineno))
                if top == "os" and alias.name != "os":
                    problems.append((f"imports {alias.name}", node.lineno))
        if isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            if top in FILE_MODULES:
                problems.append((f"imports from {node.module}", node.lineno))
            if top == "os" and any(alias.name not in OS_ALLOWED for alias in node.names):
                problems.append(("imports a file function from os", node.lineno))
            for alias in node.names:
                if alias.name in BANNED_NAMES:
                    problems.append((f"imports {alias.name}", node.lineno))
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr not in OS_ALLOWED:
            problems.append((f"os.{node.attr}", node.lineno))
        if isinstance(node, ast.Name) and node.id in BANNED_NAMES:
            problems.append((f"uses {node.id}", node.lineno))
        if isinstance(node, ast.Attribute) and node.attr in BANNED_NAMES | BANNED_METHODS:
            problems.append((f"uses .{node.attr}", node.lineno))
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.strip().lower() == "location":
            problems.append(("a Location header (a redirect)", node.lineno))
    return sorted(set(problems), key=lambda p: p[1])


def app_files():
    return sorted(APP.glob("*.py"))


# In plain English: the one module allowed to open a file, and exactly what it may do. app/secret_files.py reads a
# mounted Secret; it may import PurePosixPath to check the path and call open once. Anything else it does, or
# anything any other file does, still fails.
ALLOWED = {"secret_files.py": {"imports from pathlib", "uses open"}}


# In plain English: the problems left after removing what the allowance excuses for this file.
def unexpected(filename, problems):
    excused = ALLOWED.get(filename, set())
    return [problem for problem in problems if problem[0] not in excused]



# ---------- The real code ----------

@pytest.mark.owasp("A01", 22, 23, 36, 59, 61, 65, 219, 377, 379, 548, 552, 601)
def test_application_code_never_touches_the_file_system_or_redirects():
    files = app_files()
    assert files, "no application files were found to check"
    found = {path.name: unexpected(path.name, find_file_access(path.read_text(encoding="utf-8"))) for path in files}
    assert {name: problems for name, problems in found.items() if problems} == {}


@pytest.mark.owasp("A01", 22, 23, 36, 59, 61, 65, 219, 377, 379, 548, 552, 601)
def test_the_check_covers_the_real_application_files():
    names = {path.name for path in app_files()}
    assert {"main.py", "auth.py", "db.py", "errors.py"} <= names


@pytest.mark.owasp("A01", 22, 23, 36, 59, 61, 65, 219, 377, 379, 548, 552, 601)
def test_every_allowance_is_still_needed_and_opens_exactly_one_file():
    # An allowance that nothing uses would let a future file read through under the same name.
    for filename, labels in ALLOWED.items():
        path = APP / filename
        if not path.exists():
            continue
        problems = find_file_access(path.read_text(encoding="utf-8"))
        assert {label for label, _ in problems} == labels, (filename, problems)
        assert sum(1 for label, _ in problems if label == "uses open") == 1


@pytest.mark.owasp("A01", 22, 23, 36, 59, 61, 65, 219, 377, 379, 548, 552, 601)
def test_the_allowed_module_is_still_caught_when_it_does_anything_else():
    extra = "import os\n\ndef f(path):\n    return os.listdir(path)\n"
    assert unexpected("secret_files.py", find_file_access(extra))
    assert unexpected("secret_files.py", find_file_access("from pathlib import Path\n"))  # only PurePosixPath's module label is excused, not Path itself
    assert unexpected("secret_files.py", find_file_access("def f(p):\n    return open(p).read()\n")) == []
    assert unexpected("other.py", find_file_access("def f(p):\n    return open(p).read()\n"))


# ---------- The check proves itself ----------

BAD = {
    "open a file": "def f(name):\n    return open(name).read()\n",
    "open with a computed path": "def f(user):\n    return open('/data/' + user)\n",
    "pathlib import": "from pathlib import Path\n",
    "path object": "def f(x):\n    return Path(x).read_text()\n",
    "read_text on anything": "def f(p):\n    return p.read_text()\n",
    "write_bytes": "def f(p):\n    p.write_bytes(b'x')\n",
    "os path join": "import os\n\ndef f(a, b):\n    return os.path.join(a, b)\n",
    "os listdir": "import os\n\ndef f(a):\n    return os.listdir(a)\n",
    "os remove": "import os\n\ndef f(a):\n    os.remove(a)\n",
    "os symlink": "import os\n\ndef f(a, b):\n    os.symlink(a, b)\n",
    "os link": "import os\n\ndef f(a, b):\n    os.link(a, b)\n",
    "os walk": "import os\n\ndef f(a):\n    return list(os.walk(a))\n",
    "os submodule import": "import os.path\n",
    "from os import a file function": "from os import listdir\n",
    "shutil": "import shutil\n",
    "temporary file": "import tempfile\n\ndef f():\n    return tempfile.NamedTemporaryFile()\n",
    "glob": "import glob\n",
    "zip file": "import zipfile\n",
    "send a file back": "from fastapi.responses import FileResponse\n",
    "serve a folder": "from fastapi.staticfiles import StaticFiles\n",
    "redirect": "from fastapi.responses import RedirectResponse\n\ndef f(url):\n    return RedirectResponse(url)\n",
    "redirect through a header": "def f(url):\n    return Response(status_code=302, headers={'Location': url})\n",
    "iterate a folder": "def f(p):\n    return list(p.iterdir())\n",
    "make a folder": "def f(p):\n    p.mkdir()\n",
    "resolve a path": "def f(p):\n    return p.resolve()\n",
}

GOOD = {
    "reading an environment variable": "import os\n\nvalue = os.environ.get('X')\nother = os.getenv('Y')\n",
    "importing environ": "from os import environ\n",
    "a database call": "def f(connection):\n    return connection.execute('SELECT 1')\n",
    "a word that merely contains open": "def reopen_later():\n    return 1\n",
}


@pytest.mark.owasp("A01", 22, 23, 36, 59, 61, 65, 219, 377, 379, 548, 552, 601)
@pytest.mark.parametrize("label", sorted(BAD))
def test_every_bad_program_is_caught(label):
    assert find_file_access(BAD[label]), label


@pytest.mark.owasp("A01", 22, 23, 36, 59, 61, 65, 219, 377, 379, 548, 552, 601)
@pytest.mark.parametrize("label", sorted(GOOD))
def test_good_programs_are_not_flagged(label):
    assert find_file_access(GOOD[label]) == []
