# In plain English: a guardrail that fails the build if the application ever starts accepting uploaded files or
# web-form bodies. Today every request is a small JSON message and nothing else: no file upload, no form. This
# test keeps it that way, so a "helpful" change cannot add an upload door (which would need size limits, type
# checks, scanning and a safe place to store the file) without someone deciding that on purpose.
#
# It reads the program text (it never runs it) and looks at the real structure of the code, so a word inside a
# comment or a string does not trigger it and renaming an import does not hide it. Its own tests at the bottom feed
# it small bad and good programs, so the check cannot pass by never finding anything.
#
# Why it matters (OWASP A06, insecure design): CWE-434, unrestricted upload of a file with a dangerous type, and
# CWE-646, relying on the name or extension of a supplied file.
import ast
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parent.parent / "app"

BANNED_MODULES = {"multipart", "python_multipart", "aiofiles", "werkzeug", "cgi", "tempfile", "shutil", "zipfile", "tarfile"}
BANNED_NAMES = {"UploadFile", "File", "Form", "FileResponse", "StaticFiles"}
BANNED_METHODS = {"form", "stream"}  # request.form(), request.stream()


def find_problems(source, name="app/x.py"):
    tree = ast.parse(source)
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in BANNED_MODULES:
                    problems.append(f"{name}:{node.lineno}: imports '{alias.name}'")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in BANNED_MODULES:
                problems.append(f"{name}:{node.lineno}: imports from '{node.module}'")
            for alias in node.names:
                if alias.name in BANNED_NAMES:
                    problems.append(f"{name}:{node.lineno}: imports '{alias.name}'")
        elif isinstance(node, ast.Attribute):
            if node.attr in BANNED_NAMES:
                problems.append(f"{name}:{node.lineno}: uses '{node.attr}'")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in BANNED_METHODS:
            problems.append(f"{name}:{node.lineno}: reads a request as '{node.func.attr}()'")
    return problems


def app_files():
    return sorted(APP.rglob("*.py"))


@pytest.mark.owasp("A06", 434, 646)
def test_application_code_accepts_no_uploaded_files_or_forms():
    files = app_files()
    assert files, "no application files were found to check"
    problems = []
    for path in files:
        problems.extend(find_problems(path.read_text(encoding="utf-8"), f"app/{path.relative_to(APP).as_posix()}"))
    assert problems == [], "\n".join(problems)


@pytest.mark.owasp("A06", 434, 646)
def test_the_check_covers_the_real_application_files():
    assert {"main.py", "auth.py", "db.py"} <= {path.name for path in app_files()}


BAD_PROGRAMS = {
    "UploadFile": "from fastapi import UploadFile\n",
    "File": "from fastapi import File\n",
    "Form": "from fastapi import Form\n",
    "File brought in through the module": "import fastapi\nx = fastapi.File(...)\n",
    "multipart": "import multipart\n",
    "python_multipart": "import python_multipart\n",
    "from python_multipart": "from python_multipart import parse_options_header\n",
    "tempfile": "import tempfile\n",
    "shutil": "import shutil\n",
    "zipfile": "import zipfile\n",
    "tarfile": "import tarfile\n",
    "static files": "from fastapi.staticfiles import StaticFiles\n",
    "file response": "from fastapi.responses import FileResponse\n",
    "reading a form": "async def f(request):\n    return await request.form()\n",
    "reading a stream": "async def f(request):\n    return request.stream()\n",
}
GOOD_PROGRAMS = {
    "a json route": "from fastapi import FastAPI\napp = FastAPI()\n\n@app.post('/x')\ndef f(body: dict):\n    return body\n",
    "the words in a comment": "# no UploadFile and no File here\nx = 1\n",
    "the words in a string": "message = 'import tempfile'\n",
    "a name that only contains the word": "profile = 1\nFileName = 2\n",
    "a method called form on something else": "class A:\n    def forms(self):\n        return 1\nA().forms()\n",
}


@pytest.mark.owasp("A06", 434, 646)
@pytest.mark.parametrize("label", sorted(BAD_PROGRAMS))
def test_every_bad_program_is_caught(label):
    assert find_problems(BAD_PROGRAMS[label]), label


@pytest.mark.owasp("A06", 434, 646)
@pytest.mark.parametrize("label", sorted(GOOD_PROGRAMS))
def test_every_good_program_passes(label):
    assert find_problems(GOOD_PROGRAMS[label]) == [], f"wrongly flagged: {label}"
