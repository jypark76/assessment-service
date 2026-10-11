# In plain English: a guardrail that fails the build if application code ever starts running shell
# commands, evaluating text as code, loading data that can run code, or choosing what to call from
# text. Today none of the code in app/ does any of these. This test keeps it that way: if someone adds
# one, even by accident or in a helpful-looking change, this test goes red and the merge is blocked.
#
# It reads the program text (it never runs it) and looks at the real structure of the code, so a word
# inside a comment or a string does not trigger it, and renaming an import (import subprocess as sp)
# does not hide a call. It does not need a database or a network.
#
# Its own tests at the bottom feed it small bad programs and good programs, so the check cannot pass
# by never finding anything.
import ast
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parent.parent / "app"

# Modules that are never imported at all: they run commands, load code or objects from data, or
# reach outside the program in ways this service has no need for.
FORBIDDEN_MODULES = {"subprocess", "pickle", "cPickle", "marshal", "shelve", "ctypes", "runpy", "code", "pty", "importlib"}

# Calls that are forbidden even though the module itself is allowed: (module, function).
FORBIDDEN_CALLS = {
    ("os", name)
    for name in (
        "system", "popen", "startfile",
        "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
        "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
        "posix_spawn", "posix_spawnp",
    )
} | {("yaml", name) for name in ("load", "load_all", "unsafe_load", "unsafe_load_all")}

# Built-in functions that run text as code, or import by name.
FORBIDDEN_BUILTINS = {"eval", "exec", "compile", "__import__"}

# Built-ins that choose an attribute by name. They are fine with a fixed word and forbidden with a
# name that could come from outside, because that is how "unsafe reflection" starts.
DYNAMIC_ATTRIBUTE_BUILTINS = {"getattr", "setattr", "delattr"}


# In plain English: reads one program's text and returns a list of plain sentences, one per forbidden
# thing it finds, each with the line number. An empty list means it is clean.
def find_forbidden(source, name="<code>"):
    tree = ast.parse(source)
    problems = []
    module_names = {}  # the name used in this file -> the real module (handles "import os as o")
    imported_functions = {}  # a name brought in with "from x import y" -> (x, y)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                real = alias.name
                module_names[alias.asname or alias.name.split(".")[0]] = real.split(".")[0]
                if real.split(".")[0] in FORBIDDEN_MODULES:
                    problems.append(f"{name}:{node.lineno}: imports forbidden module '{real}'")
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").split(".")[0]
            if module in FORBIDDEN_MODULES:
                problems.append(f"{name}:{node.lineno}: imports from forbidden module '{node.module}'")
            for alias in node.names:
                imported_functions[alias.asname or alias.name] = (module, alias.name)
                if (module, alias.name) in FORBIDDEN_CALLS:
                    problems.append(f"{name}:{node.lineno}: imports forbidden function '{module}.{alias.name}'")

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in FORBIDDEN_BUILTINS:
                problems.append(f"{name}:{node.lineno}: calls forbidden built-in '{func.id}'")
            elif func.id in DYNAMIC_ATTRIBUTE_BUILTINS:
                chosen = node.args[1] if len(node.args) > 1 else None
                if not (isinstance(chosen, ast.Constant) and isinstance(chosen.value, str)):
                    problems.append(f"{name}:{node.lineno}: '{func.id}' with a name that is not a fixed word")
            elif imported_functions.get(func.id) in FORBIDDEN_CALLS:
                module, function = imported_functions[func.id]
                problems.append(f"{name}:{node.lineno}: calls forbidden function '{module}.{function}'")
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            module = module_names.get(func.value.id, func.value.id)
            if (module, func.attr) in FORBIDDEN_CALLS:
                problems.append(f"{name}:{node.lineno}: calls forbidden function '{module}.{func.attr}'")
    return problems


def app_files():
    return sorted(APP.rglob("*.py"))


# In plain English: the real check. Every Python file in app/ must be clean.
@pytest.mark.owasp("A05", 77, 78, 88, 94, 95, 470)
@pytest.mark.owasp("A08", 426, 427, 502)
def test_application_code_contains_no_forbidden_calls():
    files = app_files()
    assert files, "no application files were found to check"
    problems = []
    for path in files:
        problems.extend(find_forbidden(path.read_text(encoding="utf-8"), f"app/{path.relative_to(APP).as_posix()}"))
    assert problems == [], "\n".join(problems)


# In plain English: the check must really be looking at the application. If the folder were missing or
# empty the test above would have nothing to complain about, so this makes sure the files it covers
# are the ones we expect to exist.
@pytest.mark.owasp("A05", 77, 78, 88, 94, 95, 470)
@pytest.mark.owasp("A08", 426, 427, 502)
def test_the_check_covers_the_real_application_files():
    names = {path.name for path in app_files()}
    assert {"main.py", "auth.py", "db.py"} <= names


# ---------------------------------------------------------------------------
# Self-tests: the check must complain about each forbidden thing, and stay quiet for good code.
# ---------------------------------------------------------------------------

BAD_PROGRAMS = {
    "import of subprocess": "import subprocess\n",
    "import subprocess with a nickname": "import subprocess as sp\nsp.run(['ls'])\n",
    "from subprocess import": "from subprocess import run\n",
    "os.system": "import os\nos.system('ls')\n",
    "os.system with a nickname": "import os as o\no.system('ls')\n",
    "os.popen": "import os\nos.popen('ls')\n",
    "os exec family": "import os\nos.execv('/bin/sh', ['sh'])\n",
    "os function brought in by name": "from os import system\nsystem('ls')\n",
    "eval": "eval('1 + 1')\n",
    "exec": "exec('x = 1')\n",
    "compile": "compile('1', 'f', 'eval')\n",
    "__import__": "__import__('os')\n",
    "importlib": "import importlib\nimportlib.import_module('os')\n",
    "pickle": "import pickle\npickle.loads(b'')\n",
    "marshal": "import marshal\n",
    "shelve": "import shelve\n",
    "ctypes": "import ctypes\n",
    "yaml.load": "import yaml\nyaml.load('a: 1')\n",
    "yaml.unsafe_load": "import yaml\nyaml.unsafe_load('a: 1')\n",
    "getattr with a variable name": "def f(x, name):\n    return getattr(x, name)\n",
    "setattr with a computed name": "def f(x, a):\n    setattr(x, 'p' + a, 1)\n",
    "getattr with only one argument": "def f(x):\n    return getattr(x)\n",
    "a forbidden call inside a function": "def f():\n    import os\n    os.system('ls')\n",
    "a forbidden call inside a class": "class A:\n    def f(self):\n        eval('1')\n",
}

GOOD_PROGRAMS = {
    "yaml.safe_load": "import yaml\nyaml.safe_load('a: 1')\n",
    "getattr with a fixed word": "def f(x):\n    return getattr(x, 'name')\n",
    "plain os use": "import os\nvalue = os.environ.get('A')\npath = os.path.join('a', 'b')\n",
    "the word in a comment": "# we never call eval or subprocess or os.system here\nx = 1\n",
    "the word in a string": "message = 'do not use eval or pickle'\n",
    "a method called eval on something else": "class A:\n    def eval(self):\n        return 1\nA().eval()\n",
    "json": "import json\njson.loads('{}')\n",
}


@pytest.mark.owasp("A05", 77, 78, 88, 94, 95, 470)
@pytest.mark.owasp("A08", 426, 427, 502)
def test_every_bad_program_is_caught():
    for label, source in BAD_PROGRAMS.items():
        assert find_forbidden(source), f"not caught: {label}"


@pytest.mark.owasp("A05", 77, 78, 88, 94, 95, 470)
def test_every_good_program_passes():
    for label, source in GOOD_PROGRAMS.items():
        assert find_forbidden(source) == [], f"wrongly flagged: {label}: {find_forbidden(source)}"


@pytest.mark.owasp("A05", 77, 78, 88, 94, 95, 470)
def test_a_problem_names_the_line():
    problems = find_forbidden("x = 1\ny = 2\neval('1')\n", "app/x.py")
    assert problems == ["app/x.py:3: calls forbidden built-in 'eval'"]
