# In plain English: tests that read the application code and fail if error handling gets sloppy. A program
# that catches every error and carries on, or that swallows an error without doing anything, hides real
# problems and can leave things half done. These tests walk the code in app/ and refuse:
#   - a bare "except:" and a catch of "Exception" anywhere except the two places that must have one (CWE-396)
#   - a handler that does nothing with the error, such as "except X: pass" (CWE-390 and 391)
#   - a database connection opened without "with", or a Kafka reader without a "finally" that closes it,
#     because an error would then leave it open (CWE-460)
#   - debug leftovers: print, breakpoint, pdb, traceback, debug or reload switches, and logging that attaches
#     a traceback (CWE-215), in the code and in the Dockerfile and Kubernetes files
#
# Like the forbidden-calls test, it also proves itself: a list of deliberately bad programs must each be
# caught, and a list of good ones must not be.
import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"

# In plain English: the only places allowed to catch a generic Exception, with the reason.
#   db.py database_is_ready: a readiness check must answer True or False whatever goes wrong inside, and it
#   deliberately keeps the details out of the answer.
#   errors.py catch_everything: the catch-all that turns any unexpected error into a fixed reply and one safe
#   log line (tests/test_error_handling.py proves what it does).
ALLOWED_GENERIC = {("db.py", "database_is_ready"), ("errors.py", "catch_everything")}

# In plain English: the only handlers allowed to do "nothing" with an error, with the reason. Each is a
# handler for a UniqueViolation, which here means "another worker saved the same version number a moment
# earlier". That is expected, not a fault: the code then looks again (continue) or reads the row the other
# worker saved (pass). Anything else that swallows an error still fails.
#   (file, function, error caught)
ALLOWED_QUIET = {
    ("grades.py", "record_grade", "UniqueViolation"),
    ("reviews.py", "record_review", "UniqueViolation"),
    ("submissions.py", "create_submission", "UniqueViolation"),
}

GENERIC_NAMES = {"Exception", "BaseException"}
DEBUG_SWITCHES = {"debug", "reload"}
BANNED_MODULES = {"pdb", "ipdb", "traceback"}
BANNED_CALLS = {"print", "breakpoint"}


# In plain English: true when a Kafka reader is created directly as an argument of run(...) and the run function in
# the same file closes its reader in a finally. Then run() owns the closing, which is what we want.
def handed_to_a_function_that_closes(call, parent, tree):
    outer = parent.get(call)
    if not (isinstance(outer, ast.Call) and isinstance(outer.func, ast.Name) and outer.func.id == "run" and call in outer.args):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "run":
            return any(
                isinstance(t, ast.Try) and any(isinstance(c, ast.Call) and getattr(c.func, "attr", "") == "close" for s in t.finalbody for c in ast.walk(s))
                for t in ast.walk(node)
            )
    return False


# In plain English: reads one Python file's text and returns a list of (rule, line) for every problem found.
# "filename" is the bare file name, used for the allow-list above.
def find_problems(source, filename, allowed=ALLOWED_GENERIC, quiet=ALLOWED_QUIET):
    tree = ast.parse(source)
    parent = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

    def function_of(node):
        while node in parent:
            node = parent[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node
        return None

    def caught_names(handler):
        kinds = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
        return {k.id if isinstance(k, ast.Name) else getattr(k, "attr", "") for k in kinds}

    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                problems.append(("bare except", node.lineno))
            elif caught_names(node) & GENERIC_NAMES:
                function = function_of(node)
                if (filename, function.name if function else None) not in allowed:
                    problems.append(("generic except", node.lineno))
            if all(isinstance(s, (ast.Pass, ast.Continue)) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) for s in node.body):
                function = function_of(node)
                names = caught_names(node) if node.type is not None else set()
                excused = len(names) == 1 and (filename, function.name if function else None, next(iter(names))) in quiet
                if not excused:
                    problems.append(("handler does nothing", node.lineno))
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            if name == "connect" and not (isinstance(parent.get(node), ast.withitem) and parent[node].context_expr is node):
                function = function_of(node)
                if not (filename == "db.py" and function and function.name == "connect"):
                    problems.append(("connection opened without with", node.lineno))
            if name == "Consumer" and not handed_to_a_function_that_closes(node, parent, tree):
                function = function_of(node)
                closes = function is not None and any(
                    isinstance(t, ast.Try) and any(isinstance(c, ast.Call) and getattr(c.func, "attr", "") == "close" for s in t.finalbody for c in ast.walk(s))
                    for t in ast.walk(function)
                )
                if not closes:
                    problems.append(("reader not closed in finally", node.lineno))
            if name in BANNED_CALLS and isinstance(node.func, ast.Name):
                problems.append(("debug leftover", node.lineno))
            if name == "exception" and isinstance(node.func, ast.Attribute):
                problems.append(("logging attaches a traceback", node.lineno))
            for keyword in node.keywords:
                if keyword.arg in DEBUG_SWITCHES and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    problems.append(("debug leftover", node.lineno))
                if keyword.arg == "exc_info":
                    problems.append(("logging attaches a traceback", node.lineno))
        if isinstance(node, ast.Import) and {alias.name.split(".")[0] for alias in node.names} & BANNED_MODULES:
            problems.append(("debug leftover", node.lineno))
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in BANNED_MODULES:
            problems.append(("debug leftover", node.lineno))
    return sorted(problems, key=lambda p: p[1])


def app_files():
    return sorted(APP.glob("*.py"))


# ---------- The real code ----------

@pytest.mark.owasp("A10", 396, 390, 391, 460)
@pytest.mark.owasp("A02", 489)
def test_application_code_has_no_sloppy_error_handling():
    files = app_files()
    assert files, "no application files were found to check"
    found = {path.name: find_problems(path.read_text(encoding="utf-8"), path.name) for path in files}
    assert {name: problems for name, problems in found.items() if problems} == {}


@pytest.mark.owasp("A10", 396)
def test_the_check_covers_the_real_application_files():
    names = {path.name for path in app_files()}
    assert {"main.py", "auth.py", "db.py", "errors.py"} <= names


@pytest.mark.owasp("A10", 396)
def test_every_allowed_generic_catch_still_exists_and_is_needed():
    # An entry that no longer matches real code would quietly allow a future catch-all in that spot.
    for filename, function in ALLOWED_GENERIC:
        source = (APP / filename).read_text(encoding="utf-8")
        without_allowance = find_problems(source, filename, allowed=set())
        assert ("generic except", next(line for rule, line in without_allowance if rule == "generic except")) in without_allowance, (filename, function)


# ---------- The check proves itself ----------

BAD = {
    "bare except": "def f():\n    try:\n        g()\n    except:\n        return 1\n",
    "generic except": "def f():\n    try:\n        g()\n    except Exception:\n        return 1\n",
    "generic except in a tuple": "def f():\n    try:\n        g()\n    except (ValueError, Exception):\n        return 1\n",
    "base exception": "def f():\n    try:\n        g()\n    except BaseException:\n        return 1\n",
    "generic except somewhere not allowed": "def other():\n    try:\n        g()\n    except Exception:\n        return 1\n",
    "handler does nothing": "def f():\n    try:\n        g()\n    except ValueError:\n        pass\n",
    "handler only continues": "def f():\n    for i in x:\n        try:\n            g()\n        except ValueError:\n            continue\n",
    "handler only has a comment-like string": "def f():\n    try:\n        g()\n    except ValueError:\n        'ignored'\n",
    "connection opened without with": "def f():\n    c = connect()\n    c.execute('x')\n",
    "connection through a module": "def f():\n    c = psycopg.connect('x')\n",
    "reader not closed": "def f():\n    c = Consumer({})\n    c.poll(1)\n",
    "reader closed outside finally": "def f():\n    c = Consumer({})\n    try:\n        c.poll(1)\n    except ValueError:\n        return 1\n    c.close()\n",
    "print": "def f():\n    print('x')\n",
    "breakpoint": "def f():\n    breakpoint()\n",
    "pdb import": "import pdb\n",
    "traceback import": "from traceback import print_exc\n",
    "debug switch": "app = FastAPI(debug=True)\n",
    "reload switch": "uvicorn.run('x', reload=True)\n",
    "logging with a traceback": "def f():\n    log.error('x', exc_info=True)\n",
    "logging.exception": "def f():\n    try:\n        g()\n    except ValueError:\n        log.exception('x')\n",
}

GOOD = {
    "specific catches": "def f():\n    try:\n        g()\n    except (ValueError, KeyError):\n        return 1\n",
    "a handler that acts": "def f():\n    try:\n        g()\n    except ValueError as e:\n        log.warning('x %s', type(e).__name__)\n        raise\n",
    "connection with with": "def f():\n    with connect() as c:\n        c.execute('x')\n",
    "reader closed in finally": "def f():\n    c = Consumer({})\n    try:\n        c.poll(1)\n    finally:\n        c.close()\n",
    "debug off": "app = FastAPI(debug=False)\n",
}


@pytest.mark.owasp("A10", 396, 390, 391, 460, 215)
@pytest.mark.parametrize("label", sorted(BAD))
def test_every_bad_program_is_caught(label):
    assert find_problems(BAD[label], "somefile.py"), label


@pytest.mark.owasp("A10", 396, 390, 391, 460, 215)
@pytest.mark.parametrize("label", sorted(GOOD))
def test_good_programs_are_not_flagged(label):
    assert find_problems(GOOD[label], "somefile.py") == []


@pytest.mark.owasp("A10", 396)
def test_the_two_allowed_places_are_allowed_only_in_their_own_file_and_function():
    source = "def database_is_ready():\n    try:\n        g()\n    except Exception:\n        return False\n"
    assert find_problems(source, "db.py") == []
    assert find_problems(source, "other.py") != []
    assert find_problems(source.replace("database_is_ready", "something_else"), "db.py") != []


@pytest.mark.owasp("A10", 390, 391)
def test_a_quiet_unique_violation_handler_is_allowed_only_in_its_own_function():
    source = "def record_grade():\n    try:\n        g()\n    except UniqueViolation:\n        continue\n"
    assert find_problems(source, "grades.py") == []
    assert find_problems(source, "other.py") != []
    assert find_problems(source.replace("record_grade", "elsewhere"), "grades.py") != []
    assert find_problems(source.replace("UniqueViolation", "DataError"), "grades.py") != []
    assert find_problems(source.replace("UniqueViolation", "(UniqueViolation, DataError)"), "grades.py") != []


@pytest.mark.owasp("A10", 390, 391)
def test_every_allowed_quiet_handler_still_exists_and_is_needed():
    # Only the files that exist in this repo are checked; an entry for a file this repo lacks is skipped.
    present = [(f, fn, err) for f, fn, err in ALLOWED_QUIET if (APP / f).exists()]
    for filename, function, error in present:
        source = (APP / filename).read_text(encoding="utf-8")
        assert any(rule == "handler does nothing" for rule, _ in find_problems(source, filename, quiet=set())), (filename, function)


@pytest.mark.owasp("A10", 460)
def test_a_reader_handed_to_run_is_fine_only_when_run_closes_it():
    closes = "def run(c, p):\n    try:\n        c.poll(1)\n    finally:\n        c.close()\n\n\ndef main():\n    run(Consumer({}), 1)\n"
    assert find_problems(closes, "somefile.py") == []
    forgets = closes.replace("        c.close()\n", "        pass\n")
    assert find_problems(forgets, "somefile.py") != []
    other = closes.replace("run(Consumer({}), 1)", "go(Consumer({}), 1)")
    assert find_problems(other, "somefile.py") != []


@pytest.mark.owasp("A10", 396)
def test_db_py_may_open_a_connection_only_inside_its_own_connect_function():
    source = "def connect():\n    return psycopg.connect('x')\n"
    assert find_problems(source, "db.py") == []
    assert find_problems(source, "examples.py") != []
    assert find_problems("def other():\n    return psycopg.connect('x')\n", "db.py") != []


# ---------- Debug leftovers in the deploy files ----------

@pytest.mark.owasp("A10", 215)
@pytest.mark.owasp("A02", 489)
def test_the_dockerfile_and_kubernetes_files_switch_no_debug_or_reload_on():
    files = [ROOT / "Dockerfile", *sorted((ROOT / "k8s").rglob("*.y*ml")), *sorted((ROOT / "k8s").rglob("*.sh"))]
    files = [f for f in files if f.exists()]
    assert len(files) >= 3
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            lowered = line.lower()
            assert "--reload" not in lowered, f"{path.name}:{number}"
            assert "debug" not in lowered or "false" in lowered, f"{path.name}:{number}: {line.strip()}"


@pytest.mark.owasp("A10", 215)
@pytest.mark.owasp("A02", 489)
def test_the_running_app_is_not_in_debug_mode():
    from app.main import app

    assert app.debug is False
