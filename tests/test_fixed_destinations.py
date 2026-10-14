# In plain English: a guardrail that keeps this service from ever reaching a place chosen by someone else. A message or a request must
# never be able to pick the address the service connects to, or the Kafka topic it reads or writes.
#
# HOW IT WORKS. This service makes no web call at all, and its Kafka calls are few. So this test does not try to prove that arbitrary
# Python goes to a fixed place (that is an arms race with whoever writes the next trick). It bans every web library and every web
# sending method, and it PINS the Kafka calls exactly:
#   - only the files listed in KAFKA_FILES may call produce or subscribe, and nothing else that talks to Kafka (assign, seek, consume);
#   - produce(TOPIC_NAME, key=, value=, headers=, on_delivery=) takes ONE positional topic, which must be a text constant bound
#     exactly once at the top of the file (or, where listed in TOPIC_PARAMETER_FUNCTIONS, an unchanged parameter of that function
#     whose callers may only pass such a constant), and only named keywords: no keyword topic, no *args, no **kwargs;
#   - subscribe([TOPIC_NAME]) takes one list holding one such constant;
#   - getattr/setattr/delattr/globals/locals/vars, `import *` and a few dunder attributes are banned everywhere, because each is a way
#     around everything above.
# The "bound exactly once" rule is checked against every way Python can bind a name (a table of binding forms, the language's own
# list of syntax kinds that carry a name, and Python's own symbol table).
# Why it matters: if a request or message could pick the address or the topic, an attacker could make the service call an internal
# system, leak data to their own server or read someone else's topic (OWASP A05 CWE-610, and the server-side request forgery family in A01).
import ast
import textwrap
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parent.parent / "app"

OUTBOUND_MODULES = {
    "requests", "httpx", "urllib", "urllib3", "http", "socket", "aiohttp", "websockets", "ftplib", "smtplib",
    "telnetlib", "xmlrpc", "poplib", "imaplib", "paramiko", "grpc",
}
# Methods that send over a web client. This service has no web client, so none may appear anywhere.
SENDING_NAMES = {"post", "put", "patch", "delete", "request", "stream", "send", "build_request"}
# The files that may talk to Kafka.
KAFKA_FILES = {"results_consumer.py", "sender.py"}
TOPIC_CALLS = {"produce", "subscribe", "assign", "seek", "consume"}
# Functions through which a topic reaches the one produce call as a parameter (empty when every produce call names its constant).
TOPIC_PARAMETER_FUNCTIONS = {"send_batch", "run"}
# The one place a **keywords expansion into those functions is allowed: (file, the function it is in, the function it calls).
FORWARDERS = {("sender.py", "run", "send_batch")}
DANGEROUS_CALLS = {"getattr", "setattr", "delattr", "globals", "locals", "vars"}
DANGEROUS_ATTRIBUTES = {"__dict__", "__getattribute__", "__globals__", "__builtins__", "__import__", "__class__"}
PRODUCE_KEYWORDS = {"key", "value", "headers", "on_delivery"}

# In plain English: every name that ONE piece of code binds, meaning gives a value to, declares, imports, defines or deletes.
# This list is Python's own: it covers every syntax tree node type that can carry a name (a test below checks the list against the
# language itself, so a new kind of binding added by a future Python makes a test fail instead of slipping by).
def names_bound_by(node):
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return {node.id}  # =, :=, +=, for, with ... as, comprehensions, del, tuple and star unpacking
    if isinstance(node, ast.arg):
        return {node.arg}  # every parameter of a def or a lambda, including *args, **kwargs, keyword-only and positional-only
    if isinstance(node, ast.ExceptHandler):
        return {node.name} if node.name else set()  # except ... as name, except* ... as name
    if isinstance(node, ast.alias):
        return {(node.asname or node.name).split(".")[0]}  # import x, import x as y, from x import y [as z]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, (ast.MatchAs, ast.MatchStar)):
        return {node.name} if node.name else set()
    if isinstance(node, ast.MatchMapping):
        return {node.rest} if node.rest else set()
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return set(node.names)  # declaring that a name is rebound from inside a function is itself a re-binding
    if type(node).__name__ in ("TypeVar", "ParamSpec", "TypeVarTuple"):
        return {node.name}  # def f[NAME](): ...  and  class C[NAME]: ...
    return set()


# In plain English: true if the name is bound exactly once in the whole file, and that one binding is a text written at the top
# of the file (`NAME = "..."` or `NAME: str = "..."`).
def is_a_text_constant_bound_once(tree, name):
    top_level_texts = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            top_level_texts += [target for target in node.targets if isinstance(target, ast.Name) and target.id == name]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            top_level_texts.append(node.target)
    bindings = sum(1 for node in ast.walk(tree) if name in names_bound_by(node))
    return len(top_level_texts) == 1 and bindings == 1



# In plain English: true only for the web framework's route declaration, `@app.post("/x", status_code=201)`: the attribute is the thing
# being called and that call is a decorator of a function. A route declaration only declares; it sends nothing. (A request hidden
# inside the decorator's arguments would need a sending method of its own, which is flagged on its own.)
def is_a_decorator(node, parents):
    call = parents.get(node)
    if not (isinstance(call, ast.Call) and call.func is node):
        return False
    holder = parents.get(call)
    return isinstance(holder, (ast.FunctionDef, ast.AsyncFunctionDef)) and call in holder.decorator_list


def enclosing_function(node, parents):
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    return None


# In plain English: checks every Kafka call in a file, and returns plain sentences, one per problem.
def kafka_problems(tree, name):
    problems = []
    base = name.rsplit("/", 1)[-1]
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in TOPIC_CALLS - {"produce", "subscribe"}:
            problems.append(f"{name}:{node.lineno}: '{node.attr}' is not a Kafka call this service may make")
    for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "produce"]:
        function = enclosing_function(call, parents)
        topic = call.args[0] if call.args else None
        by_constant = isinstance(topic, ast.Name) and is_a_text_constant_bound_once(tree, topic.id)
        by_parameter = False
        if isinstance(topic, ast.Name) and function is not None and function.name in TOPIC_PARAMETER_FUNCTIONS:
            arguments = function.args
            parameters = {a.arg for a in arguments.posonlyargs + arguments.args + arguments.kwonlyargs}
            rebound = set()
            for statement in function.body:
                for part in ast.walk(statement):
                    rebound |= names_bound_by(part)
            by_parameter = topic.id in parameters and topic.id not in rebound
        shape_ok = len(call.args) == 1 and (by_constant or by_parameter) and all(keyword.arg in PRODUCE_KEYWORDS for keyword in call.keywords)
        if not shape_ok:
            problems.append(f"{name}:{call.lineno}: produce must be produce(NAME, key=, value=, headers=, on_delivery=) with NAME a text constant bound once")
    for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "subscribe"]:
        topics = call.args[0] if call.args else None
        shape_ok = (
            len(call.args) == 1 and not call.keywords and isinstance(topics, ast.List) and len(topics.elts) == 1
            and isinstance(topics.elts[0], ast.Name) and is_a_text_constant_bound_once(tree, topics.elts[0].id)
        )
        if not shape_ok:
            problems.append(f"{name}:{call.lineno}: subscribe must be subscribe([NAME]) with NAME a text constant bound once")
    # callers of the functions that take the topic as a parameter may only pass a constant bound once (or nothing, for the default)
    for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
        callee = call.func.id if isinstance(call.func, ast.Name) else call.func.attr if isinstance(call.func, ast.Attribute) else None
        if callee not in TOPIC_PARAMETER_FUNCTIONS:
            continue
        function = enclosing_function(call, parents)
        forwarding = function is not None and (base, function.name, callee) in FORWARDERS
        for keyword in call.keywords:
            if keyword.arg is None and not forwarding:
                problems.append(f"{name}:{call.lineno}: '{callee}' is called with **keywords, which could carry a topic")
            if keyword.arg == "topic" and not (isinstance(keyword.value, ast.Name) and is_a_text_constant_bound_once(tree, keyword.value.id)):
                problems.append(f"{name}:{call.lineno}: the topic given to '{callee}' is not a text constant bound once")
        if any(isinstance(argument, ast.Starred) for argument in call.args):
            problems.append(f"{name}:{call.lineno}: '{callee}' is called with *arguments, which could carry a topic")
    return problems


# In plain English: reads one program's text and returns plain sentences, one per problem, each with its line number.
def find_unfixed_destinations(source, name="<code>"):
    tree = ast.parse(source)
    base = name.rsplit("/", 1)[-1]
    problems = []
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in OUTBOUND_MODULES:
                    problems.append(f"{name}:{node.lineno}: imports '{alias.name}', which opens connections to other machines")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in OUTBOUND_MODULES:
                problems.append(f"{name}:{node.lineno}: imports from '{node.module}', which opens connections to other machines")
            if any(alias.name == "*" for alias in node.names):
                problems.append(f"{name}:{node.lineno}: 'import *' can silently re-bind any name")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_CALLS:
            problems.append(f"{name}:{node.lineno}: calls '{node.func.id}', which can reach any name or attribute")
        elif isinstance(node, ast.Attribute):
            if node.attr in DANGEROUS_ATTRIBUTES:
                problems.append(f"{name}:{node.lineno}: uses '{node.attr}', which can reach any name or attribute")
            if node.attr in SENDING_NAMES and not is_a_decorator(node, parents):
                problems.append(f"{name}:{node.lineno}: '{node.attr}' sends over a web client, and this service has none")
            if node.attr in ("produce", "subscribe") and base not in KAFKA_FILES:
                problems.append(f"{name}:{node.lineno}: '{node.attr}' talks to Kafka, which only {sorted(KAFKA_FILES)} may do")
    problems += kafka_problems(tree, name)
    return problems


def app_files():
    return sorted(APP.rglob("*.py"))


# In plain English: the real check. Every Python file in app/ must be clean.
@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.owasp("A07", 941)
def test_application_code_reaches_only_fixed_destinations():
    files = app_files()
    assert files, "no application files were found to check"
    problems = []
    for path in files:
        problems.extend(find_unfixed_destinations(path.read_text(encoding="utf-8"), f"app/{path.relative_to(APP).as_posix()}"))
    assert problems == [], "\n".join(problems)


@pytest.mark.owasp("A05", 610)
def test_the_check_covers_the_real_application_files_and_the_real_kafka_calls():
    names = {path.name for path in app_files()}
    assert {"main.py", "auth.py", "db.py"} <= names and KAFKA_FILES <= names
    found = set()
    for path in app_files():
        text = path.read_text(encoding="utf-8")
        if ".produce(" in text or ".subscribe(" in text:
            found.add(path.name)
    assert found == KAFKA_FILES, "the list of Kafka files and the files that really call Kafka differ"


KAFKA_FILE = f"app/{sorted(KAFKA_FILES)[0]}"
KAFKA_PROGRAM = """\
TOPIC = "a-topic"
DEAD_LETTER_TOPIC = "a-topic.dead-letter"


def run(consumer, producer):
    consumer.subscribe([TOPIC])
@BODY@
"""
GOOD_PRODUCE = "    producer.produce(DEAD_LETTER_TOPIC, key=b'k', value=b'v', headers=[], on_delivery=None)"


def program(body):
    return KAFKA_PROGRAM.replace("@BODY@", body)


@pytest.mark.owasp("A05", 610)
def test_the_good_program_is_not_flagged():
    assert find_unfixed_destinations(program(GOOD_PRODUCE), KAFKA_FILE) == []


BAD_PRODUCES = {
    "a computed topic": "    producer.produce(message.topic(), key=b'k')",
    "a topic from a message": "    producer.produce(value.topic, key=b'k')",
    "a literal topic instead of the named constant": "    producer.produce('a-topic', key=b'k')",
    "a keyword topic": "    producer.produce(topic=value.topic, value=b'v')",
    "a keyword topic and a positional one": "    producer.produce(DEAD_LETTER_TOPIC, topic=value.topic)",
    "no topic argument": "    producer.produce(key=b'k', value=b'v')",
    "unpacked arguments": "    producer.produce(*value)",
    "unpacked keyword arguments": "    producer.produce(DEAD_LETTER_TOPIC, **value)",
    "an unknown keyword": "    producer.produce(DEAD_LETTER_TOPIC, partition=value.p)",
    "a topic that is an alias": "    t = value.topic\n    producer.produce(t, key=b'k')",
    "a topic that is an alias of the constant": "    t = DEAD_LETTER_TOPIC\n    producer.produce(t, key=b'k')",
    "a topic that is a parameter": "    producer.produce(topic, key=b'k')",
    "a constant that is rebound in the function": "    global DEAD_LETTER_TOPIC\n    DEAD_LETTER_TOPIC = value.topic\n    producer.produce(DEAD_LETTER_TOPIC)",
    "a constant rebound by a loop": "    for DEAD_LETTER_TOPIC in value:\n        producer.produce(DEAD_LETTER_TOPIC)",
    "assign": "    producer.assign(value.partitions)",
    "seek": "    producer.seek(value.position)",
    "consume": "    producer.consume(1)",
    "getattr on the producer": "    getattr(producer, 'produce')(value.topic)",
    "the dictionary of the producer": "    producer.__dict__['produce'](value.topic)",
    "globals": "    globals()['x'] = 1",
}


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A07", 941)
@pytest.mark.parametrize("label", sorted(BAD_PRODUCES))
def test_every_other_way_to_send_to_kafka_is_caught(label):
    source = program(BAD_PRODUCES[label])
    compile(source, label, "exec")
    assert find_unfixed_destinations(source, KAFKA_FILE) != [], f"not caught: {label}"


BAD_SUBSCRIBES = {
    "a second constant": "    consumer.subscribe([TOPIC, DEAD_LETTER_TOPIC])",
    "a computed topic": "    consumer.subscribe([job.topic])",
    "a keyword": "    consumer.subscribe(topics=[TOPIC])",
    "an alias": "    t = job.topic\n    consumer.subscribe([t])",
    "a literal": "    consumer.subscribe(['a-topic'])",
    "unpacked": "    consumer.subscribe(*job.topics)",
    "not a list": "    consumer.subscribe(TOPIC)",
    "a callback keyword": "    consumer.subscribe([TOPIC], on_assign=job.callback)",
    "a second positional argument": "    consumer.subscribe([TOPIC], job.callback)",
}


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A07", 941)
@pytest.mark.parametrize("label", sorted(BAD_SUBSCRIBES))
def test_every_other_way_to_subscribe_is_caught(label):
    source = KAFKA_PROGRAM.replace("    consumer.subscribe([TOPIC])\n", BAD_SUBSCRIBES[label] + "\n", 1).replace("@BODY@", GOOD_PRODUCE)
    compile(source, label, "exec")
    assert find_unfixed_destinations(source, KAFKA_FILE) != [], f"not caught: {label}"


@pytest.mark.owasp("A05", 610)
def test_kafka_calls_in_any_other_file_are_caught():
    for call in ("producer.produce(TOPIC)", "consumer.subscribe([TOPIC])", "consumer.seek(x)", "consumer.assign(x)", "consumer.consume(1)"):
        source = f"TOPIC = 'x'\ndef f(producer, consumer, x):\n    {call}\n"
        assert find_unfixed_destinations(source, "app/not_a_kafka_file.py") != [], call


TOPIC_FUNCTION = sorted(TOPIC_PARAMETER_FUNCTIONS)[0] if TOPIC_PARAMETER_FUNCTIONS else None


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A07", 941)
@pytest.mark.skipif(TOPIC_FUNCTION is None, reason="this service passes no topic as a parameter")
def test_a_topic_parameter_is_only_allowed_in_its_listed_function_unchanged_and_with_constant_callers():
    def sender(body, call="    NAME(producer, topic=TOPIC)"):
        text = f'TOPIC = "a-topic"\n\n\ndef NAME(producer, topic=TOPIC):\n{body}\n\n\ndef go(producer, job):\n{call}\n'
        return text.replace("NAME", TOPIC_FUNCTION)

    good = sender("    producer.produce(topic, key=b'k', value=b'v', on_delivery=None)")
    assert find_unfixed_destinations(good, KAFKA_FILE) == []
    assert find_unfixed_destinations(good.replace("def " + TOPIC_FUNCTION, "def other_name"), KAFKA_FILE) != []  # not the listed function
    assert find_unfixed_destinations(sender("    topic = producer.t\n    producer.produce(topic, key=b'k')"), KAFKA_FILE) != []
    assert find_unfixed_destinations(sender("    producer.produce(topic, key=b'k')", call="    NAME(producer, topic=job.topic)".replace("NAME", TOPIC_FUNCTION)), KAFKA_FILE) != []
    assert find_unfixed_destinations(sender("    producer.produce(topic, key=b'k')", call="    NAME(producer, **job.kw)".replace("NAME", TOPIC_FUNCTION)), KAFKA_FILE) != []
    assert find_unfixed_destinations(sender("    producer.produce(topic, key=b'k')", call="    NAME(*job.args)".replace("NAME", TOPIC_FUNCTION)), KAFKA_FILE) != []
    alias = sender("    producer.produce(topic, key=b'k')", call="    t = job.topic\n    NAME(producer, topic=t)".replace("NAME", TOPIC_FUNCTION))
    assert find_unfixed_destinations(alias, KAFKA_FILE) != []


SIMPLE_BAD = {
    "requests": "import requests\nrequests.get('http://x')\n",
    "requests with a nickname": "import requests as r\n",
    "from requests import": "from requests import get\n",
    "httpx": "import httpx\n",
    "httpx from": "from httpx import Client\n",
    "urllib.request": "import urllib.request\n",
    "from urllib import": "from urllib import request\n",
    "http.client": "import http.client\n",
    "socket": "import socket\n",
    "smtplib": "import smtplib\n",
    "aiohttp": "import aiohttp\n",
    "star import": "from os import *\n",
    "getattr": "def f(o, n):\n    return getattr(o, n)\n",
    "getattr with a fixed word": "def f(o):\n    return getattr(o, 'post')\n",
    "setattr": "def f(o):\n    setattr(o, 'x', 1)\n",
    "delattr": "def f(o):\n    delattr(o, 'x')\n",
    "globals": "def f():\n    return globals()\n",
    "locals": "def f():\n    return locals()\n",
    "vars": "def f(o):\n    return vars(o)\n",
    "the dictionary of an object": "def f(o):\n    return o.__dict__\n",
    "the class of an object": "def f(o):\n    return o.__class__\n",
    "the built-ins": "def f(o):\n    return o.__builtins__\n",
    "the globals of a function": "def f(o):\n    return o.__globals__\n",
    "a sending method": "def f(c, u):\n    c.post(u)\n",
    "a request hidden inside a decorator argument": "@app.post(c.post(u))\ndef f(c, u):\n    pass\n",
    "a request hidden inside another decorator": "@wrap(c.post(u))\ndef f(c, u):\n    pass\n",
    "a sending call in a return annotation": "def f() -> c.post('/x'):\n    pass\n",
    "a sending call in a default value": "def f(a=c.post('/x')):\n    pass\n",
    "a sending method used as a bare decorator": "@c.post\ndef f(c, u):\n    pass\n",
    "a sending method passed as a decorator argument": "@route(c.post)\ndef f(c, u):\n    pass\n",
    "a sending method passed as a decorator keyword": "@route(handler=c.post)\ndef f(c, u):\n    pass\n",
    "a sending call on a class decorator": "@c.post('/x')\nclass A:\n    pass\n",
    "a sending method called after the definition": "def f(c, u):\n    pass\n\nc.post('/x')\n",
    "a sending method with a fixed address": "def f(c):\n    c.post('/x')\n",
    "a sending method with a keyword address": "def f(c, m):\n    c.post(url=m.url)\n",
    "request": "def f(c, m):\n    c.request('GET', m.url)\n",
    "stream": "def f(c, m):\n    c.stream('POST', m.url)\n",
}
SIMPLE_GOOD = {
    "the database driver": "import psycopg\n",
    "the kafka client": "from confluent_kafka import Consumer\n",
    "the word in a comment": "# we never import requests or socket here\nx = 1\n",
    "the word in a string": "text = 'import requests'\n",
    "an ordinary dictionary lookup": "def f(d, k):\n    return d.get(k)\n",
    "a settings lookup": "def f(environment):\n    return environment.get('X')\n",
    "an ordinary method": "def f(o):\n    return o.close()\n",
    "a route declaration": "@app.post('/x')\ndef f():\n    pass\n",
    "a route declaration with a status code": "@app.post('/x', status_code=201)\ndef f():\n    pass\n",
    "a route declaration with a model": "@app.delete('/x', response_model=Thing)\ndef f():\n    pass\n",
    "an async route declaration": "@app.put('/x')\nasync def f():\n    pass\n",
    "importing a name": "from os import path\n",
}


@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize("label", sorted(SIMPLE_BAD))
def test_every_banned_construct_is_caught_in_any_file(label):
    assert find_unfixed_destinations(SIMPLE_BAD[label], "app/other.py") != [], f"not caught: {label}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize("label", sorted(SIMPLE_GOOD))
def test_ordinary_code_is_not_flagged(label):
    assert find_unfixed_destinations(SIMPLE_GOOD[label], "app/other.py") == [], f"wrongly flagged: {label}"


@pytest.mark.owasp("A05", 610)
def test_a_problem_names_the_line():
    problems = find_unfixed_destinations("x = 1\ny = 2\nimport socket\n", "app/x.py")
    assert problems and problems[0].startswith("app/x.py:3:")


# ---------------------------------------------------------------------------
# The "bound exactly once" rule is only as good as the list of ways Python can bind a name. These tests check that list against the
# language itself.
# ---------------------------------------------------------------------------

# (label, the binding written inside the function body). NAME is replaced by the name under test.
BINDING_FORMS = [
    ("assignment", "NAME = m.url"),
    ("tuple unpacking", "NAME, other = m.pair"),
    ("parenthesised unpacking", "(NAME, other) = m.pair"),
    ("list unpacking", "[NAME, other] = m.pair"),
    ("starred unpacking", "*NAME, other = m.items"),
    ("nested unpacking", "(other, (NAME, more)) = m.pair"),
    ("chained assignment", "other = NAME = m.url"),
    ("annotated assignment", "NAME: str = m.url"),
    ("augmented assignment", "NAME += m.suffix"),
    ("for loop", "for NAME in items:\n    pass"),
    ("for loop over a tuple", "for (NAME, other) in items:\n    pass"),
    ("with statement", "with m.open() as NAME:\n    pass"),
    ("with statement, tuple", "with m.open() as (NAME, other):\n    pass"),
    ("except handler", "try:\n    m.go()\nexcept ValueError as NAME:\n    pass"),
    ("except-star handler", "try:\n    m.go()\nexcept* ValueError as NAME:\n    pass"),
    ("import", "import NAME"),
    ("import dotted", "import NAME.sub"),
    ("import as", "import os.path as NAME"),
    ("from import", "from os import NAME"),
    ("from import as", "from os import path as NAME"),
    ("def", "def NAME():\n    pass"),
    ("async def", "async def NAME():\n    pass"),
    ("class", "class NAME:\n    pass"),
    ("walrus", "(NAME := m.url)"),
    ("list comprehension target", "[0 for NAME in items]"),
    ("set comprehension target", "{0 for NAME in items}"),
    ("dict comprehension target", "{0: 0 for NAME in items}"),
    ("generator target", "(0 for NAME in items)"),
    ("delete", "del NAME"),
    ("global declaration", "global NAME"),
    ("lambda parameter", "f = lambda NAME: 0"),
    ("lambda star parameter", "f = lambda *NAME: 0"),
    ("lambda double-star parameter", "f = lambda **NAME: 0"),
    ("lambda keyword-only parameter", "f = lambda *, NAME: 0"),
    ("nested def parameter", "def inner(NAME):\n    pass"),
    ("nested def star parameter", "def inner(*NAME):\n    pass"),
    ("nested def double-star parameter", "def inner(**NAME):\n    pass"),
    ("nested def keyword-only parameter", "def inner(*, NAME):\n    pass"),
    ("nested def positional-only parameter", "def inner(NAME, /):\n    pass"),
    ("nested def default value parameter", "def inner(NAME=1):\n    pass"),
    ("match capture", "match m.x:\n    case NAME:\n        pass"),
    ("match as", "match m.x:\n    case str() as NAME:\n        pass"),
    ("match star", "match m.x:\n    case [*NAME]:\n        pass"),
    ("match mapping rest", "match m.x:\n    case {'a': 1, **NAME}:\n        pass"),
    ("match class capture", "match m.x:\n    case str(NAME):\n        pass"),
    ("type alias", "type NAME = int"),
    ("generic def type parameter", "def inner[NAME]():\n    pass"),
    ("generic def paramspec", "def inner[**NAME]():\n    pass"),
    ("generic def typevartuple", "def inner[*NAME]():\n    pass"),
    ("generic class type parameter", "class Inner[NAME]:\n    pass"),
]
SIGNATURE_FORMS = [
    ("parameter", "NAME"),
    ("star parameter", "*NAME"),
    ("double-star parameter", "**NAME"),
    ("keyword-only parameter", "*, NAME"),
    ("positional-only parameter", "NAME, /"),
    ("parameter with a default", "NAME=1"),
]
# `global` for a name that is a parameter is a SyntaxError in Python itself, so that one row cannot apply to a parameter.
PARAMETER_FORMS = [form for form in BINDING_FORMS if form[0] != "global declaration"]



@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A07", 941)
@pytest.mark.parametrize("label, binding", BINDING_FORMS, ids=[label for label, _ in BINDING_FORMS])
def test_every_way_of_binding_a_topic_constant_is_caught_wherever_it_sits(label, binding):
    def with_binding(layout):
        indented = textwrap.indent(binding.replace("NAME", "DEAD_LETTER_TOPIC"), "    ")
        lines = {
            "before": f"{indented}\n{GOOD_PRODUCE}",
            "after": f"{GOOD_PRODUCE}\n{indented}",
            "middle": f"    first = 1\n{indented}\n{GOOD_PRODUCE}\n    last = 2",
        }[layout]
        return program(lines)

    # Python refuses `global NAME` after NAME has been used, so that one form is only tried where it comes first.
    for layout in ("before", "middle") if label == "global declaration" else ("before", "after", "middle"):
        source = with_binding(layout)
        compile(source, label, "exec")
        assert find_unfixed_destinations(source, KAFKA_FILE) != [], f"not caught: {label}, {layout}"
    elsewhere = program(GOOD_PRODUCE) + "\n\ndef other(m, items):\n" + textwrap.indent(binding.replace("NAME", "DEAD_LETTER_TOPIC"), "    ") + "\n"
    compile(elsewhere, label, "exec")
    assert find_unfixed_destinations(elsewhere, KAFKA_FILE) != [], f"not caught in another function: {label}"
    control = program("    pass\n" + GOOD_PRODUCE)
    assert find_unfixed_destinations(control, KAFKA_FILE) == [], f"the control wrongly fails: {label}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize("label, binding", BINDING_FORMS, ids=[label for label, _ in BINDING_FORMS])
def test_every_way_of_binding_the_subscribed_topic_is_caught(label, binding):
    source = program(GOOD_PRODUCE) + "\n\ndef other(m, items):\n" + textwrap.indent(binding.replace("NAME", "TOPIC"), "    ") + "\n"
    compile(source, label, "exec")
    assert find_unfixed_destinations(source, KAFKA_FILE) != [], f"not caught: {label}"


# In plain English: the table above must cover EVERY kind of syntax that can carry a name. This lists those kinds from the language
# itself. If a newer Python adds one, or the scanner stops covering one, this fails and says which.
@pytest.mark.owasp("A05", 610)
def test_the_binding_table_covers_every_syntax_kind_that_can_carry_a_name():
    fields = {"name", "asname", "arg", "vararg", "kwarg", "rest", "optional_vars", "target", "targets", "names"}
    in_the_language = {
        cls.__name__
        for cls in vars(ast).values()
        if isinstance(cls, type) and issubclass(cls, ast.AST) and fields & set(getattr(cls, "_fields", ()))
    }
    accounted_for = {
        # each of these binds a name, and has rows in BINDING_FORMS or SIGNATURE_FORMS
        "Assign", "AnnAssign", "AugAssign", "For", "AsyncFor", "comprehension", "withitem", "ExceptHandler", "alias", "Import",
        "ImportFrom", "FunctionDef", "AsyncFunctionDef", "ClassDef", "arguments", "arg", "NamedExpr", "Delete", "Global",
        "Nonlocal", "MatchAs", "MatchStar", "MatchMapping", "TypeAlias", "TypeVar", "ParamSpec", "TypeVarTuple",
        # this one carries a name but binds nothing: it is the name of a keyword argument in a call, f(name=value)
        "keyword",
    }
    assert in_the_language == accounted_for, (in_the_language ^ accounted_for)


# In plain English: names_bound_by must agree with Python's own record of which names a program binds. Python's symbol table lists,
# for every scope, the names that are assigned, are parameters, are imported or are defined as a function or class. The scanner
# must report every one of them.
@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize("label, binding", BINDING_FORMS, ids=[label for label, _ in BINDING_FORMS])
def test_the_scanner_agrees_with_pythons_own_symbol_table(label, binding):
    import symtable

    body = "def g(m, items):\n" + textwrap.indent(binding.replace("NAME", "NAME"), "    ") + "\n"
    source = "TARGET = 1\n" + body
    scanner_bound = set()
    for node in ast.walk(ast.parse(source)):
        scanner_bound |= names_bound_by(node)

    def python_bound(table):
        names = {
            symbol.get_name()
            for symbol in table.get_symbols()
            if symbol.is_assigned() or symbol.is_parameter() or symbol.is_imported() or symbol.is_namespace() or symbol.is_declared_global()
        }
        for child in table.get_children():
            names |= python_bound(child)
        return names

    assert "NAME" in python_bound(symtable.symtable(source, "<test>", "exec")), f"the row does not really bind the name: {label}"
    assert "NAME" in scanner_bound, f"the scanner misses a binding Python reports: {label}"

