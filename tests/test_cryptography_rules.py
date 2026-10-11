# In plain English: a guardrail that keeps the application's use of cryptography (hashing, encryption, random
# numbers, certificates) to the small set of safe things it uses today, so nobody can add a weak or home-made
# one by accident. Today the Python code does exactly three things: it compares keys with hmac.compare_digest
# (in auth.py only), it makes random identifiers with uuid4, and it reads secrets from files. The database
# uses one hash (SHA-256, to fingerprint a submission) and random uuids made by the database.
#
# Anything else, a second hashing library, the "random" module, a switched-off certificate check, a counter used
# as an identifier, an old hash like MD5, turns this test red. Adding something new is then a deliberate change
# to this file, made in a pull request that someone reads, never a quiet edit.
#
# It reads the program text (it never runs it) and the real structure of the code, so a word in a comment or a
# string does not trigger it and renaming an import does not hide it. Its own tests at the bottom feed it small
# bad and good programs, so the check cannot pass by never finding anything.
#
# Why it matters (OWASP A04, cryptographic failures): weak or hand-made algorithms (CWE-327, 328, 326, 1240, 757,
# 780, 329, 323, 325, 347), weak or predictable random values and identifiers (CWE-330 to 342, 1241) and switched-off
# certificate checks (CWE-296). There are no user passwords here, so password hashing (CWE-261, 759, 760, 916) cannot
# arise, and this test keeps it that way by banning the hashing libraries it would need.
import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"
DATABASE = ROOT / "db"

# Modules that are never imported: they hash, encrypt, sign, or make random numbers that can be predicted.
# ("secrets" and "uuid" are allowed: they use the operating system's secure random source.)
BANNED_MODULES = {
    "hashlib", "random", "ssl", "crypt",
    "cryptography", "Crypto", "Cryptodome", "nacl", "OpenSSL", "M2Crypto", "pyaes", "rsa", "ecdsa",
    "jwt", "jose", "authlib", "itsdangerous", "passlib", "bcrypt", "argon2", "scrypt", "pyotp",
}
# hmac is allowed only in these files, and only for compare_digest.
HMAC_FILES = {"auth.py"}
ALLOWED_HMAC_FUNCTIONS = {"compare_digest"}
# Old or time-based uuid kinds are predictable; only uuid4 (random) is allowed.
BANNED_UUID_FUNCTIONS = {"uuid1", "uuid3", "uuid5", "getnode"}
# Names that mean "do not check the certificate".
BANNED_CERTIFICATE_NAMES = {"CERT_NONE", "CERT_OPTIONAL", "_create_unverified_context", "_create_default_https_context"}
INSECURE_SSLMODE = re.compile(r"sslmode\s*=\s*['\"]?(disable|allow|prefer)\b")


def _line(name, node, message):
    return f"{name}:{node.lineno}: {message}"


# In plain English: reads one program's text and returns a list of plain sentences, one per problem, each with
# the line number. An empty list means it is clean.
def find_crypto_problems(source, name="app/x.py"):
    tree = ast.parse(source)
    base = name.rsplit("/", 1)[-1]
    problems = []
    module_names = {}  # the name used in this file -> the real module ("import uuid as u" gives {"u": "uuid"})
    from_names = {}  # a name brought in with "from x import y" -> (x, y)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                module_names[alias.asname or root] = root
                if root in BANNED_MODULES:
                    problems.append(_line(name, node, f"imports banned cryptography module '{alias.name}'"))
                if root == "hmac" and base not in HMAC_FILES:
                    problems.append(_line(name, node, "imports hmac outside the one file allowed to"))
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in BANNED_MODULES:
                problems.append(_line(name, node, f"imports from banned cryptography module '{node.module}'"))
            if root == "hmac" and base not in HMAC_FILES:
                problems.append(_line(name, node, "imports hmac outside the one file allowed to"))
            for alias in node.names:
                from_names[alias.asname or alias.name] = (root, alias.name)
                if root == "uuid" and alias.name in BANNED_UUID_FUNCTIONS:
                    problems.append(_line(name, node, f"imports banned uuid function '{alias.name}'"))
                if root == "hmac" and alias.name not in ALLOWED_HMAC_FUNCTIONS:
                    problems.append(_line(name, node, f"imports hmac function '{alias.name}' (only compare_digest is allowed)"))
                if alias.name in BANNED_CERTIFICATE_NAMES:
                    problems.append(_line(name, node, f"imports certificate-check switch '{alias.name}'"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                module = module_names.get(func.value.id, func.value.id)
                if module == "uuid" and func.attr in BANNED_UUID_FUNCTIONS:
                    problems.append(_line(name, node, f"calls banned uuid function '{func.attr}'"))
                if module == "hmac" and func.attr not in ALLOWED_HMAC_FUNCTIONS:
                    problems.append(_line(name, node, f"calls hmac.{func.attr} (only compare_digest is allowed)"))
            elif isinstance(func, ast.Name):
                origin = from_names.get(func.id)
                if origin and origin[0] == "uuid" and origin[1] in BANNED_UUID_FUNCTIONS:
                    problems.append(_line(name, node, f"calls banned uuid function '{origin[1]}'"))
                if origin and origin[0] == "hmac" and origin[1] not in ALLOWED_HMAC_FUNCTIONS:
                    problems.append(_line(name, node, f"calls hmac.{origin[1]} (only compare_digest is allowed)"))
            for keyword in node.keywords:
                if keyword.arg in {"verify", "check_hostname"} and isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                    problems.append(_line(name, node, f"switches off certificate checking ({keyword.arg}=False)"))
                if keyword.arg == "sslmode" and isinstance(keyword.value, ast.Constant) and str(keyword.value.value) in {"disable", "allow", "prefer"}:
                    problems.append(_line(name, node, f"sets the weak database sslmode '{keyword.value.value}'"))
        elif isinstance(node, ast.Attribute):
            if node.attr in BANNED_CERTIFICATE_NAMES:
                problems.append(_line(name, node, f"uses certificate-check switch '{node.attr}'"))
        elif isinstance(node, ast.Name):
            if node.id in BANNED_CERTIFICATE_NAMES:
                problems.append(_line(name, node, f"uses certificate-check switch '{node.id}'"))
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr in {"check_hostname", "verify"} and isinstance(node.value, ast.Constant) and node.value.value is False:
                    problems.append(_line(name, node, f"switches off certificate checking ({target.attr} = False)"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and INSECURE_SSLMODE.search(node.value):
            problems.append(_line(name, node, "contains a weak database sslmode"))
    return problems


SQL_COMMENT = re.compile(r"--[^\n]*")
SQL_RULES = {
    "the md5 function": re.compile(r"\bmd5\s*\(", re.I),
    "the crypt function": re.compile(r"\bcrypt\s*\(", re.I),
    "gen_salt": re.compile(r"\bgen_salt\s*\(", re.I),
    "random()": re.compile(r"\brandom\s*\(", re.I),
    "setseed": re.compile(r"\bsetseed\s*\(", re.I),
    "a time-based or name-based uuid": re.compile(r"\buuid_generate_v(1|1mc|3|5)\s*\(", re.I),
    "database-side encryption functions": re.compile(r"\b(pgp_sym_|pgp_pub_|encrypt\s*\(|decrypt\s*\(|encrypt_iv|decrypt_iv)", re.I),
    "a counter used as an identifier": re.compile(r"\b(small|big)?serial\b|\bas\s+identity\b|\bnextval\s*\(|\bcreate\s+sequence\b", re.I),
}
STRONG_HASHES = {"sha256", "sha384", "sha512"}
DIGEST_CALL = re.compile(r"\b(digest|hmac)\s*\((?:[^()]|\([^()]*\))*?,\s*'([A-Za-z0-9]+)'\s*\)", re.S)


# In plain English: reads the text of one database file and returns one sentence per problem.
def find_sql_problems(text, name="db/x.sql"):
    code = SQL_COMMENT.sub("", text)
    problems = []
    for label, pattern in SQL_RULES.items():
        for match in pattern.finditer(code):
            line = code[: match.start()].count("\n") + 1
            problems.append(f"{name}:{line}: uses {label}")
    for match in DIGEST_CALL.finditer(code):
        if match.group(2).lower() not in STRONG_HASHES:
            line = code[: match.start()].count("\n") + 1
            problems.append(f"{name}:{line}: hashes with '{match.group(2)}' (only SHA-2 is allowed)")
    return problems


def app_files():
    return sorted(APP.rglob("*.py"))


def database_files():
    return sorted(path for path in DATABASE.rglob("*") if path.suffix in {".sql", ".yaml", ".yml", ".xml"})


@pytest.mark.owasp("A04", 327, 328, 326, 1240, 757, 780, 329, 323, 325, 347, 330, 331, 332, 334, 335, 336, 337, 338, 340, 342, 1241, 296, 261, 759, 760, 916)
def test_application_code_uses_no_unreviewed_cryptography():
    files = app_files()
    assert files, "no application files were found to check"
    problems = []
    for path in files:
        problems.extend(find_crypto_problems(path.read_text(encoding="utf-8"), f"app/{path.relative_to(APP).as_posix()}"))
    assert problems == [], "\n".join(problems)


@pytest.mark.owasp("A04", 327, 328, 326, 1240, 330, 338, 340, 342, 1241, 916)
def test_database_files_use_no_weak_hash_and_no_predictable_identifier():
    files = database_files()
    assert files, "no database files were found to check"
    problems = []
    for path in files:
        problems.extend(find_sql_problems(path.read_text(encoding="utf-8"), f"db/{path.relative_to(DATABASE).as_posix()}"))
    assert problems == [], "\n".join(problems)


@pytest.mark.owasp("A04", 327, 330, 340)
def test_the_checks_cover_the_real_files():
    # Proves the two tests above are not passing because they looked at nothing.
    assert {"main.py", "auth.py", "db.py"} <= {path.name for path in app_files()}
    assert "init.sql" in {path.name for path in database_files()}


@pytest.mark.owasp("A04", 327, 328, 330, 340)
def test_the_only_use_of_hmac_is_comparing_keys_in_auth():
    users = {}
    for path in app_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "hmac":
                users.setdefault(path.name, set()).add(node.attr)
    assert users == {"auth.py": {"compare_digest"}}


# ---------------------------------------------------------------------------
# Self-tests: the check must complain about each bad thing, and stay quiet for good code.
# ---------------------------------------------------------------------------
BAD_PROGRAMS = {
    "hashlib": "import hashlib\nhashlib.md5(b'x')\n",
    "hashlib with a nickname": "import hashlib as h\nh.sha1(b'x')\n",
    "from hashlib": "from hashlib import sha256\n",
    "random": "import random\nrandom.random()\n",
    "from random": "from random import choice\n",
    "ssl": "import ssl\n",
    "a crypto library": "from cryptography.fernet import Fernet\n",
    "pycryptodome": "from Crypto.Cipher import AES\n",
    "nacl": "import nacl.secret\n",
    "jwt": "import jwt\n",
    "bcrypt": "import bcrypt\n",
    "passlib": "from passlib.hash import pbkdf2_sha256\n",
    "uuid1": "import uuid\nuuid.uuid1()\n",
    "uuid1 with a nickname": "import uuid as u\nu.uuid1()\n",
    "uuid1 brought in by name": "from uuid import uuid1\nuuid1()\n",
    "uuid5": "import uuid\nuuid.uuid5(uuid.NAMESPACE_DNS, 'x')\n",
    "uuid3": "from uuid import uuid3\n",
    "the machine address": "import uuid\nuuid.getnode()\n",
    "hmac outside auth": "import hmac\nhmac.compare_digest(b'a', b'b')\n",
    "hmac.new in auth": "import hmac\nhmac.new(b'k', b'm', 'sha256')\n",
    "hmac.digest in auth": "import hmac\nhmac.digest(b'k', b'm', 'sha256')\n",
    "hmac function brought in by name": "from hmac import new\nnew(b'k')\n",
    "verify false": "import httpx\nhttpx.get('x', verify=False)\n",
    "check_hostname false keyword": "f(check_hostname=False)\n",
    "check_hostname assigned": "c.check_hostname = False\n",
    "verify assigned": "s.verify = False\n",
    "CERT_NONE": "x = something.CERT_NONE\n",
    "CERT_NONE by name": "from something import CERT_NONE\nx = CERT_NONE\n",
    "an unverified context": "ctx = something._create_unverified_context()\n",
    "sslmode disable keyword": "connect(sslmode='disable')\n",
    "sslmode prefer keyword": "connect(sslmode='prefer')\n",
    "sslmode in a connection string": "url = 'host=db sslmode=disable'\n",
}
GOOD_PROGRAMS = {
    "hmac compare in auth": ("app/auth.py", "import hmac\nhmac.compare_digest(b'a', b'b')\n"),
    "uuid4": ("app/x.py", "from uuid import uuid4\nuuid4()\n"),
    "uuid4 with a nickname": ("app/x.py", "import uuid as u\nu.uuid4()\n"),
    "uuid as a type": ("app/x.py", "from uuid import UUID\nUUID('00000000-0000-0000-0000-000000000000')\n"),
    "secrets": ("app/x.py", "import secrets\nsecrets.token_hex(32)\n"),
    "os.urandom": ("app/x.py", "import os\nos.urandom(16)\n"),
    "verify true": ("app/x.py", "import httpx\nhttpx.get('x', verify=True)\n"),
    "sslmode require": ("app/x.py", "connect(sslmode='require')\n"),
    "sslmode verify-full in a string": ("app/x.py", "url = 'host=db sslmode=verify-full'\n"),
    "the words in a comment": ("app/x.py", "# we never use hashlib, random or verify=False here\nx = 1\n"),
    "the words in a string": ("app/x.py", "message = 'import hashlib'\n"),
    "a name that only contains the word": ("app/x.py", "my_random_value = 1\nrandomize = 2\n"),
    "a method called random on something else": ("app/x.py", "class A:\n    def random(self):\n        return 1\nA().random()\n"),
}


@pytest.mark.owasp("A04", 327, 328, 326, 1240, 757, 780, 329, 323, 325, 347, 330, 331, 332, 334, 335, 336, 337, 338, 340, 342, 1241, 296)
@pytest.mark.parametrize("label", sorted(BAD_PROGRAMS))
def test_every_bad_program_is_caught(label):
    # "hmac outside auth" is checked under a name other than auth.py; the others under auth.py too, so a pass there is not a free pass.
    name = "app/x.py"
    assert find_crypto_problems(BAD_PROGRAMS[label], name), label
    if label != "hmac outside auth":
        assert find_crypto_problems(BAD_PROGRAMS[label], "app/auth.py"), label


@pytest.mark.owasp("A04", 327, 330, 340)
@pytest.mark.parametrize("label", sorted(GOOD_PROGRAMS))
def test_every_good_program_passes(label):
    name, source = GOOD_PROGRAMS[label]
    assert find_crypto_problems(source, name) == [], f"wrongly flagged: {label}"


@pytest.mark.owasp("A04", 327, 330)
def test_a_problem_names_the_line():
    assert find_crypto_problems("x = 1\ny = 2\nimport random\n", "app/x.py") == ["app/x.py:3: imports banned cryptography module 'random'"]


BAD_SQL = {
    "md5": "SELECT md5('x');",
    "crypt": "SELECT crypt('pw', gen_salt('bf'));",
    "gen_salt": "SELECT gen_salt('md5');",
    "random": "SELECT random();",
    "setseed": "SELECT setseed(0.5);",
    "uuid v1": "SELECT uuid_generate_v1();",
    "uuid v5": "SELECT uuid_generate_v5(a, b);",
    "digest with md5": "SELECT digest('x', 'md5');",
    "digest with sha1": "SELECT digest(a || '|' || b, 'sha1');",
    "digest with sha1 across lines": "SELECT encode(digest(\n  a || (b)::text,\n  'sha1'), 'hex');",
    "hmac with md5": "SELECT hmac('x', 'k', 'md5');",
    "pgp encryption": "SELECT pgp_sym_encrypt('x', 'k');",
    "encrypt": "SELECT encrypt('x', 'k', 'aes');",
    "serial key": "CREATE TABLE t (id serial PRIMARY KEY);",
    "bigserial key": "CREATE TABLE t (id BIGSERIAL PRIMARY KEY);",
    "identity key": "CREATE TABLE t (id integer GENERATED ALWAYS AS IDENTITY);",
    "nextval": "SELECT nextval('s');",
    "sequence": "CREATE SEQUENCE s;",
}
GOOD_SQL = {
    "sha256 digest": "SELECT encode(digest(a || '|' || b, 'sha256'), 'hex');",
    "sha256 across lines": "SELECT encode(digest(\n  a || (b)::text || '|',\n  'sha256'), 'hex');",
    "random uuid": "CREATE TABLE t (id uuid PRIMARY KEY DEFAULT gen_random_uuid());",
    "a generated column that is not an identity": "CREATE TABLE t (h text GENERATED ALWAYS AS (lower(a)) STORED);",
    "the words in a comment": "-- never use md5( or random() or serial here\nSELECT 1;",
    "a column called randomness_note": "CREATE TABLE t (randomness_note text);",
}


@pytest.mark.owasp("A04", 327, 328, 326, 1240, 330, 338, 340, 342, 1241, 916)
@pytest.mark.parametrize("label", sorted(BAD_SQL))
def test_every_bad_sql_is_caught(label):
    assert find_sql_problems(BAD_SQL[label]), label


@pytest.mark.owasp("A04", 327, 330, 340)
@pytest.mark.parametrize("label", sorted(GOOD_SQL))
def test_every_good_sql_passes(label):
    assert find_sql_problems(GOOD_SQL[label]) == [], f"wrongly flagged: {label}: {find_sql_problems(GOOD_SQL[label])}"
