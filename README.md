# Assessment service

The record keeper for an AI assessment grader. It is one small service in a
larger set of microservices, built in Python and meant to run on Kubernetes.

**Status: early work in progress.** The two database tables exist and are tested,
and the assignment and submission routes work. Grading and review are not written
yet, so a submission has only its first version, the student's work.

## What it will do

It is the system of record for assignments, submissions, grades and instructor
reviews. It contains no AI. The AI lives in the grader workers, which come later.

- **Assignments:** a title (unique across the system) and a rubric.
- **Submissions:** the student's work, kept as a series of **versions**. Every
  grade, rejection and approval is a new row with the next version number, so
  nothing is ever edited or deleted and the full grading history survives.

## What it will own

Its own Postgres database with two tables, `assignments` and a versioned
`submissions` table. No other service reads that database directly. Other
services ask this service through its API.

The setup in [`db/init.sql`](db/init.sql) creates the service's limited login and
the two tables. The database itself enforces the rules: a title is unique ignoring
capital letters and outer spaces, each status carries only its own fields, a version
number is used once, a submission has at most one approval, and every later version
must repeat the name, essay and assignment of version 1 (checked with a SHA-256
fingerprint, using Postgres's bundled `pgcrypto`). The login can read and add rows,
never change or delete them.

## API

| Call | What it does |
|---|---|
| `GET /health` | Report whether the service is alive |
| `GET /ready` | Report whether the service can reach its database |
| `POST /assignments` | Create an assignment (instructor, title, rubric). Answers 201, or 409 if the title is in use |
| `GET /assignments` | List the newest assignments, without rubrics (`limit` 1 to 100, default 50) |
| `GET /assignments/{id}` | Read one assignment with its rubric, or 404 |
| `POST /submissions` | Send a student's work in as version 1. Answers 201, 200 for a retry, 404 for an unknown assignment, or 409 if the ID is used for different content |
| `GET /submissions/{id}` | Read a submission with its history, one entry per version, or 404 |

There is no way to change or delete an assignment or a submission through the API.

The caller chooses the `submission_id`, and it doubles as the request ID. Sending the
same request again (a double click, or a retry after a timeout) returns the original
with a 200 and creates nothing new. The same ID with different content is refused with
a 409 and the stored submission is left as it was. Different IDs are always different
submissions, even for the same student and the same essay.

Bad input is refused with a 422 that names the field and the reason but never repeats
what the caller sent, not even the name of a field the caller invented. Text with a
null character, or text that cannot be written as UTF-8, is refused the same way.

## Tests

```
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt
.venv/Scripts/python -m pytest -v
```

The same tests run on every pull request, and the `main` branch rules require
them to pass before a merge.

The pipeline also builds the Docker image and starts it with the network off, then
checks `/health`, that `/ready` fails safely with no database, that it runs as user
1000 and that only the code and the list of libraries are in `/app`.

`tests/test_k8s_manifests.py` builds the Kubernetes files for the laptop settings and
checks them against our rules (namespace, no Secret, fixed image tags, a locked-down
service pod and more). It needs `kubectl` and is skipped without it. Its self-tests
feed it deliberately broken files, so it cannot pass by never complaining.

`tests/test_database.py`, `tests/test_tables.py`, `tests/test_assignments.py` and
`tests/test_submissions.py` need a real database and are skipped when none is configured. In the pipeline they run
against a throwaway Postgres that is built from `db/init.sql` and the first-start
password script, then destroyed. They refuse to run unless the database is named
`assessment_test`. The service's login cannot delete rows, so a database used for
several runs keeps the rows of earlier runs, and the tests use random titles for
that reason. To run them yourself, start a temporary container (use any passwords
you like) and point the settings at it:

```
# In Git Bash on Windows, put MSYS_NO_PATHCONV=1 before "docker run". Without it
# Git Bash rewrites the folder paths and the setup scripts are never found.
docker run -d --name test-db \
  -e POSTGRES_PASSWORD=admin -e POSTGRES_DB=assessment_test -e APP_PASSWORD=app \
  -v "$PWD/db/init.sql:/docker-entrypoint-initdb.d/01-init.sql:ro" \
  -v "$PWD/k8s/overlays/local/set-app-password.sh:/docker-entrypoint-initdb.d/02-set-app-password.sh:ro" \
  -p 5432:5432 postgres:17

# wait about 20 seconds for the database to finish setting itself up, then:
DB_HOST=localhost DB_NAME=assessment_test DB_USER=assessment_app DB_PASSWORD=app \
  .venv/Scripts/python -m pytest -v tests/test_database.py tests/test_tables.py tests/test_assignments.py tests/test_submissions.py

docker rm -f test-db
```

## Running on Kubernetes

The cluster files live in `k8s/`:

- `k8s/base/` holds what every environment shares (the Deployment and Service).
- `k8s/overlays/local/` holds the laptop settings, including a Postgres pod.
- `k8s/deploy.sh` looks at which cluster `kubectl` points at and applies the
  matching settings. It refuses any cluster it does not recognise.

```
bash k8s/deploy.sh --preview   # show what would be deployed
bash k8s/deploy.sh             # deploy
```

First time on a cluster: create the Secret by hand (the script prints the
command), then run `deploy.sh`. On its first start the database sets itself up
from `db/init.sql` and gives the `assessment_app` login its password from the
Secret. To start the database from scratch:

```
kubectl delete -n assessment deployment/assessment-db pvc/assessment-db-data
bash k8s/deploy.sh
```

The database pod has a NetworkPolicy (`k8s/overlays/local/networkpolicy.yaml`) that
allows only the service pod to connect. It is written but not verified: Docker
Desktop's built-in cluster does not enforce NetworkPolicy, so a wrong pod still gets
through there. It has to be tested on a cluster that enforces policies.

On AWS the database is RDS, so the Postgres pod is not used there.

## Known limits

- The service has no authentication. It does not check who is calling, so anyone
  who can reach it can create and read assignments and can read any submission,
  including the student's name and essay, if they know its ID. Who may see what is
  decided when the frontend arrives. Student names are stored only in this service.
- Reachability is limited by the network only: the service is `ClusterIP`, so nothing
  outside the cluster can reach it, but there is no rule yet on which pods inside the
  cluster may call it. That rule is planned for when the real callers exist.
- The NetworkPolicy on the database is written but not verified, because Docker
  Desktop's built-in cluster does not enforce it.
- If the database is down, the routes answer a plain 500 with no details.

## Security notes

- This repo is public. It never contains passwords, API keys or Kubernetes
  Secret files, not even templates.
- The service's database login can read and add rows but cannot create tables or
  change or delete rows, and tests prove each refusal.
- Error replies never repeat what the caller sent, and tests plant a marker string
  to prove it.
- The database passwords live only in a Kubernetes Secret that is created by
  hand with a command. They are never written into any file.
