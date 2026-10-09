# Assessment service

The record keeper for an AI assessment grader. It is one small service in a
larger set of microservices, built in Python and meant to run on Kubernetes.

**Status: early work in progress.** A runnable skeleton exists: the health
checks, an empty database with its limited login, the tests and pipeline, and the
Kubernetes files. The tables and the real routes are not written yet.

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

Today the database holds no tables. The setup in [`db/init.sql`](db/init.sql)
only creates the service's limited login, which can connect but cannot create
anything. The permissions for each table will be granted together with the table:
read and add rows, never change or delete them.

## API

| Call | What it does |
|---|---|
| `GET /health` | Report whether the service is alive |
| `GET /ready` | Report whether the service can reach its database |

The assignment and submission routes come with the tables. Bad input is refused
with a 422 that names the field and the reason but never repeats what the caller
sent, not even the name of a field the caller invented.

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

`tests/test_database.py` needs a real database and is skipped when none is
configured. In the pipeline it runs against a throwaway Postgres that is built
from `db/init.sql` and the first-start password script, then destroyed. It refuses
to run unless the database is named `assessment_test`. To run it yourself, start a
temporary container (use any passwords you like) and point the settings at it:

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
  .venv/Scripts/python -m pytest -v tests/test_database.py

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

- The service has no authentication yet and is internal-only. Who may see what
  is decided when the frontend arrives.
- The NetworkPolicy is written but not verified, because Docker Desktop's
  built-in cluster does not enforce it.

## Security notes

- This repo is public. It never contains passwords, API keys or Kubernetes
  Secret files, not even templates.
- The service's database login can connect but cannot create tables. Once the
  tables exist it will be able to read and add rows but not change or delete them.
- The database passwords live only in a Kubernetes Secret that is created by
  hand with a command. They are never written into any file.
