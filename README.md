# Knowledge service

The memory of past grading for an AI assessment grader. It is one small
service in a larger set of microservices, built in Python and meant to run on
Kubernetes.

**Status: work in progress.** The API, the tests and the local Kubernetes setup
exist. The AWS setup (RDS, ECR, EKS) is not written yet.

## What it does

1. **Stores approved examples.** After an instructor approves a grade, the
   example (student work, grade and reasoning) is saved here along with an
   embedding, a list of 384 numbers describing what the text is about.
2. **Finds similar examples.** Given a new piece of student work, it returns
   the past examples closest in meaning, so grading stays consistent.

## What it owns

Its own Postgres database with the pgvector extension and a single
`examples` table. No other service reads that database directly. Other
services ask this service through its API.

The setup lives in [`db/init.sql`](db/init.sql). The table holds an example ID,
an assignment ID (a plain reference to another service), the student work, the
grade, the reasoning, the embedding and a timestamp. It stores no student
names.

## API

| Call | What it does |
|---|---|
| `POST /examples` | Save an approved example and compute its embedding |
| `GET /examples?assignment_id=...` | List the examples for one assignment (newest first, up to 100) |
| `POST /examples/search` | Return the examples most similar in meaning to some text. It searches inside the assignment. If the assignment has no examples at all it returns nothing, unless the caller sets `fallback_to_all` to `true`, which borrows similar examples from every assignment. The flag is off by default, which protects against typos and accidents. It is not a security control, because it travels in the same request and the service has no authentication. Each result carries its `assignment_id` and a `same_assignment` flag, so the caller can tell borrowed examples from the assignment's own |
| `GET /health` | Report whether the service is alive |
| `GET /ready` | Report whether the service can reach its database |

Bad input is refused with a 422 that names the field and the reason but never
repeats what the caller sent.

## Tests

```
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt
.venv/Scripts/python -m pytest -v
```

The same tests run on every pull request, and the `main` branch rules require
them to pass before a merge.

The pipeline also builds the Docker image and starts it with the network off, then checks
`/health`, that `/ready` fails safely with no database, that the model is inside the image,
that it runs as user 1000 and that only the code, the model and the list of libraries are in `/app`.

`tests/test_k8s_manifests.py` builds the Kubernetes files for the laptop settings and
checks them against our rules (namespace, no Secret, fixed image tags, a locked-down
service pod and more). It needs `kubectl` and is skipped without it. Its self-tests
feed it deliberately broken files, so it cannot pass by never complaining.

`tests/test_database.py` needs a real database and is skipped when none is
configured. In the pipeline it runs against a throwaway Postgres that is built
from `db/init.sql` and the first-start password script, then destroyed. The
service login cannot delete, so these tests leave rows behind and refuse to run
unless the database is named `knowledge_test`. To run them yourself, start a
temporary container (use any passwords you like) and point the settings at it:

```
# In Git Bash on Windows, put MSYS_NO_PATHCONV=1 before "docker run". Without it
# Git Bash rewrites the folder paths and the setup scripts are never found.
docker run -d --name test-db \
  -e POSTGRES_PASSWORD=admin -e POSTGRES_DB=knowledge_test -e APP_PASSWORD=app \
  -v "$PWD/db/init.sql:/docker-entrypoint-initdb.d/01-init.sql:ro" \
  -v "$PWD/k8s/overlays/local/set-app-password.sh:/docker-entrypoint-initdb.d/02-set-app-password.sh:ro" \
  -p 5432:5432 pgvector/pgvector:0.8.7-pg17

# wait about 20 seconds for the database to finish setting itself up, then:
DB_HOST=localhost DB_NAME=knowledge_test DB_USER=knowledge_app DB_PASSWORD=app \
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
from `db/init.sql` and gives the `knowledge_app` login its password from the
Secret. To start the database from scratch:

```
kubectl delete -n knowledge deployment/knowledge-db pvc/knowledge-db-data
bash k8s/deploy.sh
```

The embedding model loads on the first save or search call, not at startup, so
the first call is slower. If it is ever preloaded at startup, add a
`startupProbe` to the Deployment so a slow start is not mistaken for a crash.

The database pod has a NetworkPolicy (`k8s/overlays/local/networkpolicy.yaml`) that
allows only the service pod to connect. It is written but not verified: Docker
Desktop's built-in cluster does not enforce NetworkPolicy, so a wrong pod still gets
through there. It has to be tested on a cluster that enforces policies.

On AWS the database is RDS, so the Postgres pod is not used there.

## Starting a new service from this repo

This repo is the template for the other microservices. See [`NEW_SERVICE.md`](NEW_SERVICE.md)
for the rename command, what to rewrite, the one-time GitHub setup and the order of work.

## Known limits

- The `fallback_to_all` flag guards against typos and accidents, not against a caller who wants the data. It travels in the same unauthenticated request, so any caller that can reach the service can set it with any assignment ID and read other assignments' examples. Real protection needs authentication, or the caller checking that the assignment exists. The service is internal-only for now.
- Search uses pgvector's HNSW index with iterative scan switched on, which stops
  after 20000 scanned rows (`hnsw.max_scan_tuples`). A small assignment hidden
  behind tens of thousands of closer examples from other assignments could still
  return too few results. Nothing near that size exists today.
- The NetworkPolicy is written but not verified, because Docker Desktop's
  built-in cluster does not enforce it.

## Security notes

- This repo is public. It never contains passwords, API keys or Kubernetes
  Secret files, not even templates.
- The service's database login can read and add examples but cannot update or
  delete them.
- The database passwords live only in a Kubernetes Secret that is created by
  hand with a command. They are never written into any file.
