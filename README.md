# Assessment service

The record keeper for an AI assessment grader. It is one small service in a
larger set of microservices, built in Python and meant to run on Kubernetes.

**Status: early work in progress.** The two database tables exist and are tested,
and the assignment, submission, grade and review routes work, so a submission can go
through its whole life: submitted, graded, rejected, graded again and approved. Sending
approved examples on to the knowledge service is not written yet.

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

## Changing the database

`db/init.sql` builds the first version of the tables, once, on an empty database. Every change after
that is a numbered file in [`db/changelog`](db/changelog), applied by Liquibase (a free tool that
applies database changes in order and remembers which ones it has applied). The root list
[`changelog-root.yaml`](db/changelog/changelog-root.yaml) names the files in order. Never edit a change
that has already been applied. Add the next numbered file and list it. A test checks that every file is
on the list.

On every deploy, a one-time job (`k8s/base/migrate-job.yaml`) runs Liquibase as the database admin, with
the password from the Kubernetes Secret, and applies only the changes that are missing. The service's own
login still cannot change tables. `deploy.sh` deploys in two steps: first everything except the service,
including the migration job, then it waits for the job, and only when the database changes are done does it
roll out the service, so a new version never starts on an old table. If a change fails, the script stops
within a few minutes, prints the job's log from every attempt, and leaves the running service untouched.

`bash db/check-upgrade.sh` proves an upgrade on a throwaway database that already holds an assignment and
a submission: they survive, the new table's rules work, the service login can read and add but not change
or delete, and a second run changes nothing. The pipeline runs it on every pull request.

Change 0001 adds `approval_sends`: a table that remembers which approved submissions have been sent on to
the knowledge service, so the sender (next step) never has to guess.

## The Kafka sender

When an instructor approves a grade, the essay and its grade should reach the knowledge service. A second
program, [`app/sender.py`](app/sender.py), does that. It runs as its own Deployment (`assessment-sender`)
from the same image, started with `python -m app.sender`, and has no web port. The message format is the
shared contract in `platform/contracts/approved-examples.md`.

- Approving a grade only saves a row. It never talks to Kafka, so a Kafka outage cannot stop an instructor
  approving.
- Every few seconds the sender asks the database for approved submissions that are not yet in the table
  `approval_sends`, publishes a message for each (key = the submission ID; no student name, no reviewer name)
  and adds the submission to `approval_sends` ONLY after Kafka confirms it arrived.
- Anything not confirmed stays waiting and is sent again on the next round. That is the re-send sweep:
  nothing is lost if Kafka is down or the sender crashes at a bad moment.
- Delivery is at-least-once: a message may occasionally arrive twice. That is harmless, because the knowledge
  service recognises the submission ID and saves nothing twice.
- A message is checked against the contract's limits before it is sent, so one the reader would refuse is
  never published. Tests also check that this service's own limits never exceed the reader's.
- No student text is written to the logs, only submission IDs and counts.

Limits: one sender (a second would only create duplicates); a few seconds of delay by design; the tests use
a pretend Kafka (the real one is proven on the cluster by hand); connections on the laptop are plain, with no
login. More than a whole batch (50) of permanently invalid approved rows would hold up the ones behind them;
the field limits make such rows impossible.

## The service key

Every route except `GET /health` and `GET /ready` needs the header `Authorization: Bearer <key>`.
The key is one long secret shared with the trusted callers (the other services). It lives in the
Kubernetes Secret `assessment-service-key` (made by hand, never in this repo) and reaches the pod
as the setting `SERVICE_KEYS`.

- A missing or wrong key answers 401 with the same fixed reply every time. It never says what was
  wrong and never repeats what was sent.
- If no usable key is configured the service answers 503 on every protected route. It never opens up.
- A key shorter than 32 characters is not usable. Make one with `openssl rand -hex 32`.
- The setting may list several keys separated by commas. To replace a key without downtime: add the
  new one next to the old, switch the callers to it, then remove the old one.
- New routes are protected by default. A test finds every route by asking the app, so a route added
  later cannot be forgotten.

One shared key says "a trusted caller", not "which person", and it travels as plain HTTP inside the
cluster on the laptop. Real user login comes later.

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
| `GET /submissions?status=` | List the submissions whose newest version has that status, oldest first (`status=graded` is the queue waiting for an instructor). Optional `assignment_id` and `limit` 1 to 100, default 50. No names or essays in the list |
| `POST /submissions/{id}/reviews` | Record an instructor's approve or reject as the next version. Answers 201, 200 for a retry, 404 for an unknown submission, or 409 if the submission has moved on or is not waiting for review |
| `POST /submissions/{id}/grades` | Record a grade as the next version. Answers 201, 200 for a retry, 404 for an unknown submission, or 409 if the submission has moved on or is not waiting for a grade |

There is no way to change or delete an assignment or a submission through the API.

The caller chooses the `submission_id`, and it doubles as the request ID. Sending the
same request again (a double click, or a retry after a timeout) returns the original
with a 200 and creates nothing new. The same ID with different content is refused with
a 409 and the stored submission is left as it was. Different IDs are always different
submissions, even for the same student and the same essay.

A grade is never written onto an existing row. It is added as the next version with the
status `graded`, so the whole history stays. The grader sends `based_on_version`, the
version it graded. If that is still the latest version, the grade goes in (201). If the
same grade is already saved at the next version, it is a retry and the saved grade comes
back (200) with nothing added. If the submission has moved on, or that version already
has a different grade, the answer is 409 and nothing changes, so two workers can never
both win. Only a new submission, or one an instructor rejected, can be graded. One that
is already graded or approved cannot.

A review works the same way. The reviewer sends `based_on_version` (the grade being
reviewed), a `decision` of `approve` or `reject`, and a `reviewer_username`. A rejection
must carry feedback and an approval must not. The review is added as the next version
(`rejected` or `approved`) and copies the grade it is about. Only a submission whose
newest version is a grade can be reviewed. A rejected submission goes back to the grader
for a new grade, and an approved one is final. A retry returns the saved review (200), and
a different review for a version that already has one gets a 409, so two reviewers can
never both win.

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

`tests/test_database.py`, `tests/test_tables.py`, `tests/test_assignments.py`,
`tests/test_submissions.py`, `tests/test_grades.py`, `tests/test_reviews.py` and
`tests/test_races.py` need a real database and are skipped when none is configured.
`tests/test_races.py` makes two workers or reviewers act on one submission at once, with
collisions both planted on purpose and caused by eight threads at the same instant. In the pipeline they run
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
  .venv/Scripts/python -m pytest -v tests/test_database.py tests/test_tables.py tests/test_assignments.py tests/test_submissions.py tests/test_grades.py tests/test_reviews.py tests/test_races.py

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

- The service key proves only that the caller is a trusted service, not which person is
  acting. Any holder of the key can create and read assignments, read any submission,
  including the student's name and essay, if they know its ID, and write a grade to a
  submission that is waiting for one. Real per-user login is planned.
- `reviewer_username` is a name the caller claims, not a proven identity, so anyone who
  can reach the service can approve or reject a grade. That is acceptable only while
  nothing consumes approvals. Before approved examples are sent on to the knowledge
  service (the store the grader learns from), callers must be authenticated, or a forged
  approval could put a bad example into future grading. The service key (above) narrows who can
  call at all; it does not prove which instructor approved. Who may see what is
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
