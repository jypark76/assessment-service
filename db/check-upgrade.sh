#!/usr/bin/env bash
# In plain English: this proves the database upgrade really works on a database that
# ALREADY holds data, which is the case that matters. It:
#   1. starts a throwaway Postgres built the old way (db/init.sql only, no changes yet),
#   2. saves an assignment and a submission in it, like the live database has,
#   3. runs the Liquibase change files against it,
#   4. checks the old rows survived and the new table and its rules are in place,
#   5. runs Liquibase a second time and checks it changed nothing,
#   6. throws the throwaway database away.
# The password is made up fresh for each run and never stored anywhere.
#
# Needs Docker. Usage:  bash db/check-upgrade.sh
set -euo pipefail

# Git Bash on Windows rewrites folder paths in docker commands unless told not to.
export MSYS_NO_PATHCONV=1

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
postgres_image="postgres:17"
liquibase_image="liquibase/liquibase:4.31.1"
name="upgrade-check-db"
database="upgrade_check"
password="$(openssl rand -hex 12)"

# Always remove the throwaway database, even if a check fails.
cleanup() {
  docker rm -f "$name" > /dev/null || true
}
trap cleanup EXIT

# Runs one SQL statement as the admin and prints only the answer.
sql() {
  docker exec -i "$name" psql -U postgres -d "$database" -v ON_ERROR_STOP=1 -tA -c "$1"
}

# Stops with a clear message if a check does not match what was expected.
expect() {
  if [ "$3" != "$2" ]; then
    echo "FAILED: $1 (expected '$2', got '$3')" >&2
    exit 1
  fi
  echo "ok: $1"
}

# Runs Liquibase against the throwaway database. It shares the database's own
# network, so "localhost" is the database on any computer.
migrate() {
  docker run --rm --network "container:$name" \
    -v "$here/changelog:/liquibase/changelog:ro" \
    -e LIQUIBASE_COMMAND_URL="jdbc:postgresql://localhost:5432/$database" \
    -e LIQUIBASE_COMMAND_USERNAME=postgres \
    -e LIQUIBASE_COMMAND_PASSWORD="$password" \
    "$liquibase_image" \
    --search-path=/liquibase/changelog --changelog-file=changelog-root.yaml update
}

echo "Starting a throwaway database built the old way (init.sql only)..."
docker run -d --name "$name" \
  -e POSTGRES_PASSWORD="$password" -e POSTGRES_DB="$database" \
  -v "$here/init.sql:/docker-entrypoint-initdb.d/01-init.sql:ro" \
  "$postgres_image" > /dev/null

# Wait until the first-start script has finished AND the real server answers.
ready=""
for _ in $(seq 1 60); do
  if docker logs "$name" 2>&1 | grep -q "init process complete" \
    && docker exec "$name" pg_isready -h 127.0.0.1 -U postgres -d "$database" > /dev/null; then
    ready="yes"
    break
  fi
  sleep 2
done
[ -n "$ready" ] || { echo "The throwaway database did not become ready." >&2; exit 1; }

echo "Before the upgrade:"
expect "the sent table is not there yet" "0"   "$(sql "SELECT count(*) FROM information_schema.tables WHERE table_name = 'approval_sends'")"
assignment="22222222-2222-4222-8222-222222222222"
submission="33333333-3333-4333-8333-333333333333"
sql "INSERT INTO assignments (assignment_id, instructor_username, title, rubric) VALUES ('$assignment', 'teacher', 'Old assignment', 'old rubric')" > /dev/null
sql "INSERT INTO submissions (submission_id, version, assignment_id, status, student_name, submission_text) VALUES ('$submission', 1, '$assignment', 'submitted', 'Old Student', 'old essay')" > /dev/null
expect "one old submission is saved" "1" "$(sql "SELECT count(*) FROM submissions")"

echo "Running the upgrade (first time)..."
migrate

echo "After the upgrade:"
expect "the sent table is there" "1"   "$(sql "SELECT count(*) FROM information_schema.tables WHERE table_name = 'approval_sends'")"
expect "the old submission survived" "1" "$(sql "SELECT count(*) FROM submissions WHERE submission_id = '$submission'")"
expect "Liquibase logged exactly one change" "1" "$(sql "SELECT count(*) FROM databasechangelog")"

echo "Checking the new table behaves:"
sql "INSERT INTO approval_sends (submission_id) VALUES ('$submission')" > /dev/null
echo "ok: a submission can be recorded as sent"
if sql "INSERT INTO approval_sends (submission_id) VALUES ('$submission')" > /dev/null 2>&1; then
  echo "FAILED: the same submission was recorded twice" >&2
  exit 1
fi
echo "ok: the same submission cannot be recorded twice"

# The service's own login (assessment_app) must be able to read and add, and nothing else.
# It is created by init.sql without a password, so it is given one here only to test with.
sql "ALTER ROLE assessment_app PASSWORD '$password'" > /dev/null
app_sql() {
  docker exec -i -e PGPASSWORD="$password" "$name" psql -h 127.0.0.1 -U assessment_app -d "$database" -v ON_ERROR_STOP=1 -tA -c "$1"
}
app_sql "INSERT INTO approval_sends (submission_id) VALUES (gen_random_uuid())" > /dev/null
echo "ok: the service login can add a row"
expect "the service login can read the table" "2" "$(app_sql "SELECT count(*) FROM approval_sends")"
if app_sql "UPDATE approval_sends SET sent_at = now()" > /dev/null 2>&1; then
  echo "FAILED: the service login could change a row" >&2
  exit 1
fi
echo "ok: the service login cannot change a row"
if app_sql "DELETE FROM approval_sends" > /dev/null 2>&1; then
  echo "FAILED: the service login could delete a row" >&2
  exit 1
fi
echo "ok: the service login cannot delete a row"

echo "Running the upgrade again (should change nothing)..."
before="$(sql "SELECT count(*) FROM submissions")"
migrate
expect "Liquibase still has exactly one change logged" "1" "$(sql "SELECT count(*) FROM databasechangelog")"
expect "no submissions were added or lost" "$before" "$(sql "SELECT count(*) FROM submissions")"
expect "no sent records were added or lost" "2" "$(sql "SELECT count(*) FROM approval_sends")"

echo "All upgrade checks passed."
