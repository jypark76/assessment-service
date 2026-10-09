#!/bin/sh
# In plain English: when the database starts for the very first time, Postgres
# runs every script in its "first start" folder in name order. The first one
# (01-init.sql, copied from db/init.sql) creates the table and the limited
# login "assessment_app" with no password. This second script then gives that
# login its password, taken from the Secret. The password is read from the
# APP_PASSWORD setting inside the pod, so it is never written in any file.
# Postgres only runs these scripts on an empty disk, so restarts never redo it.
set -e
psql -v ON_ERROR_STOP=1 -v pw="$APP_PASSWORD" -U postgres -d "$POSTGRES_DB" <<'SQL'
ALTER ROLE assessment_app PASSWORD :'pw';
SQL
