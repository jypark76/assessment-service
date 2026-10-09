-- In plain English: this file sets up the assessment service's own database.
-- It runs once, when the database is first created. At this stage the database
-- holds no tables yet. They arrive with the first real features. All this file
-- does for now is create the limited login the service connects with.

-- The limited login the service connects with. It is created WITHOUT a
-- password here, because this file lives in a public repo. The password is set
-- separately when the database starts (see k8s/overlays/local/set-app-password.sh)
-- and is never written into any file.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'assessment_app') THEN
    CREATE ROLE assessment_app LOGIN;
  END IF;
END
$$;

-- Lets that login look inside the database's main folder (the "public schema").
-- It is NOT allowed to create anything there, so the service cannot add tables
-- or change the database's structure even if it has a bug. The permissions on
-- each table (read and add rows, never change or delete them) will be granted
-- together with the tables themselves.
GRANT USAGE ON SCHEMA public TO assessment_app;
