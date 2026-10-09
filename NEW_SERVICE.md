# Starting a new service from this template

This repo is the pattern for every other microservice in the grading platform. It
holds a working service (FastAPI, its own Postgres database, tests, a pipeline,
Kubernetes files and a deploy script). A new service starts as a copy and then
changes the parts that belong to the knowledge service.

This repo is marked as a GitHub template repository. That setting adds a **Use this
template** button on its front page. The button creates a brand new repo with the
same files and a clean history, not linked to this one. The template copies files
only. Repo settings (branch rules, required checks, secret scanning) are NOT copied
and must be set up again for each new repo (step 3).

## Step 1: create the repo and rename

1. Click **Use this template**, then **Create a new repository**. Name it
   `<name>-service`, for example `assessment-service`. Keep it **public**.
2. Clone it. Keep this guide open from the template repo on GitHub. In your new
   clone, delete `NEW_SERVICE.md` and the paragraph in `README.md` titled "Starting a
   new service from this repo". They describe the template, and the rename below would
   turn them into nonsense.
3. Rename. The knowledge service's name appears in 11 forms
   (`knowledge-service`, `knowledge-db`, `knowledge_app`, `knowledge_test`, the
   `knowledge` namespace and database, and so on), and all of them are the word
   `knowledge` plus a suffix. One command changes every one (it was tried on a copy
   of this repo and the renamed copy passed its tests). Replace `assessment` with your
   service's word, in lowercase and with no dashes:

   ```
   grep -rlI "knowledge" --exclude-dir=.git --exclude-dir=.venv . | xargs sed -i 's/knowledge/assessment/g; s/Knowledge/Assessment/g'
   ```

4. Check nothing was missed. This should print nothing:

   ```
   grep -rIi "knowledge" --exclude-dir=.git --exclude-dir=.venv .
   ```

## Step 2: replace the parts that belong to the knowledge service

The rename only changes names. These parts hold the knowledge service's actual job
and must be rewritten for the new service:

| File | What to do |
|---|---|
| `db/init.sql` | Replace the `examples` table and its indexes. Keep the pattern: a login created with no password, and only the permissions the service needs |
| `app/examples.py` | Replace the request shapes and the save, list and search functions. Keep the null-character check |
| `app/main.py` | Replace the routes. Keep `/health`, `/ready`, the 422 handler and the `safe_reason` and `safe_field` helpers |
| `app/embeddings.py`, `requirements.txt`, `Dockerfile` | Delete if the service has no AI model. Then also remove `fastembed`, the model download line and `FASTEMBED_CACHE_PATH` from the Dockerfile |
| `tests/test_validation.py`, `test_database.py`, `test_vectors.py`, `test_search_settings.py`, `test_embeddings_lock.py` | Rewrite for the new routes and data. Keep the guards and the controls (see the rules below) |
| `k8s/base/deployment.yaml` | Set memory and CPU for the new service. The knowledge service needs room for its model |
| `README.md` | Rewrite the description, the API table and the known limits |

### If the service has no database

Delete these, then fix the pieces that point at them:

- `app/db.py` and the `/ready` check on the database (keep `/ready`, but make it check what the service really needs)
- `db/`, `k8s/overlays/local/db.yaml`, `networkpolicy.yaml`, `set-app-password.sh` and the `DB_*` settings in `configmap.yaml`
- the `database-tests` job in `.github/workflows/tests.yml` and `tests/test_database.py`
- in `k8s/deploy.sh`: the `knowledge-db-init` ConfigMap step and the Secret check, if the service has no Secret
- in `tests/test_k8s_manifests.py`: the `MADE_OUTSIDE` list and the rules that mention the database pod

## Step 3: one-time GitHub setup for the new repo

Do this before any real work, so every pull request is protected from the start.

1. **Two rulesets on the default branch** (Settings, then Rules, then Rulesets):
   - `main: tests must pass`: require a pull request and the status checks
     `tests`, `database-tests`, `kubernetes-checks` and `image-build`. No bypass for anyone.
     A check only appears in the picker after it has run once, so add them after the
     first pull request.
   - `main: review required`: one approval required, with the repository admin on the
     bypass list ("For pull requests only").
2. **Secret scanning and push protection:** Settings, then Security. Turn them on.
3. Leave **Template repository** unchecked on the new repo. It is not a template.
4. Do NOT add any Kubernetes Secret files to the repo, not even templates.

## Step 4: the order of work

The same order that finally worked on the knowledge service. The deploy path comes
before the real features.

1. Commit the `.gitignore` first.
2. Smallest runnable service: only `/health` and `/ready`. Build and run the image.
3. Pipeline and rulesets. **Prove the gate** with a deliberately broken pull request.
4. Deploy path: `k8s/base`, the local overlay and `deploy.sh`. Create the Secret by
   hand. Deploy the bare service and watch it become ready.
5. If it owns data: `db/init.sql` and the first-start password script together, then
   prove the limited login with a refused `DELETE`.
6. Add the real routes one at a time, each with strict input rules and a test that
   breaks it on purpose. Redeploy after each one.
7. Run the clean-room test: wipe the database disk and the deployments, redeploy from
   the repo plus the hand-made Secret, and read the log for the setup lines. Do not
   delete any pod during the test.
8. Harden: the NetworkPolicy (it can only be proven on a cluster that enforces
   policies, such as EKS with network policy on), and a second review pass.

## The rules that keep the checks honest

- The repo alone must rebuild everything. Anything done by hand and not written in the
  repo is a bug. The only exception is the Secret.
- A check must be able to fail, and you must have seen it fail. Each gate is proven
  with a deliberately broken pull request: grant `DELETE` in `init.sql`, remove the
  namespace from the generated ConfigMap, delete the model download line from the
  Dockerfile.
- A test that expects a failure first proves the success case in the same test.
- Probe every place caller data can appear (values, field names, query parameters) with
  a secret-looking marker, and check it never comes back.
- Tests that need a database refuse to run unless it is named `<name>_test`, and CI sets
  a flag so a skipped test counts as a failure.
- Run every new pipeline check on your own computer before the first pipeline run. In
  Git Bash on Windows put `MSYS_NO_PATHCONV=1` in front of `docker` commands that
  contain paths.
- Read the namespace of every object in the deploy preview, not just the names.
- Comments claim only what the code does. If a fix has a ceiling, say where it is.

## Before you open a pull request

- Ask: what did I do by hand that is not in the repo?
- Run the clean-room test.
- Run the full test suite and the Kubernetes checks on your computer.
- Get a second review pass on the diff.
