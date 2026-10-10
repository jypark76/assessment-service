#!/usr/bin/env bash
# In plain English: this script deploys the assessment service to whichever
# Kubernetes cluster your computer is currently pointed at, using the right
# settings for that cluster. It works out the environment by itself:
#   - the Docker Desktop cluster on your laptop  -> the "local" settings
#   - an AWS EKS cluster                         -> the "aws" settings
#   - anything else                              -> it refuses and stops
# That last rule is the safety net: laptop settings can never be applied to a
# real cluster by accident, or the other way round.
#
# It never creates or reads passwords. (On the laptop it also hands the table
# setup file db/init.sql to the database pod, which contains no secrets.) The Secret must already exist; if it
# does not, the script tells you the command to type and stops.
#
# Usage:  bash k8s/deploy.sh            (deploy)
#         bash k8s/deploy.sh --preview  (only show what would be deployed)
set -euo pipefail

# Find the k8s folder no matter where the script is run from.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ask kubectl which cluster it is pointed at right now.
context="$(kubectl config current-context)"

# Pick the settings folder from the cluster's name.
case "$context" in
  docker-desktop)
    overlay="local"
    ;;
  arn:aws:eks:*)
    overlay="aws"
    ;;
  *)
    echo "Refusing to deploy: the cluster '$context' is not recognised." >&2
    echo "Expected 'docker-desktop' (laptop) or an AWS EKS cluster." >&2
    exit 1
    ;;
esac

# The settings folder must exist. The AWS one is not written yet, on purpose.
if [ ! -d "$here/overlays/$overlay" ]; then
  echo "Refusing to deploy: there are no '$overlay' settings yet (k8s/overlays/$overlay)." >&2
  exit 1
fi

echo "Cluster:  $context"
echo "Settings: $overlay"

# Preview mode: show the final result and stop, changing nothing.
if [ "${1:-}" = "--preview" ]; then
  kubectl kustomize "$here/overlays/$overlay"
  exit 0
fi

# Deploying to AWS costs money and is visible to others, so ask first.
if [ "$overlay" = "aws" ]; then
  read -r -p "This is a real AWS cluster. Type 'yes' to continue: " answer
  [ "$answer" = "yes" ] || { echo "Cancelled."; exit 1; }
fi

# Make sure the "assessment" room exists, because the Secret has to live in it.
kubectl apply -f "$here/base/namespace.yaml"

# The passwords must already be in the cluster. We never create them here.
# "--ignore-not-found" means a missing Secret gives an empty answer, while any
# other problem (no connection, expired login, no permission) shows its real
# error and stops the script.
secret="$(kubectl get secret assessment-db -n assessment --ignore-not-found -o name)"
if [ -z "$secret" ]; then
  echo "The Secret 'assessment-db' does not exist yet. Create it first, with your own passwords:" >&2
  echo "  kubectl create secret generic assessment-db -n assessment --from-literal=postgres-password=ADMIN_PASSWORD --from-literal=app-password=APP_PASSWORD" >&2
  exit 1
fi

# The service key callers must present. Same rule: it must already exist, and the script
# never creates it. The key is a long random value; every service that calls this one
# gets it from this Secret. To make one: openssl rand -hex 32
key_secret="$(kubectl get secret assessment-service-key -n assessment --ignore-not-found -o name)"
if [ -z "$key_secret" ]; then
  echo "The Secret 'assessment-service-key' does not exist yet. Create it first, with your own random key:" >&2
  echo "  kubectl create secret generic assessment-service-key -n assessment --from-literal=keys=\"\$(openssl rand -hex 32)\"" >&2
  exit 1
fi

# Laptop only: hand the table-setup file (db/init.sql) to the database pod. It
# contains no secrets. The pod runs it by itself on its first start.
if [ "$overlay" = "local" ]; then
  kubectl create configmap assessment-db-init -n assessment \
    --from-file=01-init.sql="$here/../db/init.sql" \
    --dry-run=client -o yaml | kubectl apply -f -
fi

# Hand the database change files (db/changelog) to the cluster. They contain no
# secrets. The one-time migration job reads them from this ConfigMap. This happens
# on every environment, because every database needs its changes applied.
kubectl create configmap assessment-db-changelog -n assessment \
  --from-file="$here/../db/changelog" \
  --dry-run=client -o yaml | kubectl apply -f -

# A job cannot be changed after it is made, so remove the old migration job first.
# It is safe to run again: it only applies the changes that are missing.
kubectl delete job assessment-migrate -n assessment --ignore-not-found

# Waits for the database changes to finish, and stops the whole deploy loudly if they
# fail. It looks at the job's own state every few seconds, so a failure is reported
# the moment it happens, with the job's log. (Kubernetes' ready-made wait command
# cannot do that: it only stops early on success, so a failure shows up after the
# full timeout.)
wait_for_migration() {
  local deadline=$((SECONDS + 600))
  local succeeded failed
  while [ "$SECONDS" -lt "$deadline" ]; do
    succeeded="$(kubectl get job assessment-migrate -n assessment -o jsonpath='{.status.succeeded}')"
    failed="$(kubectl get job assessment-migrate -n assessment -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}')"
    if [ "$succeeded" = "1" ]; then
      echo "The database changes are applied."
      return 0
    fi
    if [ "$failed" = "True" ]; then
      echo "The database migration FAILED. Its log (every attempt):" >&2
      kubectl logs -l job-name=assessment-migrate -n assessment --tail=40 --prefix >&2
      exit 1
    fi
    sleep 3
  done
  echo "The database migration did not finish within 10 minutes. Its log so far:" >&2
  kubectl logs -l job-name=assessment-migrate -n assessment --tail=40 --prefix >&2
  exit 1
}

# Deploy in two steps, so the service never starts on an old table. First everything
# except the service: the settings, the database (on a laptop) and the migration job.
kubectl apply -k "$here/overlays/$overlay" -l 'deploy-phase!=service'

# Only when the database changes are done does the service itself roll out. If they
# failed, the script has already stopped, and the running service is left untouched.
wait_for_migration

kubectl apply -k "$here/overlays/$overlay" -l 'deploy-phase=service'
