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

# Laptop only: hand the table-setup file (db/init.sql) to the database pod. It
# contains no secrets. The pod runs it by itself on its first start.
if [ "$overlay" = "local" ]; then
  kubectl create configmap assessment-db-init -n assessment \
    --from-file=01-init.sql="$here/../db/init.sql" \
    --dry-run=client -o yaml | kubectl apply -f -
fi

# Deploy everything for this environment.
kubectl apply -k "$here/overlays/$overlay"
