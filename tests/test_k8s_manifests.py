# In plain English: these tests check the Kubernetes files BEFORE they reach a
# cluster. They build the final files for the laptop settings (the same thing
# "deploy.sh --preview" shows) and check them against a short list of rules, each
# one written because of something that went wrong or that we decided.
#
# A checker that never complains proves nothing, so the second half of the file
# feeds the checker deliberately broken files and confirms it complains about each
# one. Those self-tests need no Kubernetes tools and always run.
import copy
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
OVERLAY = ROOT / "k8s" / "overlays" / "local"
DEPLOY_SCRIPT = ROOT / "k8s" / "deploy.sh"

NAMESPACE = "assessment"

# Kinds that do not live inside a namespace.
CLUSTER_WIDE = {"Namespace"}

# Kinds that run containers. Every rule about pods applies to all of them, so the
# one-time migration job cannot dodge a rule that the service has to follow.
WORKLOADS = {"Deployment", "Job"}

# The pods that must run locked down: a normal user, no extra privileges.
LOCKED_DOWN = {"assessment-service", "assessment-sender", "assessment-migrate"}

# Things the pods point at that are NOT in the rendered files on purpose:
# "assessment-db-init" is made by deploy.sh from db/init.sql, "assessment-db-changelog"
# is made by deploy.sh from the db/changelog folder, and the Secret "assessment-db"
# is created by hand and never stored in the repo.
MADE_OUTSIDE = {
    ("ConfigMap", "assessment-db-init"),
    ("ConfigMap", "assessment-db-changelog"),
    ("Secret", "assessment-db"),
    ("Secret", "assessment-service-key"),
}


# In plain English: builds the final Kubernetes files for the laptop settings and
# returns them as a list of Python dictionaries, one per object.
def render_overlay():
    result = subprocess.run(
        ["kubectl", "kustomize", str(OVERLAY)],
        capture_output=True,
        text=True,
        check=True,
    )
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


# In plain English: gives every container in a Deployment, whatever its name.
def containers_of(deployment):
    return deployment["spec"]["template"]["spec"].get("containers", [])


# In plain English: lists every ConfigMap and Secret that a Deployment points at,
# as (kind, name) pairs. It looks in all the places a pod can point at one:
# settings, settings from a whole ConfigMap, and mounted folders.
def references_of(deployment):
    found = set()
    pod = deployment["spec"]["template"]["spec"]
    for container in pod.get("containers", []):
        for env in container.get("env", []):
            source = env.get("valueFrom", {})
            if "secretKeyRef" in source:
                found.add(("Secret", source["secretKeyRef"]["name"]))
            if "configMapKeyRef" in source:
                found.add(("ConfigMap", source["configMapKeyRef"]["name"]))
        for entry in container.get("envFrom", []):
            if "configMapRef" in entry:
                found.add(("ConfigMap", entry["configMapRef"]["name"]))
            if "secretRef" in entry:
                found.add(("Secret", entry["secretRef"]["name"]))
    for volume in pod.get("volumes", []):
        if "configMap" in volume:
            found.add(("ConfigMap", volume["configMap"]["name"]))
        if "secret" in volume:
            found.add(("Secret", volume["secret"]["secretName"]))
        for source in volume.get("projected", {}).get("sources", []):
            if "configMap" in source:
                found.add(("ConfigMap", source["configMap"]["name"]))
            if "secret" in source:
                found.add(("Secret", source["secret"]["name"]))
    return found


# In plain English: the checker. It takes the list of Kubernetes objects and
# returns a list of plain sentences, one per rule that is broken. An empty list
# means every rule holds.
def find_problems(docs):
    problems = []
    defined = {(doc["kind"], doc["metadata"]["name"]) for doc in docs}

    for doc in docs:
        kind = doc["kind"]
        name = doc["metadata"]["name"]
        label = f"{kind}/{name}"

        # Rule 1: everything except the Namespace itself sits in our namespace.
        # A generated ConfigMap once had none and landed in the wrong room.
        if kind not in CLUSTER_WIDE and doc["metadata"].get("namespace") != NAMESPACE:
            problems.append(f"{label}: missing namespace '{NAMESPACE}'")

        # Rule 2: no Secret is ever stored in the repo, not even a template.
        if kind == "Secret":
            problems.append(f"{label}: a Secret must never be in the repo")

        # Rule 5: nothing is reachable from outside the cluster.
        if kind == "Service" and doc["spec"].get("type", "ClusterIP") != "ClusterIP":
            problems.append(f"{label}: service type must be ClusterIP")

        if kind not in WORKLOADS:
            continue

        for container in containers_of(doc):
            image = container.get("image", "")
            last_part = image.split("/")[-1]

            # Rule 3: a fixed version tag, never "latest" and never none.
            if ":" not in last_part:
                problems.append(f"{label}: image '{image}' has no version tag")
            elif last_part.endswith(":latest"):
                problems.append(f"{label}: image '{image}' must not use the tag latest")

            # Rule 6: a memory limit, so one pod cannot eat the whole machine.
            if not container.get("resources", {}).get("limits", {}).get("memory"):
                problems.append(f"{label}: container '{container['name']}' has no memory limit")

            # Rule 8: a password is never written as a plain value in the files. It
            # has to come from a Secret, because this repo is public.
            for env in container.get("env", []):
                if "PASSWORD" in env["name"].upper() and "valueFrom" not in env:
                    problems.append(f"{label}: {env['name']} must come from a Secret, not a written value")

        # Rule 7: every ConfigMap or Secret a pod points at must exist in the
        # files, or be one of the few things made outside them on purpose.
        for reference in sorted(references_of(doc)):
            if reference not in defined and reference not in MADE_OUTSIDE:
                problems.append(f"{label}: points at {reference[0]} '{reference[1]}', which does not exist")

        # Rule 4: the service pod and the migration job are locked down.
        if name in LOCKED_DOWN:
            pod = doc["spec"]["template"]["spec"]
            pod_security = pod.get("securityContext", {})
            if pod_security.get("runAsNonRoot") is not True:
                problems.append(f"{label}: runAsNonRoot must be true")
            run_as = pod_security.get("runAsUser")
            if not isinstance(run_as, int) or run_as == 0:
                problems.append(f"{label}: runAsUser must be a non-zero number")
            for container in pod.get("containers", []):
                security = container.get("securityContext", {})
                if security.get("allowPrivilegeEscalation") is not False:
                    problems.append(f"{label}: allowPrivilegeEscalation must be false")
                if "ALL" not in security.get("capabilities", {}).get("drop", []):
                    problems.append(f"{label}: capabilities must drop ALL")

    return problems


# ---------------------------------------------------------------------------
# Tests on the REAL files. These need the kubectl tool.
# ---------------------------------------------------------------------------


# In plain English: skips when kubectl is not installed, so a normal run on a
# computer without it still works. In the pipeline REQUIRE_KUBECTL=1 is set, and
# then a missing kubectl is a failure, because a skipped check proves nothing.
@pytest.fixture
def real_docs():
    if shutil.which("kubectl") is None:
        if os.environ.get("REQUIRE_KUBECTL") == "1":
            pytest.fail("REQUIRE_KUBECTL is set but kubectl was not found")
        pytest.skip("kubectl is not installed")
    return render_overlay()


# In plain English: the real laptop files must break none of the rules. It also
# checks the render really produced our objects, so an empty result can never pass.
def test_real_overlay_breaks_no_rules(real_docs):
    kinds = {(doc["kind"], doc["metadata"]["name"]) for doc in real_docs}
    assert ("Deployment", "assessment-service") in kinds
    assert ("Deployment", "assessment-sender") in kinds
    assert ("Deployment", "assessment-db") in kinds
    assert ("NetworkPolicy", "assessment-db-allow-service-only") in kinds
    assert ("Job", "assessment-migrate") in kinds
    assert find_problems(real_docs) == []


# In plain English: the deploy script must never hide errors by sending them to
# the "bit bucket". That once made a real error look like "Secret missing".
def test_deploy_script_does_not_hide_errors():
    assert "/dev/null" not in DEPLOY_SCRIPT.read_text(encoding="utf-8")


# In plain English: the migration job logs in to the database as the admin, so its
# password must come from the Kubernetes Secret, never from a value written in the
# files. It must also really run Liquibase's "update", which applies only the
# changes that are missing and does nothing when there are none.
def test_the_migration_job_gets_its_password_from_the_secret_and_runs_update(real_docs):
    job = next(doc for doc in real_docs if doc["kind"] == "Job" and doc["metadata"]["name"] == "assessment-migrate")
    container = containers_of(job)[0]
    env = {item["name"]: item for item in container.get("env", [])}
    password = env["LIQUIBASE_COMMAND_PASSWORD"]
    assert "value" not in password
    assert password["valueFrom"]["secretKeyRef"] == {"name": "assessment-db", "key": "postgres-password"}
    assert container["args"][-1] == "update"


# In plain English: the database only lets labelled pods connect to it. The
# migration job must carry a label the door rule accepts, or it could never reach
# the database on a cluster that enforces the rule.
def test_the_database_door_lets_the_migration_job_in(real_docs):
    job = next(doc for doc in real_docs if doc["kind"] == "Job" and doc["metadata"]["name"] == "assessment-migrate")
    assert job["spec"]["template"]["metadata"]["labels"]["app"] == "assessment-migrate"
    policy = next(doc for doc in real_docs if doc["kind"] == "NetworkPolicy")
    allowed = [
        source["podSelector"]["matchLabels"]["app"]
        for rule in policy["spec"]["ingress"]
        for source in rule["from"]
    ]
    assert "assessment-migrate" in allowed
    assert "assessment-sender" in allowed
    assert "assessment-service" in allowed


# In plain English: the deploy script must hand the change files to the cluster and
# clear out the old migration job first (a job cannot be changed after it is made).
def test_deploy_script_hands_over_the_changes_and_clears_the_old_job():
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    assert "assessment-db-changelog" in script
    assert "kubectl delete job assessment-migrate" in script


# In plain English: the service must roll out only AFTER the database changes are
# done. Otherwise a new service version could start on the old table, and if the
# migration failed the new version would already be live. The Deployment carries a
# label so the script can pick it out. The script applies everything else first, waits
# for the migration, and only then applies the service and the sender. Nothing else may carry the
# label, or it too would wait.
def test_the_service_rolls_out_only_after_the_migration(real_docs):
    labelled = [
        doc["metadata"]["name"]
        for doc in real_docs
        if doc["metadata"].get("labels", {}).get("deploy-phase") == "service"
    ]
    assert sorted(labelled) == ["assessment-sender", "assessment-service"]
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    everything_else_first = script.index("deploy-phase!=service")
    wait_for_the_migration = script.index("\nwait_for_migration\n")
    the_service_last = script.index("deploy-phase=service")
    assert everything_else_first < wait_for_the_migration < the_service_last


# In plain English: a failed migration must be reported as soon as it fails, with its
# log. "kubectl wait" cannot do that: it only stops early on success, so a failure shows
# up after the whole timeout. The script looks at the job's own state instead.
def test_a_failed_migration_is_reported_without_waiting_for_a_timeout():
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    assert "kubectl wait" not in script
    assert "Failed" in script
    assert "kubectl logs -l job-name=assessment-migrate" in script


# In plain English: the job's own retries must run out before the script stops
# waiting, or the script would give up on a job that is still trying. Four retries
# wait about 2.5 minutes in total, well inside the script's 10 minutes.
def test_the_migration_job_gives_up_before_the_deploy_script_does(real_docs):
    job = next(doc for doc in real_docs if doc["kind"] == "Job" and doc["metadata"]["name"] == "assessment-migrate")
    assert job["spec"]["backoffLimit"] <= 4


# ---------------------------------------------------------------------------
# Self-tests: the checker must complain about broken files. No kubectl needed.
# ---------------------------------------------------------------------------


# In plain English: a small set of Kubernetes objects that breaks no rule. Each
# self-test copies it and breaks exactly one thing.
def good_docs():
    return [
        {"kind": "Namespace", "metadata": {"name": NAMESPACE}},
        {
            "kind": "ConfigMap",
            "metadata": {"name": "settings", "namespace": NAMESPACE},
            "data": {"DB_HOST": "assessment-db"},
        },
        {
            "kind": "Service",
            "metadata": {"name": "assessment-service", "namespace": NAMESPACE},
            "spec": {"ports": [{"port": 8000}]},
        },
        {
            "kind": "Deployment",
            "metadata": {"name": "assessment-service", "namespace": NAMESPACE},
            "spec": {
                "template": {
                    "spec": {
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000},
                        "containers": [
                            {
                                "name": "assessment-service",
                                "image": "assessment-service:0.4.0",
                                "envFrom": [{"configMapRef": {"name": "settings"}}],
                                "env": [
                                    {
                                        "name": "DB_PASSWORD",
                                        "valueFrom": {"secretKeyRef": {"name": "assessment-db", "key": "app-password"}},
                                    }
                                ],
                                "resources": {"limits": {"memory": "1Gi"}},
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]},
                                },
                            }
                        ],
                    }
                }
            },
        },
        {
            "kind": "Job",
            "metadata": {"name": "assessment-migrate", "namespace": NAMESPACE},
            "spec": {
                "template": {
                    "metadata": {"labels": {"app": "assessment-migrate"}},
                    "spec": {
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 1001},
                        "containers": [
                            {
                                "name": "liquibase",
                                "image": "liquibase/liquibase:4.31.1",
                                "args": ["update"],
                                "env": [
                                    {
                                        "name": "LIQUIBASE_COMMAND_PASSWORD",
                                        "valueFrom": {"secretKeyRef": {"name": "assessment-db", "key": "postgres-password"}},
                                    }
                                ],
                                "resources": {"limits": {"memory": "768Mi"}},
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]},
                                },
                            }
                        ],
                    },
                }
            },
        },
    ]


# In plain English: the control. Before trusting any "broken" case, the good
# files must come back clean, or a complaint could mean anything.
def test_good_files_come_back_clean():
    assert find_problems(good_docs()) == []


def deployment_of(docs):
    return next(doc for doc in docs if doc["kind"] == "Deployment")


def test_catches_a_missing_namespace():
    docs = good_docs()
    del docs[1]["metadata"]["namespace"]
    assert any("missing namespace" in problem for problem in find_problems(docs))


def test_catches_a_secret_in_the_repo():
    docs = good_docs()
    docs.append({"kind": "Secret", "metadata": {"name": "oops", "namespace": NAMESPACE}})
    assert any("Secret must never be in the repo" in problem for problem in find_problems(docs))


def test_catches_the_latest_tag():
    docs = good_docs()
    containers_of(deployment_of(docs))[0]["image"] = "assessment-service:latest"
    assert any("latest" in problem for problem in find_problems(docs))


def test_catches_a_missing_tag():
    docs = good_docs()
    containers_of(deployment_of(docs))[0]["image"] = "assessment-service"
    assert any("no version tag" in problem for problem in find_problems(docs))


def test_catches_a_service_open_to_the_outside():
    docs = good_docs()
    docs[2]["spec"]["type"] = "NodePort"
    assert any("ClusterIP" in problem for problem in find_problems(docs))


def test_catches_a_missing_memory_limit():
    docs = good_docs()
    containers_of(deployment_of(docs))[0]["resources"] = {}
    assert any("memory limit" in problem for problem in find_problems(docs))


def test_catches_a_pointer_to_something_that_does_not_exist():
    docs = good_docs()
    containers_of(deployment_of(docs))[0]["envFrom"] = [{"configMapRef": {"name": "no-such-settings"}}]
    assert any("does not exist" in problem for problem in find_problems(docs))


def test_catches_a_name_mismatch_in_a_mounted_folder():
    docs = good_docs()
    pod = deployment_of(docs)["spec"]["template"]["spec"]
    pod["volumes"] = [{"name": "scripts", "projected": {"sources": [{"configMap": {"name": "scripts-1a2b3c"}}]}}]
    assert any("scripts-1a2b3c" in problem for problem in find_problems(docs))


def test_catches_a_pod_that_may_run_as_root():
    docs = good_docs()
    deployment_of(docs)["spec"]["template"]["spec"]["securityContext"] = {}
    problems = find_problems(docs)
    assert any("runAsNonRoot" in problem for problem in problems)
    assert any("runAsUser" in problem for problem in problems)


def test_catches_privilege_escalation_and_kept_capabilities():
    docs = good_docs()
    security = containers_of(deployment_of(docs))[0]["securityContext"]
    security["allowPrivilegeEscalation"] = True
    security["capabilities"] = {"drop": []}
    problems = find_problems(docs)
    assert any("allowPrivilegeEscalation" in problem for problem in problems)
    assert any("drop ALL" in problem for problem in problems)


# In plain English: a thing made outside the files on purpose (the hand-made
# Secret) must NOT be reported, or the checker would cry wolf on a healthy setup.
def test_allows_the_things_made_outside_on_purpose():
    docs = good_docs()
    assert ("Secret", "assessment-db") in references_of(deployment_of(docs))
    assert find_problems(docs) == []


# In plain English: the rules must cover the migration job too, not only the
# Deployments. A checker that skipped Jobs would let a bad migration job through.
def job_of(docs):
    return next(doc for doc in docs if doc["kind"] == "Job")


def test_catches_a_problem_in_the_migration_job():
    docs = good_docs()
    containers_of(job_of(docs))[0]["image"] = "liquibase/liquibase:latest"
    problems = find_problems(docs)
    assert any("Job/assessment-migrate" in problem and "latest" in problem for problem in problems)


def test_catches_a_migration_job_that_may_run_as_root():
    docs = good_docs()
    job_of(docs)["spec"]["template"]["spec"]["securityContext"] = {}
    problems = find_problems(docs)
    assert any("Job/assessment-migrate" in problem and "runAsNonRoot" in problem for problem in problems)


# In plain English: a password must never be written as a plain value in the files.
# It has to come from the Kubernetes Secret, because this repo is public.
def test_catches_a_password_written_in_the_files():
    docs = good_docs()
    containers_of(job_of(docs))[0]["env"] = [{"name": "LIQUIBASE_COMMAND_PASSWORD", "value": "hunter2"}]
    problems = find_problems(docs)
    assert any("PASSWORD" in problem and "Secret" in problem for problem in problems)


# In plain English: every retry of the migration job must be a NEW pod that stays
# after it fails. With "OnFailure" Kubernetes restarts the container inside one pod
# and deletes that pod when the retries run out, and the log goes with it. We found
# that out in a real failure drill: the script could not show why the migration failed.
def test_failed_migration_pods_are_kept_so_their_log_can_be_read(real_docs):
    job = next(doc for doc in real_docs if doc["kind"] == "Job" and doc["metadata"]["name"] == "assessment-migrate")
    assert job["spec"]["template"]["spec"]["restartPolicy"] == "Never"


# In plain English: the service key must reach the pod from the Kubernetes Secret and
# never from a value written in the files, and the deploy script must stop with the
# create command if that Secret does not exist yet.
def test_the_service_key_comes_from_a_secret_never_from_the_files(real_docs):
    deployment = next(d for d in real_docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "assessment-service")
    env = {item["name"]: item for item in containers_of(deployment)[0]["env"]}
    key = env["SERVICE_KEYS"]
    assert "value" not in key
    assert key["valueFrom"]["secretKeyRef"] == {"name": "assessment-service-key", "key": "keys"}
    settings = next(d for d in real_docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "assessment-service-config")
    assert "SERVICE_KEYS" not in settings["data"]
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    assert "kubectl get secret assessment-service-key" in script
    assert "kubectl create secret generic assessment-service-key" in script


# In plain English: the sender is its own Deployment from the SAME image as the web service,
# started with a different command. It listens on no port, takes the database password from
# the Secret (never from a written value), gets the Kafka address from the shared settings,
# and runs as exactly one copy (two would only send harmless duplicates).
def test_the_sender_runs_the_sender_code_from_the_same_image(real_docs):
    service = next(d for d in real_docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "assessment-service")
    sender = next(d for d in real_docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "assessment-sender")
    container = containers_of(sender)[0]
    assert container["image"] == containers_of(service)[0]["image"]
    assert container["command"] == ["python", "-m", "app.sender"]
    assert "ports" not in container
    assert sender["spec"]["replicas"] == 1
    assert sender["spec"]["template"]["metadata"]["labels"]["app"] == "assessment-sender"
    password = {item["name"]: item for item in container["env"]}["DB_PASSWORD"]
    assert "value" not in password
    assert password["valueFrom"]["secretKeyRef"] == {"name": "assessment-db", "key": "app-password"}
    settings = next(d for d in real_docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "assessment-service-config")
    assert settings["data"]["KAFKA_BOOTSTRAP"] == "kafka.kafka.svc.cluster.local:9092"
    assert container["envFrom"] == [{"configMapRef": {"name": "assessment-service-config"}}]
    # The sender does not call the service's own routes, so it must not hold the service key.
    assert "SERVICE_KEYS" not in {item["name"] for item in container["env"]}
