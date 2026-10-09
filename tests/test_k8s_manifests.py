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

# Things the pods point at that are NOT in the rendered files on purpose:
# "assessment-db-init" is made by deploy.sh from db/init.sql, and the Secret
# "assessment-db" is created by hand and never stored in the repo.
MADE_OUTSIDE = {("ConfigMap", "assessment-db-init"), ("Secret", "assessment-db")}


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

        if kind != "Deployment":
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

        # Rule 7: every ConfigMap or Secret a pod points at must exist in the
        # files, or be one of the few things made outside them on purpose.
        for reference in sorted(references_of(doc)):
            if reference not in defined and reference not in MADE_OUTSIDE:
                problems.append(f"{label}: points at {reference[0]} '{reference[1]}', which does not exist")

        # Rule 4: the service pod itself is locked down.
        if name == "assessment-service":
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
    assert ("Deployment", "assessment-db") in kinds
    assert ("NetworkPolicy", "assessment-db-allow-service-only") in kinds
    assert find_problems(real_docs) == []


# In plain English: the deploy script must never hide errors by sending them to
# the "bit bucket". That once made a real error look like "Secret missing".
def test_deploy_script_does_not_hide_errors():
    assert "/dev/null" not in DEPLOY_SCRIPT.read_text(encoding="utf-8")


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
