# In plain English: tests that every pod this repo deploys is locked down the same way, by reading the real
# Kubernetes files. No Kubernetes tools are needed, so this runs with every other test.
#
# Every pod:
#   - gets no Kubernetes service-account token (the services never talk to the Kubernetes API, and a stolen token
#     would be a free key to it);
#   - uses the container runtime's default seccomp profile (it blocks dozens of rarely used system calls);
#   - is never privileged.
#
# Our own service pods (the ones running this repo's image) also:
#   - run with a read-only root filesystem, no privilege escalation and all Linux capabilities dropped;
#   - get their secrets (the service keys, the database password) as mounted files from a Secret, never as
#     environment variables, and only from folders under /etc/secrets;
#   - get a small, size-limited temporary folder for anything that has to be written.
#
# Why it matters (OWASP A02, security misconfiguration): CWE-16 configuration in general, and CWE-526, secrets in
# environment variables. Third-party pods (the database, Kafka, the migration tool) get the first group of rules
# only, because forcing a read-only filesystem on software that manages its own data folder could break it.
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
FOLDERS = [folder for folder in (ROOT / "k8s", ROOT / "kafka") if folder.exists()]
WORKLOADS = {"Deployment", "StatefulSet", "Job", "CronJob", "DaemonSet", "ReplicaSet"}
OUR_IMAGES = {"knowledge-service", "assessment-service"}
SECRET_FOLDER = "/etc/secrets/"


def pod_spec_of(document):
    spec = document.get("spec") or {}
    if document.get("kind") == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    return ((spec.get("template") or {}).get("spec")) or {}


def containers_of(pod):
    return list(pod.get("containers") or []) + list(pod.get("initContainers") or [])


def image_name(container):
    return str(container.get("image", "")).split("/")[-1].split(":")[0].split("@")[0]


# In plain English: takes the parsed Kubernetes documents and returns a list of sentences, one per rule broken.
def find_problems(documents):
    problems = []
    for document in documents:
        if not isinstance(document, dict) or document.get("kind") not in WORKLOADS:
            continue
        name = f"{document['kind']}/{(document.get('metadata') or {}).get('name', '?')}"
        pod = pod_spec_of(document)
        if pod.get("automountServiceAccountToken") is not False:
            problems.append(f"{name}: automountServiceAccountToken must be false")
        pod_security = pod.get("securityContext") or {}
        if (pod_security.get("seccompProfile") or {}).get("type") != "RuntimeDefault":
            problems.append(f"{name}: seccompProfile must be RuntimeDefault")
        mounts_by_volume = {}
        volumes = {volume.get("name"): volume for volume in pod.get("volumes") or []}
        for container in containers_of(pod):
            security = container.get("securityContext") or {}
            if security.get("privileged") is True:
                problems.append(f"{name}: container {container.get('name')} is privileged")
            if image_name(container) not in OUR_IMAGES:
                continue
            label = f"{name}/{container.get('name')}"
            if security.get("readOnlyRootFilesystem") is not True:
                problems.append(f"{label}: readOnlyRootFilesystem must be true")
            if security.get("allowPrivilegeEscalation") is not False:
                problems.append(f"{label}: allowPrivilegeEscalation must be false")
            if "ALL" not in (security.get("capabilities") or {}).get("drop", []):
                problems.append(f"{label}: capabilities must drop ALL")
            if pod_security.get("runAsNonRoot") is not True:
                problems.append(f"{label}: runAsNonRoot must be true")
            for source in container.get("envFrom") or []:
                if "secretRef" in source:
                    problems.append(f"{label}: secrets must be mounted as files, not loaded as environment variables (envFrom secretRef)")
            mounts = {mount.get("mountPath"): mount for mount in container.get("volumeMounts") or []}
            for env in container.get("env") or []:
                if "secretKeyRef" in (env.get("valueFrom") or {}):
                    problems.append(f"{label}: {env.get('name')} is a secret in an environment variable; mount it as a file instead")
                value = str(env.get("value", ""))
                if env.get("name", "").endswith("_FILE"):
                    if not value.startswith(SECRET_FOLDER):
                        problems.append(f"{label}: {env.get('name')} must point inside {SECRET_FOLDER}")
                        continue
                    backing = [mount for path, mount in mounts.items() if value.startswith(path.rstrip("/") + "/")]
                    if not backing:
                        problems.append(f"{label}: {env.get('name')} points at {value}, which no volume is mounted at")
                        continue
                    volume = volumes.get(backing[0].get("name")) or {}
                    if "secret" not in volume:
                        problems.append(f"{label}: {env.get('name')} points into a volume that is not a Secret")
                    if backing[0].get("readOnly") is not True:
                        problems.append(f"{label}: the Secret volume for {env.get('name')} must be mounted read-only")
            if not any(path == "/tmp" for path in mounts):
                problems.append(f"{label}: a read-only filesystem needs a temporary folder mounted at /tmp")
            else:
                tmp = volumes.get(mounts["/tmp"].get("name")) or {}
                if "emptyDir" not in tmp or not (tmp.get("emptyDir") or {}).get("sizeLimit"):
                    problems.append(f"{label}: /tmp must be an emptyDir with a size limit")
    return problems


def real_documents():
    documents = []
    for folder in FOLDERS:
        for path in sorted(folder.rglob("*.y*ml")):
            documents.extend(d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d)
    return documents


# ---------- The real files ----------

@pytest.mark.owasp("A02", 16, 526)
@pytest.mark.owasp("A06", 266, 269, 316)
def test_every_pod_this_repo_deploys_is_locked_down():
    documents = real_documents()
    workloads = [d for d in documents if isinstance(d, dict) and d.get("kind") in WORKLOADS]
    assert workloads, "no workload file was found, so there was nothing to check"
    assert find_problems(documents) == []


@pytest.mark.owasp("A02", 16)
def test_the_check_really_looks_at_the_pods_of_this_repo():
    documents = real_documents()
    kinds = {d["kind"] for d in documents if isinstance(d, dict) and d.get("kind") in WORKLOADS}
    assert kinds, kinds


# ---------- The check proves itself ----------

def good_app_pod():
    return {
        "kind": "Deployment",
        "metadata": {"name": "app"},
        "spec": {"template": {"spec": {
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "fsGroup": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "app",
                "image": "knowledge-service:0.1",
                "env": [{"name": "DB_PASSWORD_FILE", "value": "/etc/secrets/db/app-password"}],
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}, {"name": "db", "mountPath": "/etc/secrets/db", "readOnly": True}],
            }],
            "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}}, {"name": "db", "secret": {"secretName": "x"}}],
        }}},
    }


def good_third_party_pod():
    return {
        "kind": "StatefulSet",
        "metadata": {"name": "kafka"},
        "spec": {"template": {"spec": {
            "automountServiceAccountToken": False,
            "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "kafka", "image": "apache/kafka:3.9.0"}],
        }}},
    }


def changed(make, edit):
    document = make()
    edit(document)
    return [document]


def pod(document):
    return document["spec"]["template"]["spec"]


def container(document):
    return pod(document)["containers"][0]


BAD = {
    "the token is mounted": (good_app_pod, lambda d: pod(d).pop("automountServiceAccountToken")),
    "the token is switched on": (good_app_pod, lambda d: pod(d).update(automountServiceAccountToken=True)),
    "no seccomp profile": (good_app_pod, lambda d: pod(d)["securityContext"].pop("seccompProfile")),
    "an unconfined seccomp profile": (good_app_pod, lambda d: pod(d)["securityContext"].update(seccompProfile={"type": "Unconfined"})),
    "a third-party pod without the token rule": (good_third_party_pod, lambda d: pod(d).pop("automountServiceAccountToken")),
    "a third-party pod without seccomp": (good_third_party_pod, lambda d: pod(d)["securityContext"].pop("seccompProfile")),
    "a privileged container": (good_third_party_pod, lambda d: container(d).update(securityContext={"privileged": True})),
    "a writable root filesystem": (good_app_pod, lambda d: container(d)["securityContext"].update(readOnlyRootFilesystem=False)),
    "no read-only setting": (good_app_pod, lambda d: container(d)["securityContext"].pop("readOnlyRootFilesystem")),
    "privilege escalation allowed": (good_app_pod, lambda d: container(d)["securityContext"].update(allowPrivilegeEscalation=True)),
    "capabilities kept": (good_app_pod, lambda d: container(d)["securityContext"].update(capabilities={"drop": ["NET_RAW"]})),
    "may run as root": (good_app_pod, lambda d: pod(d)["securityContext"].update(runAsNonRoot=False)),
    "a secret in an environment variable": (good_app_pod, lambda d: container(d)["env"].append({"name": "SERVICE_KEYS", "valueFrom": {"secretKeyRef": {"name": "k", "key": "keys"}}})),
    "all secrets loaded into the environment": (good_app_pod, lambda d: container(d).update(envFrom=[{"secretRef": {"name": "everything"}}])),
    "a secret file path outside the secrets folder": (good_app_pod, lambda d: container(d)["env"].append({"name": "X_FILE", "value": "/tmp/x"})),
    "a secret file path nothing is mounted at": (good_app_pod, lambda d: container(d)["env"].append({"name": "X_FILE", "value": "/etc/secrets/other/x"})),
    "a secret path backed by a plain folder": (good_app_pod, lambda d: pod(d)["volumes"].__setitem__(1, {"name": "db", "emptyDir": {}})),
    "a secret volume that is writable": (good_app_pod, lambda d: container(d)["volumeMounts"][1].pop("readOnly")),
    "no temporary folder": (good_app_pod, lambda d: container(d)["volumeMounts"].pop(0)),
    "a temporary folder with no size limit": (good_app_pod, lambda d: pod(d)["volumes"].__setitem__(0, {"name": "tmp", "emptyDir": {}})),
    "a temporary folder on the node's disk": (good_app_pod, lambda d: pod(d)["volumes"].__setitem__(0, {"name": "tmp", "hostPath": {"path": "/tmp"}})),
}


@pytest.mark.owasp("A02", 16, 526)
def test_a_well_locked_pod_of_each_kind_has_no_problems():
    assert find_problems([good_app_pod(), good_third_party_pod()]) == []


@pytest.mark.owasp("A02", 16, 526)
@pytest.mark.parametrize("label", sorted(BAD))
def test_every_way_of_loosening_a_pod_is_caught(label):
    make, edit = BAD[label]
    assert find_problems(changed(make, edit)), label


@pytest.mark.owasp("A02", 16)
def test_documents_that_are_not_pods_are_left_alone():
    assert find_problems([None, "text", {"kind": "Service", "spec": {}}, {"kind": "ConfigMap", "data": {}}]) == []
