# In plain English: tests that nothing this repo deploys can be reached from outside the cluster. They read the
# real Kubernetes files and fail if a Service is anything but ClusterIP, if a Service asks for a node port, a
# load balancer or an outside address, if there is an Ingress or a gateway route, or if a pod joins the host's
# network or mounts the host's disk.
#
# Why it matters (OWASP A01, CWE-668 exposure of a resource to the wrong sphere): the services have no login of
# their own beyond the shared key and the decision is that nobody outside the cluster calls them (no external
# API). One careless line in a manifest would break that decision without any code changing.
#
# The Kubernetes file checker in tests/test_k8s_manifests.py already refuses these things, but it runs in its own
# job that needs Kubernetes tools. This test only reads files, so it runs with every other test.
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
FOLDERS = [folder for folder in (ROOT / "k8s", ROOT / "kafka") if folder.exists()]

OUTSIDE_KINDS = {"Ingress", "Gateway", "HTTPRoute", "GRPCRoute", "TCPRoute", "TLSRoute"}
HOST_SWITCHES = ("hostNetwork", "hostPID", "hostIPC")


# In plain English: walks any structure and yields every dictionary inside it.
def dictionaries(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from dictionaries(value)
    elif isinstance(node, list):
        for item in node:
            yield from dictionaries(item)


# In plain English: takes the parsed Kubernetes documents and returns a list of sentences, one per way something
# could be reached from outside the cluster. An empty list means everything is internal.
def find_exposure(documents):
    problems = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        kind = document.get("kind")
        name = (document.get("metadata") or {}).get("name", "?")
        if kind in OUTSIDE_KINDS:
            problems.append(f"{kind} {name} routes outside traffic in")
        if kind == "Service":
            spec = document.get("spec") or {}
            if spec.get("type", "ClusterIP") != "ClusterIP":
                problems.append(f"Service {name} has type {spec.get('type')}")
            for key in ("externalIPs", "loadBalancerIP", "externalName"):
                if key in spec:
                    problems.append(f"Service {name} sets {key}")
            for port in spec.get("ports") or []:
                if isinstance(port, dict) and "nodePort" in port:
                    problems.append(f"Service {name} opens a node port")
        for part in dictionaries(document):
            for switch in HOST_SWITCHES:
                if part.get(switch) is True:
                    problems.append(f"{kind} {name} sets {switch}")
            for container_port in part.get("ports", []) if isinstance(part.get("ports"), list) else []:
                if isinstance(container_port, dict) and "hostPort" in container_port:
                    problems.append(f"{kind} {name} opens a host port")
            for volume in part.get("volumes", []) if isinstance(part.get("volumes"), list) else []:
                if isinstance(volume, dict) and "hostPath" in volume:
                    problems.append(f"{kind} {name} mounts the host's disk")
    return problems


def real_documents():
    documents, services = [], 0
    for folder in FOLDERS:
        for path in sorted(folder.rglob("*.y*ml")):
            for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
                documents.append(document)
                if isinstance(document, dict) and document.get("kind") == "Service":
                    services += 1
    return documents, services


# ---------- The real files ----------

@pytest.mark.owasp("A01", 668)
@pytest.mark.owasp("A06", 1125, 419)
def test_nothing_this_repo_deploys_can_be_reached_from_outside_the_cluster():
    documents, services = real_documents()
    assert services >= 1, "no Service file was found, so there was nothing to check"
    assert find_exposure(documents) == []


# ---------- The check proves itself ----------

def service(**spec):
    return {"kind": "Service", "metadata": {"name": "x"}, "spec": spec}


BAD = {
    "a node port service": [service(type="NodePort")],
    "a load balancer service": [service(type="LoadBalancer")],
    "an external name": [service(type="ExternalName", externalName="evil.example")],
    "a node port on a ClusterIP service": [service(ports=[{"port": 80, "nodePort": 30080}])],
    "an outside address": [service(externalIPs=["1.2.3.4"])],
    "a load balancer address": [service(loadBalancerIP="1.2.3.4")],
    "an ingress": [{"kind": "Ingress", "metadata": {"name": "x"}}],
    "a gateway route": [{"kind": "HTTPRoute", "metadata": {"name": "x"}}],
    "host networking": [{"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"hostNetwork": True}}}}],
    "host process ids": [{"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"hostPID": True}}}}],
    "a host port": [{"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"containers": [{"ports": [{"containerPort": 80, "hostPort": 80}]}]}}}}],
    "the host's disk": [{"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"volumes": [{"name": "d", "hostPath": {"path": "/"}}]}}}}],
}

GOOD = {
    "a plain service": [service(ports=[{"port": 8000}])],
    "an explicit ClusterIP": [service(type="ClusterIP", ports=[{"port": 8000, "targetPort": 8000}])],
    "a pod with ordinary ports": [{"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"containers": [{"ports": [{"containerPort": 8000}]}], "hostNetwork": False}}}}],
    "a non-dictionary document": [None, "text"],
}


@pytest.mark.owasp("A01", 668)
@pytest.mark.parametrize("label", sorted(BAD))
def test_every_way_of_exposing_something_is_caught(label):
    assert find_exposure(BAD[label]), label


@pytest.mark.owasp("A01", 668)
@pytest.mark.parametrize("label", sorted(GOOD))
def test_internal_only_files_are_not_flagged(label):
    assert find_exposure(GOOD[label]) == []
