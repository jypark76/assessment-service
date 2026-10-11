# In plain English: tests that every ready-made image this repo deploys (the database, Kafka, the migration tool)
# is pinned to an exact digest, not just a version tag. A tag can be re-pointed at different contents by whoever
# owns the registry account, a digest cannot, so a pinned digest means "exactly the bytes I checked, or nothing".
#
# The rule: for every image that is not built from this repo, either the image line itself ends in @sha256:<64 hex>,
# or a kustomization.yaml "images:" entry for that same name has digest: sha256:<64 hex>. Our own service images are
# built here and loaded straight into the cluster, so they are left out.
#
# Why it matters (OWASP A08, software or data integrity failures): CWE-494, code downloaded without an integrity
# check, and CWE-829, functionality included from a source we do not control. The Python packages, the base image
# and the GitHub Actions are already pinned (tests/test_supply_chain_pins.py); this closes the last gap.
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
FOLDERS = [folder for folder in (ROOT / "k8s", ROOT / "kafka") if folder.exists()]
WORKLOADS = {"Deployment", "StatefulSet", "Job", "CronJob", "DaemonSet", "ReplicaSet"}
OUR_IMAGES = {"knowledge-service", "assessment-service"}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def pod_spec_of(document):
    spec = document.get("spec") or {}
    if document.get("kind") == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    return ((spec.get("template") or {}).get("spec")) or {}


def containers_of(pod):
    return list(pod.get("containers") or []) + list(pod.get("initContainers") or [])


# In plain English: "pgvector/pgvector:0.8.7-pg17@sha256:..." becomes "pgvector/pgvector".
def bare_name(image):
    without_digest = image.split("@")[0]
    last = without_digest.rsplit("/", 1)[-1]
    if ":" in last:
        without_digest = without_digest[: len(without_digest) - len(last)] + last.split(":")[0]
    return without_digest


# In plain English: takes the workload documents and the kustomization documents and returns one sentence per
# ready-made image that is not pinned to a digest.
def find_problems(documents, kustomizations):
    pinned_by_kustomize = {
        str(entry.get("name"))
        for kustomization in kustomizations
        if isinstance(kustomization, dict)
        for entry in kustomization.get("images") or []
        if DIGEST.fullmatch(str(entry.get("digest", "")))
    }
    problems = []
    for document in documents:
        if not isinstance(document, dict) or document.get("kind") not in WORKLOADS:
            continue
        name = f"{document['kind']}/{(document.get('metadata') or {}).get('name', '?')}"
        for container in containers_of(pod_spec_of(document)):
            image = str(container.get("image", ""))
            bare = bare_name(image)
            if bare.rsplit("/", 1)[-1] in OUR_IMAGES:
                continue
            inline = "@" in image and DIGEST.fullmatch(image.split("@", 1)[1])
            if not inline and bare not in pinned_by_kustomize:
                problems.append(f"{name}: image '{image}' is not pinned to a sha256 digest")
    return problems


def load_real_files():
    documents, kustomizations = [], []
    for folder in FOLDERS:
        for path in sorted(folder.rglob("*.y*ml")):
            for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
                if isinstance(document, dict) and document.get("kind") == "Kustomization":
                    kustomizations.append(document)
                elif isinstance(document, dict):
                    documents.append(document)
    return documents, kustomizations


GOOD_DIGEST = "sha256:" + "a" * 64


def workload(image, kind="Deployment"):
    return {"kind": kind, "metadata": {"name": "x"}, "spec": {"template": {"spec": {"containers": [{"image": image}]}}}}


BAD = {
    "a tag only": ([workload("postgres:17")], []),
    "no tag at all": ([workload("apache/kafka")], []),
    "the latest tag": ([workload("liquibase/liquibase:latest")], []),
    "a kustomize entry with only a tag": ([workload("postgres")], [{"images": [{"name": "postgres", "newTag": "17"}]}]),
    "a kustomize digest that is too short": ([workload("postgres")], [{"images": [{"name": "postgres", "digest": "sha256:abc"}]}]),
    "a kustomize digest for a different image": ([workload("postgres")], [{"images": [{"name": "mysql", "digest": GOOD_DIGEST}]}]),
    "an inline digest that is too short": ([workload("postgres@sha256:abc")], []),
    "an unpinned image in an init container": (
        [{"kind": "Job", "metadata": {"name": "j"}, "spec": {"template": {"spec": {"containers": [], "initContainers": [{"image": "busybox:1"}]}}}}],
        [],
    ),
    "an unpinned image in a cron job": (
        [{"kind": "CronJob", "metadata": {"name": "c"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"image": "busybox:1"}]}}}}}}],
        [],
    ),
}

GOOD = {
    "an inline digest": ([workload("postgres:17@" + GOOD_DIGEST)], []),
    "a kustomize digest": ([workload("pgvector/pgvector:0.8.7-pg17")], [{"images": [{"name": "pgvector/pgvector", "newTag": "0.8.7-pg17", "digest": GOOD_DIGEST}]}]),
    "our own image is left out": ([workload("knowledge-service")], []),
    "our own image with a tag is left out": ([workload("assessment-service:0.9.10")], []),
    "a registry with a port": ([workload("registry.local:5000/team/tool:1")], [{"images": [{"name": "registry.local:5000/team/tool", "digest": GOOD_DIGEST}]}]),
    "not a workload": ([{"kind": "ConfigMap", "data": {"image": "postgres:17"}}], []),
}


@pytest.mark.owasp("A08", 494, 829)
@pytest.mark.parametrize("label", sorted(BAD))
def test_every_bad_set_of_files_is_caught(label):
    documents, kustomizations = BAD[label]
    assert find_problems(documents, kustomizations), label


@pytest.mark.owasp("A08", 494, 829)
@pytest.mark.parametrize("label", sorted(GOOD))
def test_every_good_set_of_files_passes(label):
    documents, kustomizations = GOOD[label]
    assert find_problems(documents, kustomizations) == [], label


@pytest.mark.owasp("A08", 494, 829)
def test_every_ready_made_image_in_the_real_files_is_pinned_to_a_digest():
    documents, kustomizations = load_real_files()
    assert find_problems(documents, kustomizations) == []


@pytest.mark.owasp("A08", 494, 829)
def test_the_check_really_sees_the_ready_made_images_in_this_repo():
    # Proves the check is not passing because it found nothing to look at.
    documents, _ = load_real_files()
    images = {
        str(container.get("image", ""))
        for document in documents
        if document.get("kind") in WORKLOADS
        for container in containers_of(pod_spec_of(document))
    }
    third_party = {image for image in images if bare_name(image).rsplit("/", 1)[-1] not in OUR_IMAGES}
    if (ROOT / "k8s").exists() or (ROOT / "kafka").exists():
        assert images, "no images were found at all, so the check looked at nothing"
    for image in third_party:
        assert bare_name(image) != "", image
