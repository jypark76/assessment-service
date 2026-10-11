# In plain English: the vulnerability scanner (Grype) that the image-scan workflow runs against the image
# we build. It is a pinned copy: the version says what it is and the digest says exactly which bytes, so the
# name cannot be moved to something else. Dependabot watches this file and proposes a newer scanner, which
# matters because an out-of-date scanner can quietly miss new flaws.
FROM anchore/grype:v0.120.1@sha256:e4a44ef45d285b829ce6efe2642980329661bd2d18eab5fc539138d4adaebbbe
