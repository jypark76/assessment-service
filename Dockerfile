# In plain English: this is the recipe that packs the assessment service into one
# sealed box (a Docker image) that runs the same way on any computer.
# Build it from the repo folder:  docker build -t assessment-service .
# Run it:                         docker run --rm -p 8000:8000 assessment-service

# Start from a small, ready-made Python system.
FROM python:3.15-slim@sha256:94d3426f1def7db4a106a232ac121bfd975393e5dfd40a619b955fae45fe7913

# Python settings for containers: do not leave stray cache files, and print
# messages straight away so they show up in the logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Work inside a folder called /app in the box.
WORKDIR /app

# Install the libraries first. Docker remembers this step, so rebuilding is
# fast as long as requirements.txt has not changed. requirements.txt is a lock file: every library
# (and every library those need) is pinned to one version and its file hashes. --require-hashes makes
# the build FAIL if any downloaded file differs by even one byte, and --no-deps stops pip from
# fetching anything the lock does not list.
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.txt

# Never run the service as the all-powerful root user inside the box.
RUN useradd --create-home appuser

# From here on, everything runs as that limited user.
USER appuser

# Copy in the service code.
COPY --chown=appuser app/ ./app/

# The service listens on port 8000.
EXPOSE 8000

# The command that starts the service when the box runs. 0.0.0.0 means "accept
# connections from outside the box", which is needed for port forwarding.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
