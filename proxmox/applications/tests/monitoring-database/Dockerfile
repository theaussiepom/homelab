FROM --platform=linux/amd64 postgres:16@sha256:38471f330eb885e04de130b768d6db4e10469e2311879c7e5c699f6d2d8a1c74
# Python is fixture tooling only; the commissioned database guest already has it.
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
