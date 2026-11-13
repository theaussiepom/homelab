FROM --platform=linux/amd64 debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates python3 python3-venv python3-apt openssh-client git \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.lock.txt /opt/requirements.lock.txt
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r /opt/requirements.lock.txt
ENV PATH="/opt/venv/bin:/opt/bin:${PATH}" PYTHONDONTWRITEBYTECODE=1
COPY tools.json install-tools.py /opt/
RUN python3 /opt/install-tools.py
COPY versions.tf .terraform.lock.hcl /opt/provider-root/
RUN cd /opt/provider-root && tofu init -backend=false -input=false -lockfile=readonly -no-color \
    && tofu providers mirror /opt/provider-mirror
RUN printf 'provider_installation {\n filesystem_mirror {\n path = "/opt/provider-mirror"\n }\n}\n' > /opt/tofu.rc
ENV TF_CLI_CONFIG_FILE=/opt/tofu.rc TF_IN_AUTOMATION=1 CHECKPOINT_DISABLE=1
ARG HOST_UID=1000
ARG HOST_GID=1000
# OpenSSH needs a passwd entry even when Docker already runs as this numeric UID.
RUN if ! getent group "$HOST_GID" >/dev/null; then groupadd --gid "$HOST_GID" homelab-bootstrap; fi \
    && if ! getent passwd "$HOST_UID" >/dev/null; then \
      useradd --uid "$HOST_UID" --gid "$HOST_GID" --no-create-home --home-dir /tmp homelab-bootstrap; \
    fi
WORKDIR /src
