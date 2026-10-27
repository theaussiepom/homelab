ARG TOOLS_IMAGE=homelab-app-test
FROM ${TOOLS_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server nftables iproute2 \
    && rm -rf /var/lib/apt/lists/*
