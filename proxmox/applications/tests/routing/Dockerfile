ARG TOOLS_IMAGE=homelab-app-test
FROM ${TOOLS_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends iproute2=6.15.0-1 iptables \
    && rm -rf /var/lib/apt/lists/*
