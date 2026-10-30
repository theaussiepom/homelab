#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BUILDER_IMAGE="${BUILDER_IMAGE:-homelab-proxmox-iso-builder:9.2-1}"
TEST_IMAGE="${TEST_IMAGE:-homelab-proxmox-iso-test:9.2-1}"
action="${1:-help}"
if [[ "$action" == init ]]; then
    umask 077
    mkdir -p .local build evidence
    chmod 700 .local build evidence
    for name in hardware site media-approval; do
        if [[ ! -e ".local/$name.json" ]]; then cp "config/$name.example.json" ".local/$name.json"; fi
    done
    echo 'Created local settings in .local/. Existing files were preserved.'
    exit 0
fi
if [[ "$action" == tools ]]; then
    docker build --platform linux/amd64 -f docker/Dockerfile.build -t "$BUILDER_IMAGE" .
    docker build -f docker/Dockerfile.test -t "$TEST_IMAGE" .
    exit 0
fi
if ! docker info >/dev/null 2>&1; then echo 'Docker is unavailable. Start Docker Desktop (or the Docker service), then try again.' >&2; exit 1; fi
umask 077
mkdir -p build evidence .local
base=(--rm --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --cpus 1 --memory 2g -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONPATH=/work/src -e GNUPGHOME=/work/build/gnupg --mount "type=bind,src=$ROOT,dst=/work,readonly" --mount "type=bind,src=$ROOT/build,dst=/work/build" --mount "type=bind,src=$ROOT/evidence,dst=/work/evidence")
case "$action" in
    fetch) docker run "${base[@]}" --platform linux/amd64 --network bridge "$BUILDER_IMAGE" python3 scripts/prepare-vendor.py --fetch ;;
    prepare) docker run "${base[@]}" --platform linux/amd64 --network none "$BUILDER_IMAGE" python3 scripts/prepare-vendor.py ;;
    unit|fixture|build-production|qualify) docker run "${base[@]}" --platform linux/amd64 --network none "$BUILDER_IMAGE" python3 scripts/workflow.py "$action" ;;
    test-boot|test-profile|test-case)
        vm=(--rm --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --cpus 2 --memory 4g --network none -e PYTHONDONTWRITEBYTECODE=1 --mount "type=bind,src=$ROOT,dst=/work,readonly" --mount "type=bind,src=$ROOT/build,dst=/work/build" --mount "type=bind,src=$ROOT/evidence,dst=/work/evidence")
        docker run "${vm[@]}" "$TEST_IMAGE" python3 scripts/workflow.py "$action" ${2:+"$2"}
        ;;
    password-hash) docker run "${base[@]}" --platform linux/amd64 --network none -it --mount "type=bind,src=$ROOT/.local,dst=/work/.local" "$BUILDER_IMAGE" python3 scripts/password-hash.py ;;
    *) echo "Unknown action: $action" >&2;exit 2 ;;
esac
