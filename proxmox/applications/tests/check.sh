#!/bin/sh
# Disposable source fixture container; no target credentials or host devices.
set -eu
export PYTHONDONTWRITEBYTECODE=1
python3 /src/tools/measure_coverage.py --suite applications --output "${HOMELAB_COVERAGE_OUTPUT:-/tmp/application-coverage}"
python3 /src/proxmox/applications/tests/package_install_fixture.py
python3 /src/proxmox/applications/tests/database_account_fixture.py
python3 /src/proxmox/applications/tests/database_server_fixture.py
python3 /src/proxmox/applications/tests/runner_network_guard_fixture.py
cp -R /src/proxmox/applications/tofu /tmp/app-tofu
cd /tmp/app-tofu
tofu fmt -check -recursive
tofu init -backend=false -input=false -lockfile=readonly -no-color
tofu validate -no-color
tofu test -no-color
export ANSIBLE_LOCAL_TEMP=/tmp/ansible-local
export ANSIBLE_CONFIG=/src/proxmox/applications/ansible/ansible.cfg
ansible-playbook -i localhost, --syntax-check /src/proxmox/applications/ansible/reconcile.yml
ansible-playbook -i localhost, --syntax-check /src/proxmox/applications/ansible/preparation.yml
ansible-playbook -i localhost, --syntax-check /src/proxmox/bootstrap/ansible/host-device.yml
