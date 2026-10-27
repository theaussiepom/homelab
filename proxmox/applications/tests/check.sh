#!/bin/sh
# Run inside the pinned bootstrap Docker tools, without network or target access.
set -eu
export PYTHONDONTWRITEBYTECODE=1
python3 -m unittest discover -s /src/proxmox/applications/tests -v
python3 /src/proxmox/applications/tests/restore_fixture.py
python3 /src/proxmox/applications/tests/database_account_fixture.py
python3 /src/proxmox/applications/tests/database_server_fixture.py
python3 /src/proxmox/applications/tests/runner_network_guard_fixture.py
python3 /src/proxmox/applications/tests/ingress_network_guard_fixture.py
cp -R /src/proxmox/applications/tofu /tmp/app-tofu
cd /tmp/app-tofu
tofu fmt -check -recursive
tofu init -backend=false -input=false -lockfile=readonly -no-color
tofu validate -no-color
tofu test -no-color
export ANSIBLE_LOCAL_TEMP=/tmp/ansible-local
export ANSIBLE_CONFIG=/src/proxmox/applications/ansible/ansible.cfg
ansible-playbook -i localhost, --syntax-check /src/proxmox/applications/ansible/site.yml
ansible-playbook -i localhost, --syntax-check /src/proxmox/applications/ansible/verify.yml
ansible-playbook -i localhost, --syntax-check /src/proxmox/applications/ansible/network-startup.yml
ansible-playbook -i localhost, --syntax-check /src/proxmox/applications/ansible/ingress-network-startup.yml
ansible-playbook -i localhost, --syntax-check /src/proxmox/applications/ansible/component-image.yml
ansible-playbook -i localhost, --syntax-check /src/proxmox/applications/ansible/component-acme.yml
