# Set up restricted NFS attachment

[Bootstrap guide](README.md) · [Storage contract](../../docs/reference/storage.md)

Bootstrap installs a dedicated host capability for guest provisioning. The
application key remains a separate guest-login identity. The NFS key can append
a declared bind from an existing NFS filesystem to any eligible LXC; it has no
VMID allowlist, shell, forwarding or arbitrary-command access. It cannot create
an NFS export, create source data, replace an existing bind or change another
mount. The host's existing firewall policy must admit the runner's TCP22 path.
This setup does not edit that policy or attach guest storage.

## Prepare the operator inputs

Use the same built `homelab-bootstrap-test:1` image and operator SSH credentials
as the [bootstrap setup](README.md). The host and runner must already exist.
Use a trusted known-hosts file containing both reviewed addresses. The selected
private GitHub repository must grant your existing `gh` login administration
access; each named guest Environment must already restrict deployments to main.
The normal deployment queue must be idle during operator bootstrap work.

From the framework root, set these private values in your shell:

```sh
export HOMELAB_SSH_KEY=/absolute/private/operator-key
export HOMELAB_KNOWN_HOSTS=/absolute/private/pinned-known-hosts
NFS_SITE_REPOSITORY=example-owner/private-site
NFS_HOST_ADDRESS=192.0.2.10
NFS_RUNNER_ADDRESS=198.18.25.10
NFS_JOB_ENVIRONMENT=example-apps-cameras
NFS_ATTEMPT=/absolute/private/new-nfs-bootstrap-attempt
proxmox/bootstrap/bootstrap nfs-access \
  --repository "$NFS_SITE_REPOSITORY" --host "$NFS_HOST_ADDRESS" \
  --runner "$NFS_RUNNER_ADDRESS" --environment "$NFS_JOB_ENVIRONMENT" \
  --out "$NFS_ATTEMPT"
```

The addresses above are synthetic. `NFS_ATTEMPT` must be a new directory outside
source. Repeat `--environment` to deliver the same dedicated key to another
existing main-only guest Environment. These names select secret delivery; they
do not restrict which VMIDs the host helper supports.

## What bootstrap owns

The script creates an Ed25519 pair at
`/home/homelab-runner/.ssh/proxmox-host-nfs` only when both files are absent.
Existing pairs must match, remain runner-owned, and have a private mode0600 file.
Partial, linked, changed or application-key pairs are refused. The host receives
root-owned mode0755 `/usr/local/libexec/homelab-host-nfs.py` and one authorized
key line with `restrict`, the runner's exact source address and a forced
`/usr/bin/python3 -I` invocation. Conflicting key authority or helper bytes are
preserved and refused. The existing host authorizations are saved privately.

Key generation, retained-key derivation and the capability probe run as the
runner user with private scratch space at `/home/homelab-runner/.ansible/tmp`.
These tasks do not reuse the root tasks' temporary directory or relax its
permissions. Ansible creates the runner's scratch directory privately as needed.

The focused regression runs in the existing bootstrap test image:

```sh
docker run --rm --platform linux/amd64 --network none -v "$PWD:/src:ro" -w /src \
  homelab-bootstrap-test:1 python3 -m unittest discover \
  -s proxmox/bootstrap/tests -p test_nfs_access.py
```

It exercises the real root-to-unprivileged-user boundary, including key creation
and reuse. The capability probe uses an inert local command; the test contacts
no host and does not establish native bootstrap or guest mount acceptance.

Bootstrap pins the host key at `/var/lib/homelab-inputs/nfs-host-known_hosts`
without replacing existing trust, then verifies the installed helper digest
through the restricted key. The dedicated private key passes through a temporary
mode0700 transport directory to `gh secret set PROXMOX_NFS_SSH_KEY` on stdin.
The fetched controller file is explicitly restricted to mode0600 before it is
read for delivery, independent of the Ansible process umask. It never appears
in arguments, logs or source. The temporary transport is removed;
the original key remains on the runner. The private attempt records safe status
and preserves failure evidence. A failed step is not automatically retried.

## What ordinary CD owns

A context declares one `nfs-attachment` capability referencing this key file and
pinned trust. A selected `host_bind` causes only its Infrastructure step to
receive `PROXMOX_NFS_SSH_KEY`; other guest/app steps do not receive the key.
Credential binding refuses another retained key or the application identity.

Under the normal guest attempt/ownership locks, Infrastructure validates the
genuine previous guest state, then invokes the forced helper before provider
planning. The helper checks the closed request, live guest identity, complete
previous mount sequence, current digest, pending changes and real writable NFS
source without following symlinks or allowing a local directory fallback. The
opened directory’s mount ID and device must match its NFS mountinfo row, even
when autofs and NFS share a mountpoint. An
identical bind is a no-op; a conflicting slot or earlier mount is refused.

For an absent bind, the helper gracefully stops a running guest, verifies it is
stopped, temporarily clears protection, appends only the declared mount with
backup and replication disabled, and restores and verifies protection even if
the append fails. Only a successful verified attachment restarts a previously
running guest. It then checks the active NFS projection and exact directory
identity. It never force-stops, removes mounts, copies state or starts an app.
A failure leaves the ordinary attempt held for operator inspection.

The provider refresh sees that verified native bind before constructing its
saved plan. Existing replacement and ForceNew refusals remain mandatory; CD
records only the admitted append in its owned backend. No direct state editing,
ignored drift or second mount writer is introduced. Subsequent runs preserve
identity and repeat native/guest checks. Application-specific data import and
service acceptance stay separate from storage provisioning.
