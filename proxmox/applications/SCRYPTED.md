# Deploy prepared Scrypted state

[Application guide](README.md) · [Restricted NFS setup](../bootstrap/NFS-ATTACHMENT.md)

The component Scrypted profile retains local configuration/database at
`/server/volume` and external NFS recordings at `/nvr`. It uses the requested
floating latest image, numeric user0:0, finite memory/swap/CPU/PID/log limits and
no automatic restart. It does not pass GPU devices or initialise retained data.

Create the empty guest and its local volumes through ordinary protected CD.
Bootstrap provisions the separate restricted NFS attachment capability and its
protected `PROXMOX_NFS_SSH_KEY` secret. The site's context references that key and
pinned host trust. Selecting the existing `host_bind` declaration causes the
Infrastructure phase to attach and verify the exact NFS directory before the
saved provider plan. Identical attachment is a no-op; conflicts, pending mount
changes, a local fallback, earlier-volume changes and replacement are refused.
See the [storage contract](../../docs/reference/storage.md) for the closed fields.

Local configuration/database import uses separately reviewed protected input,
with original plugins, cameras, NVR settings, credentials, numeric metadata and
recovery material preserved. Ordinary CD does not restore or convert that state.
The source and runtime guards require the exact writable recording source and
an existing database. A pre-start settings guard refuses hardware/default
decoder settings before the upstream server starts.

The separately retained `scrypted.py` review helper describes historical
preparation inputs and emits no deployment. Use the component profile and normal
protected CD for installation and subsequent maintenance.

Passing source validation or a mount proof does not establish service acceptance.
Verify restored login/cameras, authentication/routing, old playback, new recording
continuity and intended software decoding with bounded resource observation.
Preserve failed attempts, receipts, locks and holds. Do not probe GPU, PCI, DRM or
sysfs paths as part of deployment. No scanner, source or runtime guard proves the
historical driver deadlock is fixed.
