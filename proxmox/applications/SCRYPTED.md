# Prepare Scrypted without restarting it

[Application guide](README.md)

Scrypted needs a verified decoder path before deployment can be implemented.
This preparation preserves the selected image, numeric user inside the
unprivileged guest, plugins, cameras, NVR settings and credentials, and the
container paths `/server/volume` and `/nvr`.

## Review the proposed inputs

Copy [the invented example](examples/scrypted.preparation.example.json) into your
private site repository and select your existing image ID. Using the pinned
public source, run:

```sh
python3 proxmox/applications/scrypted.py --config /path/to/private/preparation.json
```

This reads one local JSON file and prints a review report. It contacts no host,
reads no capture and emits no Compose file or runnable guest profile. Receipt
values remain private. `deployable` always stays false, even when every receipt
reference is filled. `enabled: true` and claimed decoder selections are refused.
The normal installer explicitly refuses Scrypted before reading target or
credential files. No Actions deployment integration is added in this preparation.

The proposed starting budget is 6 guest CPUs and 5 GiB guest RAM, with 4 CPUs,
4 GiB RAM and 512 tasks for the container. Container logs would rotate at
10 MiB across three files. These are finite review proposals, not measured
capacity requirements or installed settings. A later implementation must also
explicitly bound container swap, retain guest headroom, select guest swap/task
containment and use no automatic restart during qualification.

## Why the decoder decision stays open

Retained incident evidence links repeated unresponsive decoder replacement to
host memory exhaustion. Sampled Node tasks were blocked in host `nouveau`
runtime-resume/DRM paths. Automatic probing could try VAAPI, then Vulkan, then
software fallback; a stuck hardware probe cannot reach fallback. The incident
occurred without `/dev/dri` passed into the container. Removing that mapping or
adding memory/PID limits therefore does not establish a safe decoder path.

Software-only and Intel-only operation are candidates for separately approved
qualification. Neither is selected here. Establish how every relevant installed
plugin avoids NVIDIA/Vulkan enumeration on the exact selected image and restored
plugin versions. Do not invent a configuration switch or upgrade the image to
obtain a green health check. Driver/kernel changes and passthrough need separate
review and maintenance authority.

## Continue through the existing installer

Reuse the application OpenTofu guest module, `deploy.py`, restore helper,
Ansible tasks, saved-plan fingerprint, trusted TLS/SSH identity, NAS state copies
and failure hold. This local review helper is not a deployment engine. Keep an
independent private Scrypted source lock without repinning commissioned services.

1. Admit the exact new guest, networks, packages, capture, image archive and
   metadata. Preserve numeric owners, modes, ACLs, xattrs and original helper
   behavior. Keep plugin/camera/NVR settings and credentials in the frozen
   private capture; commit only verified references and hashes.
2. Bind `/nvr` to the exact selected recording source. A source guard must reject
   absent, wrong and read-only sources before any writer starts. Never let
   Docker create an empty local fallback. Preserve recording names, paths and
   ownership, and explicitly decide protection/recovery of new recordings.
3. Resolve DBus/Avahi and discovery inside the guest. Do not copy broken host
   socket binds or expose Proxmox host control sockets. Admit only a reviewed
   device path, if any; no privileged-container fallback.
4. Implement the verified decoder path and approved finite resource/swap, task,
   log and restart settings. Keep the old writer retired and recovery available
   before the explicit start phase. A failed operation retains its hold.
5. In a separately authorized target window, check real plugins, cameras,
   discovery, HA/API consumers, actual listeners, TLS/authentication, old
   playback and new recording continuity under representative load. Repeated
   decoder start/stop and motion cycles must return workers to baseline,
   stabilize memory and produce no new blocked-task reports. A port response
   alone is insufficient.

Earlier exact-image synthetic unprivileged-LXC evidence covered basic startup,
synthetic persistence and multicast under its tested kernel/runtime. It did not
exercise real cameras, restored plugins, recording writes or the incident
probe path. It is version-specific compatibility evidence, not native deployment
approval. Source tests here exercise refusal and review behavior only. They do
not launch Scrypted or prove the driver deadlock is fixed.
