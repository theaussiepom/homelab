# PegaProx: a separate management guest

[Back to application deployment](README.md) ·
[First deployment guest](../bootstrap/README.md)

**This is PegaProx's agreed plan, not a ready-to-run PegaProx installer.** The
first guest and GitHub handover have been proved. The
[HA application jobs](README.md) now have source and synthetic tests; PegaProx's
own installation jobs remain unimplemented.

## PegaProx gets its own LXC

[PegaProx](https://github.com/PegaProx/project-pegaprox) provides a web interface
for managing Proxmox. An **LXC** is a lightweight Linux container hosted by
Proxmox. We have chosen a separate Debian LXC for PegaProx.

Decision documented on **26 October 2026**. No PegaProx guest has been created.

| Guest | Its job |
| --- | --- |
| Deployment guest | Runs reviewed GitHub deployment jobs and holds their active OpenTofu state. It stays dedicated to that work. |
| PegaProx guest | Runs the management web interface, with its own configuration, credentials and memory limit. |
| General applications guest | Runs the applications selected for that guest. PegaProx is kept separate. |

PegaProx holds credentials that can manage Proxmox. Keeping it separate limits
which guest contains those credentials and lets us update or restart the web
interface independently of deployment jobs. Each guest also gets its own memory
limit, so they do not compete inside the deployment guest's current 1 GiB limit.

A separate LXC still uses some RAM. We have not measured PegaProx on this site or
chosen its final CPU/RAM/disk settings; sharing another guest would not remove
the application's memory use.

**Network plan:** place it on your management VLAN with its own stable address
and reviewed firewall access. Keep the actual VLAN number in private site
settings; a particular VLAN number is not a PegaProx requirement.
Other homes can use their management network or a different network with the
[required access](https://docs.pegaprox.com/configuration/ports/).

## How it will be installed

1. **OpenTofu creates the guest** from a reviewed GitHub deployment job.
2. **Ansible installs a selected PegaProx release** and starts its service.
3. **Connect and check it:** sign in, add the intended Proxmox host with separately
   reviewed credentials, and check that the selected management functions work.

Reusable scripts and instructions belong in this public `homelab` repository.
Site addresses, guest selections and deployment jobs belong in the private
deployment repository. Passwords and tokens stay outside public Git.

The bootstrap token is restricted to the first deployment guest. Access to
create the PegaProx guest and PegaProx's own access to Proxmox must be reviewed
for their separate purposes. Some PegaProx features also need SSH access;
see its [permission guide](https://docs.pegaprox.com/configuration/proxmox-permissions/).

## What is still to do?

- Finish the runner's ongoing NAS state backup before further guest rollout.
- Choose an unused guest ID/address and suitable resource limits.
- Prepare the guest definition, installation steps, credentials and firewall
  rules, then test the GitHub jobs on the existing rehearsal system.
- Check the real installation and back up its configuration and required keys.

This adds a management application. Home Assistant, Zigbee, MQTT and Node-RED
still need their own deployment and working-home checks. A successful PegaProx
login does not establish that the house automation has migrated.
