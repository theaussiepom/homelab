# Set up backups

[Documentation](../README.md) · [Initial deployment setup](../guides/prepare-deployment.md) · [Backup configuration reference](../reference/backup.md)

This section takes you from an empty backup server to encrypted backups that run unattended and have been tested by restoring data. It is written for the person setting up their first HomeLab installation. Use it during initial deployment preparation, before relying on backup schedules.

You install Proxmox Backup Server (PBS), prepare its storage and initial credentials, and keep an independent recovery key. Your site configuration then tells CD which guests to protect. CD configures those clients; the installed scheduler runs the backups. You do not log in to a password manager or create a new account by hand whenever you add a guest.

## Follow these steps in order

Follow the documented sequence for setup and verification. If an instruction is missing, fails, or requires a different action, stop that step and correct this guide before performing the alternative. After corrections, use the [clean rehearsal procedure](operations.md#rehearse-an-amended-guide-from-a-clean-setup) to prove the complete amended flow without undocumented leftovers.

| Step | Task | You finish with |
| --- | --- | --- |
| 1 | [Install and prepare PBS](server.md) | A reachable, trusted server with a verified persistent datastore and working administrator access |
| 2 | [Create and store the recovery key pair](recovery-key.md) | A public PEM for configuration and verified private copies outside the protected estate |
| 3 | [Create the API token and GitHub secret](access.md) | One protected management credential placed for the [setup and guest enrollment steps](access.md#what-goes-where) |
| 4 | [Configure and deploy backups](configure.md) | Selected guests, storage coverage, schedules and credentials installed through CD |
| 5 | [Verify and operate backups](operations.md) | A real backup, a successful isolated restore, retention and alerts, and a completed unattended-operation checklist |

**Do not stop at a green CD run.** It establishes that deployment completed. The last step establishes that the selected data can actually be recovered and that failures will be noticed.

## What each part does

| Part | Responsibility |
| --- | --- |
| PBS server | Stores backup data; runs verification, retention and garbage collection according to its configured jobs |
| Site-root `backup` | Holds shared backup settings; its presence does not enroll every guest |
| Guest `backup:` | Enrolls that guest and includes the client setup in its deployment |
| App recovery catalogue | Classifies app configuration, durable state, database exports and excluded transient/rebuildable data |
| Volume `backup:` | Includes a managed volume in the enrolled guest's native full-guest backup selection |
| CD | Uses the prepared datastore and manages declared namespaces and client setup, preserving identities and encryption keys |
| Installed backup scheduler | Runs backups between deployments; GitHub does not need to remain available |
| Recovery private key | Lets an operator recover client keys if the clients and controller are lost; normal CD never reads it |

The coordinated application-backup scheduler runs on the controller. Losing that controller stops its scheduled application backups until recovered. PBS server-maintenance jobs and any independently configured native PVE backup jobs have separate execution owners.

## Know what you are protecting

There are two complementary layers:

- **Application recovery:** configuration, durable files captured consistently and native database exports. This is the HomeLab guest-client job described in this section.
- **Full guest recovery:** native Proxmox Virtual Environment (PVE) backups of the operating system and included managed volumes. These need their own PVE-to-PBS storage and backup-job setup; installing a client inside a guest does not create them. See [full-guest protection](operations.md#full-guest-protection).

Temporary files, caches and scratch exports are not a replacement for durable recovery data. A copied live database directory is not a substitute for a coherent native export. Start with your selected library's [app recovery classifications](https://github.com/theaussiepom/homelab-stack/blob/main/docs/reference/backup-coverage.md) and the framework's [coverage rules](../reference/backup.md#application-recovery-declarations). Library main can change; use the documentation at your selected library revision when preparing a deployment.

## Keep these materials separate

| Material | Normal location | In GitHub secrets? |
| --- | --- | --- |
| PBS management API token | [Selected setup and enrolled-guest Environments](access.md#what-goes-where) in your deployment repository | Yes: `PBS_API_TOKEN` |
| Recovery public PEM | Referenced file in your site repository | No; it is public material |
| Recovery private PEM and passphrase | Password manager plus independently recoverable offline copies | No |
| Per-client PBS token and encryption key | Protected controller records and root-only files on that client | No manual per-guest GitHub copies |
| Datastore names, endpoint, trust fingerprint and schedules | Site configuration | No; these are configuration, not secret values |

The names used in this guide are synthetic. Your actual addresses, paths, repository, retention requirements and operating authority belong in your deployment repository. Begin with [server setup](server.md).
