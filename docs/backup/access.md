# Create API access and GitHub secrets

[Backup setup](README.md) → [Recovery key](recovery-key.md) → **API access** → [Configure backups](configure.md)

Create one dedicated PBS management identity, then store its token in the protected deployment repository. This is the initial trust that lets CD use the prepared datastore and create and maintain declared namespaces and client credentials. It is separate from your recovery key and normal PBS administrator login.

## Before you start

Complete [server setup](server.md). Use its trusted console or authenticated PBS interface. Have administrator access to the deployment repository and a reviewed GitHub Environment policy. Do not perform this task from an untrusted pull request, a recorded terminal, or a shell with tracing enabled.

The examples use PBS user `homelab-cd@pbs`, token name `deployment`, GitHub Environment `backup` and Environment secret `PBS_API_TOKEN`. Keep those names consistent with the [site management binding](../reference/backup.md#backup-management). The token's identity is `homelab-cd@pbs!deployment`; the generated secret is a separate value returned only once.

## Choose the management permissions

The bootstrap procedure below assigns PBS **Admin at `/`** to the dedicated user and its management token. This is broad server administration, including destructive capabilities. It is intended for an explicitly approved PBS-management job; it is not a backup-only grant. PBS permission-management authority itself can grant wider access, so a source allowlist is not an independent server-enforced security boundary.

Before creating the identity or token, the installation owner (or their designated security administrator) must approve the specific Admin-at-`/` grant to this automation identity. Record who approved it and its intended use in the private installation notes. If your organisation requires a narrower role matrix, qualify the exact API operations and effective permissions before use; do not weaken checks until deployment works. Ordinary guest tokens receive only their own namespace's backup/restore permissions and never this management credential. See [PBS roles and token permission intersection](https://pbs.proxmox.com/docs/user-management.html#api-token-permissions).

## Create the user and token

In the **PBS web interface**:

1. Open **Configuration → Access Control → User Management** and create user `homelab-cd` in the `pbs` realm. Give it a descriptive comment. This identity is for token-based automation; it does not need an interactive password.
2. Open **API Tokens**, select that user and create token `deployment`. If you choose an expiry, arrange renewal before it expires; an expired management token must not be silently replaced by CD.
3. Immediately save the returned token identity and secret in a protected temporary record. PBS cannot display the secret again. Do not put it in a screenshot, issue, chat or Git file.
4. Under **Permissions**, add the approved Admin role at `/`, with propagation, for both `homelab-cd@pbs` and `homelab-cd@pbs!deployment`. A token's effective access is restricted by both grants.

The equivalent **first-installation commands** below run in an interactive root Bash shell on the trusted PBS server, from any private working directory. They change accounts and permissions. Check that the names are unused first, run once, and stop on errors. The token-generation command displays a secret: capture it privately before closing the session. Do not run these through CI or an output-recording helper.

Confirm that terminal/session recording is disabled before continuing. Shell settings cannot turn off an external recorder. In this private interactive Bash session, disable tracing and history before generating the secret; restore your normal shell policy after transfer. The following settings prevent shell tracing/history capture, but do not make an otherwise recorded terminal safe.

```bash
set +x
set +o history
proxmox-backup-manager user list
proxmox-backup-manager user create homelab-cd@pbs --comment 'HomeLab backup management'
proxmox-backup-manager user generate-token homelab-cd@pbs deployment
proxmox-backup-manager acl update / Admin --auth-id homelab-cd@pbs --propagate true
proxmox-backup-manager acl update / Admin --auth-id 'homelab-cd@pbs!deployment' --propagate true
proxmox-backup-manager user permissions 'homelab-cd@pbs!deployment' --path /
```

Use **either** the UI route or the commands, not both. The last command reports effective permissions without returning the token secret. If an identity already exists or the secret is lost, preserve the existing account and records; explicitly investigate ownership before replacement. [Native account/token commands](https://pbs.proxmox.com/docs/proxmox-backup-manager/man1.html)

## Store the token in GitHub

The secret value has exactly this shape: `token-identity:token-secret`, with no spaces, quotes, HTTP-header prefix or line break. For this example, the identity portion is `homelab-cd@pbs!deployment`. Append a colon and the actual generated secret. This is the value used in PBS's `PBSAPIToken` authentication header; the workflow supplies the header prefix itself.

In **your deployment repository**, not the public framework/library:

1. Open **Settings → Environments** and create or select `backup`.
2. Restrict deployment branches/tags to your reviewed production branch policy. Apply available reviewer protections according to your plan and repository visibility; do not assume every GitHub plan supports private-repository approval gates.
3. Under **Environment secrets**, add `PBS_API_TOKEN` with the combined value described above.
4. Make the backup management job use that Environment. Only that job receives the token; guest jobs and pull-request validation do not.

The following **alternative GitHub CLI commands** run on your trusted workstation with `gh` installed and already authenticated. They write one Environment secret; they do not install `gh` on PBS or create its Environment. First replace `example-owner/example-site` with your deployment repository and create/protect `backup` in the UI as above.

```bash
PBS_SITE_REPOSITORY=example-owner/example-site
gh secret set PBS_API_TOKEN --repo "$PBS_SITE_REPOSITORY" --env backup
gh secret list --repo "$PBS_SITE_REPOSITORY" --env backup
```

Paste the combined value only at the interactive secret prompt. The listing confirms the name exists, not that its value is correct. GitHub does not return saved secret values; verify authentication during the management job's preflight without printing the header or secret. See [GitHub Environment secrets](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets#creating-secrets-for-an-environment) and [Environment protection availability](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

## What goes where

| Input | Storage | Consumer |
| --- | --- | --- |
| `PBS_API_TOKEN` | GitHub `backup` Environment secret | PBS management job only |
| PBS endpoint and certificate fingerprint | [Destination configuration](../reference/backup.md#backup-job-destination) | Management preflight and backup clients |
| Recovery public PEM | Site-relative public file referenced by [backup configuration](../reference/backup.md#backup-recovery-public-key) | Enrolled clients |
| Recovery private PEM and passphrase | [Independent recovery stores](recovery-key.md#store-independent-recovery-copies) | Recovery operator only |
| Per-client tokens/keys | Protected create-once controller records and guest files | That client's backup worker |

The Backup job also needs the existing deployment SSH and PVE credentials to verify completed guest identities and install the declared backup configuration under the existing locks. Follow the [normal deployment setup](../guides/prepare-deployment.md#prepare-the-protected-workflow) to make only `APPLICATION_SSH_KEY` and `PROXMOX_APP_TOKEN` available to its protected `backup` Environment. Copy existing encrypted values through your protected credential procedure; do not create broader accounts. These are explicit job inputs, not inherited secrets. No recovery private key, recovery passphrase or per-guest token needs a GitHub secret.

The managed native client key uses `--kdf none` so scheduled jobs do not need a separate unlock secret. The key file itself is therefore not passphrase-encrypted: it is stored as root-only `0600` on its guest and as `0600` inside the CD account's `0700` ownership record on the controller. This does **not** disable backup encryption. Anyone who obtains that key and the encrypted backup can decrypt the client's data, so protect both machines and their storage. The independently stored recovery private PEM remains passphrase-encrypted. See [the three credential roles](recovery-key.md#understand-the-three-credentials).

## Check the handoff

Before [configuring backups](configure.md), confirm the user/token exist, their effective permissions match the approved role, and GitHub shows the secret in the intended Environment. Keep recovery access to PBS independent of this one CI token. Remove temporary transfer copies only after successful protected authentication has proved the stored value works; do not delete the independent recovery material.

Later token replacement is deliberate: establish the replacement, update the Environment secret, verify it through the protected job, then revoke the old token under the operator's change procedure. Changing this management token does not require changing client encryption keys or rewriting backup history.
