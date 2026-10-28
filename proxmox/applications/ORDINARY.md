# One permanent deployment job per guest

A managed guest keeps one clearly named deployment job throughout its life.
Completing a migration does not remove that job. Keep selection, OpenTofu and
application Ansible as visible steps within it. The parent queue retains real
dependencies; independent ready guests use only admitted runner slots.

The ordinary adapter is a small extension of the existing application installer.
It reuses its OpenTofu module, authoritative backend, plan checks, pinned SSH
trust, backups and Ansible package/database/Compose tasks. It adds no runner,
controller, scheduler or recovery service.

## What the job does

1. Select the reviewed immutable public source and private desired settings.
   Keep the job visibly disabled until inputs and native authority are ready.
2. OpenTofu creates a missing guest with empty custody, or safely reconciles its
   current approved infrastructure. It never adopts or replaces a guest,
   recreates one whose installation evidence exists without state, destroys
   data, changes its data volumes, or accepts unexpected provider drift.
3. Ansible reconciles approved packages/configuration and checks the service.
   Existing application data must already be prepared. This playbook has no
   restore task and does not import SQL, convert HA settings or alter saved
   pgAdmin database profiles.
4. Retain a completed binding to the desired inputs, reusable source and backend
   state. Matching later runs return `changed: false` without target commands.
   New approved inputs take the same OpenTofu/Ansible path.

The private site derives database attachments and narrow peer rules from its
single canonical catalogue. A completed network move becomes the ordinary
baseline. Original installation inputs remain evidence and must never overwrite
that current baseline with old network assignments.

For automation, the same adapter serves one guest with ordered MQTT, HA and
Node-RED steps. Each service uses `--no-deps`; later steps cannot bypass their
predecessors or restore shared data. The original custom images, encryption
settings and login semantics stay selected. Home Assistant retains its own
login; Node-RED retains its native Authentik login.

## Failures and one-time work

Original installation/migration receipts stay immutable. Ordinary receipts use
a separate directory in the same guest state. Holds are written before native
work and retained on interruption or failure. Only the same successful run can
finish its next visible step. There is no automatic retry, rollback, hold clearing
or data restoration. A new run cannot continue an incomplete native operation.

Data projection, configuration migration, restored database selection, exclusive
writer handover and radio/USB admission remain separate explicit work. Prepare
those exact inputs before enabling the job. Keep unready guests visibly disabled.
Remove only completed one-time work; retire a normal deploy job only when the
guest itself is deliberately retired.

## Validation limits

Synthetic tests cover matching bindings, safe plan scope, unchanged results,
ordered service steps, data-volume protection and durable failures. Existing
Linux fixtures exercise shared restore/account/network/package tasks, mock
OpenTofu plans and Ansible syntax. These checks do not establish native ordinary
convergence, exact current guest state, physical USB behavior, successful browser
login, SQL authentication or household acceptance. Record those facts only from
the authorized target window.
