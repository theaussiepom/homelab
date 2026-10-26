# Connect your private repository

[Application guide](../README.md)

These files let your private GitHub repository use the reusable scripts in
public HomeLab. Your application passwords and restored settings stay outside
both repositories.

## Copy three files

Create these folders in the private repository, then copy the files to the
destinations shown:

| Copy this file | Put it here in the private repository |
| --- | --- |
| [applications.yml](applications.yml) | `.github/workflows/applications.yml` |
| [application_source.py](application_source.py) | `.github/scripts/application_source.py` |
| [source.json](source.json) | `applications/source.json` |

In `source.json`, replace the placeholder with the **full 40-character commit
ID of a reviewed, merged HomeLab revision**. A branch name such as `main` is
deliberately refused: the code you reviewed should be the code that runs.

In `applications.yml`, replace `homelab-deploy-SITE` with the unique label of
your deployment runner from the [bootstrap](../../bootstrap/README.md).
Keep the private-repository and `main` branch checks. Never attach this
deployment runner to a public repository.

## Supply one guest's settings

The workflow reads the selected guest's private JSON file from the runner,
for example `/var/lib/homelab-inputs/dns.json`. Use the
[synthetic example](../examples/site.example.json) and
[technical input reference](../OPERATIONS.md) to prepare it. Example package
versions, images and addresses are placeholders; they cannot be deployed as-is.
Restrict the directory to the runner account and its files to mode `0600`.

Before running, complete the application guide's prerequisites: API access
for that guest, network paths, NAS recovery copies and coherent source captures.
Declare the application's API access through bootstrap configuration first;
Deploy does not grant extra token permissions.

Commit the workflow and source lock to the private repository's `main` branch.
Open **Actions → Application guest deployment**, select one guest and choose
**plan** first. Review its fingerprint, then choose **deploy** with that
fingerprint during the selected service's migration window. That one run creates
the guest, verifies its SSH identity through Proxmox, installs/restores, starts
and checks the service. Copying these templates does not start a deployment.
