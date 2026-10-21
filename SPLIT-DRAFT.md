# Repository split draft

Reusable infrastructure and shared execution tooling. The earlier Proxmox draft remains held for real PVE execution.

Nothing in this checkout is committed, pushed or deployed. The GitHub repository is empty. Existing live paths, UID/GID values, runtime data and editor writers remain unchanged.

The earlier three-repository implementation draft and the separately reviewed 526-file configuration candidate are distinct provenance sources. Their previous tests do not establish acceptance of this new five-repository layout.

Before a first commit: reconcile path-dependent tests and inventory/catalog generation, review license/attribution and remaining privacy findings, scan the exact proposed trees and author metadata, and obtain explicit commit/publication authority. Use clean initial history; never push a predecessor branch here.


Source integration update: current tests use the split paths and synthetic fixtures;
fleet inventory is projected from the sole private catalog, and Compose templates
require explicit source roots/private runtime paths. Root MIT licences and bundled
third-party notices are present. Historical acceptance records remain private.
Source validation does not qualify a live deployment. Before publication, review
the exact commit and author metadata, add the separately planned secret/private-file
commit/CI safeguards, and obtain explicit commit and publication authority.
