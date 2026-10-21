# Contributing safely

Work on a branch and use a pull request. Main requires signed commits, successful checks, resolved conversations and linear history. Force pushes and deletion of main are prohibited. CodeRabbit supplies advisory reviews; it cannot replace deterministic checks or human judgement. This single-maintainer repository does not require an impossible second-person approval of the maintainer's own PR.

## Local checks

Install Git, Python 3, OpenSSH with SSH signing support, and Gitleaks 8.30.1. The helper `.github/scripts/install_gitleaks.py /path/to/tool-directory` verifies the official release archive before installing it (Linux x86_64 and macOS arm64).

Configure this clone:

```sh
git config core.hooksPath .githooks
git config hooks.gitleaksPath /absolute/path/to/gitleaks
git config user.name YOUR_GITHUB_HANDLE
git config user.email YOUR_GITHUB_NOREPLY_ADDRESS
git config gpg.format ssh
git config user.signingkey /absolute/path/to/your-signing-key
git config gpg.ssh.allowedSignersFile /absolute/path/to/allowed-signers
git config commit.gpgsign true
git config tag.gpgsign true
```

The allowed-signers file must bind your configured email to your public key. Register the public key with GitHub as a **Signing Key**. Keep private keys outside the repository. Signing authenticates authorship; it grants neither push permission nor deployment authority. Interactive workstations can use a protected key and agent. The maintainer's unattended host uses a dedicated signing-only key with restrictive ownership and permissions; its local wrapper refuses to prompt. A compromised signing host can forge signatures, so revoke the public signing key and rotate it after a suspected compromise.

Pre-commit scans the full contents of changed staged files, checks excluded/private paths, and uses pinned Gitleaks rules. It is offline and has a five-second budget. It runs no tests, builds or network operations. Pre-push has a separate five-second budget and checks local outgoing commit identities and signatures. Both fail closed; do not routinely bypass hooks. Large branches should be split into smaller reviewable changes. Clone hooks are not automatically installed by Git; repeat the configuration for every clone.

CI scans complete committed trees and each new commit, so adding then deleting a secret does not make the branch safe. It also tests the guards, validates repository-specific synthetic inputs, reviews dependency changes and performs CodeQL analysis where supported. CI uses hosted runners, read-only default permissions and pinned actions. Fork jobs need maintainer approval and receive no production secrets. GitHub-hosted runs and CodeRabbit coverage must be verified for the latest PR commit before merging.

An exact-path/hash/rule/line exception is a reviewed false positive, not a general permission to store secrets. Changes to `.githooks`, `.github`, reviewed findings, signing, and repository settings need deliberate maintainer review. A single-maintainer ruleset cannot prevent its administrator from changing that ruleset or approving a malicious workflow; keep account 2FA and recovery access secure.

Use squash merges for ordinary PRs. Review the final commit message and author identity before merging. Keep the GitHub handle and GitHub noreply email; do not add personal-email trailers. GitHub signs web-created squash commits. Release tags matching `v*` must be created deliberately by the maintainer; published releases are immutable.
