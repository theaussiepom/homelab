# Fast staged-source check

The pre-commit hook checks only added, modified, renamed or type-changed **index
blobs**, not the working files, old commits or untracked files. Deleted files
need no content scan. It performs no network requests, dependency installation,
builds, service commands or application tests.

## Setup and use

Requires Git, Python 3.11+ and an already installed Gitleaks **8.30.1**. Install
the scanner separately from its official release and verify its checksum.

```sh
git config --local core.hooksPath .githooks
# Optional when the verified scanner is not on PATH:
git config --local hooks.gitleaksPath /absolute/path/to/gitleaks
python3 .githooks/staged_guard.py
```

The hook runs automatically on a normal `git commit`. `GITLEAKS_BIN` can select
an installed binary when testing. There is no automatic download or update.
Git hooks are a local safeguard and can be bypassed; server-side controls are
separate work. A clone must enable its own hook using the setup command above.

## Checks and bounds

- Conventional private/runtime paths and paths excluded by **staged** `.gitignore`
  rules are refused, including files force-added to the index. Examples/templates
  are still scanned for secrets; their suffix is not a content exemption.
- Gitleaks runs its bundled default rules over complete changed text blobs.
  This catches secrets elsewhere in a modified file, not just added diff lines.
  Inline allow comments, repository scanner configs and ignore fingerprints
  cannot silently disable this scan.
- Symlinks, submodules, unresolved merges, archives, binary/non-UTF-8 files and
  oversized inputs are refused for a separate review rather than silently skipped.
- Limits: **five seconds**, **2,000 changed files**, **2 MiB per file**, **16 MiB total**.
  Missing/wrong-version scanners, errors and timeouts block the commit.
- Git index bytes are compared before/after checking; concurrent index changes
  block the commit. The guard does not alter the index, source, or permissions.

The scanner receives a mode-0700 temporary snapshot; files/reports stay under
that directory and are removed when the process exits normally or handles a
failure. Output contains only status, paths, rule IDs, line numbers and timing,
never matching values. Abrupt process termination can leave a private temporary
directory to remove later.

Previously reviewed false positives live in `reviewed-findings.json`. Every
exception binds one **path, full-file SHA-256, rule and line**, with a reason.
Changing the file invalidates that exception. Review a new finding before
updating this file; never suppress a whole directory or scanner rule to make
a check pass. Exceptions are read from the index, so unstaged edits do not
affect the proposed commit.

This is a fast prevention check, not a complete security/privacy audit. It does
not compare private credential stores, determine whether household identifiers
are sensitive, inspect old history, or prove runtime security.

## Regression tests

```sh
python3 -B .githooks/test_staged_guard.py
```

Tests use disposable Git repositories and synthetic credential-shaped fixtures.
They exercise actual hook acceptance/refusal, partial staging, staged ignore
rules, byte-pinned exceptions, scanner failures and the five-second timeout.
