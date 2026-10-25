# Check staged files before committing

[Back to the main README](../README.md) ·
[Full contributor setup](../docs/contributing-safely.md)

These Git hooks help prevent private files, credentials and unsafe source
formats from entering a commit. They are for contributors changing this
repository; you do not need to configure them merely to use the Proxmox guides.

**Staged files** are the versions selected by `git add` for the next commit.
The pre-commit check reads those exact Git blobs, not potentially different
working files.

## What you need

- Git and Python **3.11 or newer**.
- A verified installation of Gitleaks **8.30.1**, the secret scanner.
- A clone of this repository, with your normal commit-signing setup.

Use [contributing safely](../docs/contributing-safely.md) for the verified scanner
installer, signing requirements and complete CI expectations. No scanner download,
dependency installation, build or application test runs inside the hook.

## 1. Enable hooks in this clone

From the **repository root**:

```sh
git config --local core.hooksPath .githooks
```

If the verified scanner is not on your PATH, set its actual absolute path:

```sh
git config --local hooks.gitleaksPath /absolute/path/to/gitleaks
```

Each new clone needs its own setup. `GITLEAKS_BIN` can select an installed binary
when testing; it does not trigger a download or update.

## 2. Check the staged version

After selecting your intended files with `git add`, run:

```sh
python3 .githooks/staged_guard.py
```

**Expected result:** a successful status report. It reports paths, rule IDs and
line numbers when needed, never the matching secret values. It does not change
your files, Git index or permissions. Normal `git commit` runs the same check
automatically.

The guard checks added, modified, renamed and type-changed files. Deleted files
need no content scan. Old commits and untracked files are outside this fast
staged check; CI separately scans committed trees and new history.

## When something goes wrong

| What you see | What to do |
| --- | --- |
| Missing or wrong scanner version | Install/choose verified Gitleaks 8.30.1 using the contributor guide. |
| Private path or ignored file refused | Remove it from the proposed commit; keep the real file private. Do not force-add it to bypass the guard. |
| A secret finding | Inspect privately and replace/remove the sensitive value. An exposed credential also needs its own incident response. |
| Suspected false positive | Review that exact finding before updating the narrowly bound exception file. Do not disable a rule or directory. |
| Timeout, oversized input or unsupported file | Split/review the change appropriately; the hook intentionally blocks rather than skipping the file. |
| Git index changed during the check | Finish the other staging operation, then check the intended index again. |

Do not routinely bypass hooks. A passing scan is not a complete privacy audit or
proof of runtime security. It cannot determine every household identifier's
sensitivity or compare your private credential stores.

## What is checked?

- Conventional private/runtime paths and paths excluded by **staged**
  `.gitignore` rules are refused, including force-added files.
- Examples/templates still receive the full secret scan. Their suffix does not
  exempt their content.
- Gitleaks scans whole changed text blobs, including unchanged lines. Inline
  allow comments, repository scanner settings and ignore fingerprints cannot
  silently disable it.
- Symlinks, submodules, unresolved merges, archives, binary/non-UTF-8 files and
  oversized inputs require separate review and are refused.
- The budget is **five seconds**, **2,000 changed files**, **2 MiB per file** and
  **16 MiB total**. Scanner errors or timeouts block the commit.
- Git index bytes are compared before/after checking; a concurrent change blocks
  the result.

The scanner uses a private mode-`0700` temporary snapshot. Normal completion or
handled failure removes it; abrupt termination can leave a private directory
requiring later inspection.

Reviewed exceptions in `reviewed-findings.json` bind one **path, full-file
SHA-256, rule and line**, with a reason. Changing the file invalidates its
exception. The guard reads exceptions from the index, so unstaged edits cannot
alter the proposed commit's checks. No blanket directory/rule suppression is
an acceptable way to get a pass.

## What has actually been verified?

Run the regression checks from the repository root:

```sh
python3 -B .githooks/test_staged_guard.py
```

**Expected result:** the test summary ends with `OK`. Tests use disposable Git
repositories and synthetic credential-shaped fixtures. They exercise acceptance,
refusal, partial staging, staged ignore rules, byte-pinned exceptions, scanner
failures and the five-second timeout.

Hooks can be bypassed locally, so server-side CI and branch controls remain
separate safeguards. Before merging, check CI and CodeRabbit against the latest
PR commit using the [contributor requirements](../docs/contributing-safely.md).
