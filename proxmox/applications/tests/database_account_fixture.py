"""Real Ansible account guards in disposable Docker; never a live guest."""

import grp
import json
import os
from pathlib import Path
import pwd
import subprocess
import tempfile


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(
    Path("/.dockerenv").exists() and os.geteuid() == 0,
    "Run only as root inside a disposable Docker container",
)
TASKS = Path(__file__).resolve().parents[1] / "ansible/tasks/database-account.yml"

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    playbook = root / "account.yml"
    playbook.write_text(
        json.dumps(
            [
                {
                    "hosts": "all",
                    "connection": "local",
                    "gather_facts": False,
                    "tasks": [{"ansible.builtin.import_tasks": str(TASKS)}],
                }
            ]
        )
    )
    variables = root / "variables.json"
    command = [
        "ansible-playbook",
        "-i",
        "localhost,",
        str(playbook),
        "--extra-vars",
        "@" + str(variables),
    ]

    def run(user, group, uid, gid):
        variables.write_text(
            json.dumps(
                {
                    "app": {
                        "database": {
                            "user": user,
                            "group": group,
                            "uid": uid,
                            "gid": gid,
                            "home": "/nonexistent",
                        }
                    }
                }
            )
        )
        return subprocess.run(command, capture_output=True, text=True)

    def accounts():
        return {p: Path(p).read_bytes() for p in ("/etc/passwd", "/etc/group")}

    subprocess.run(["groupadd", "--gid", "31000", "fixture_existing"], check=True)
    before = accounts()
    failed = run("fixture_new", "fixture_existing", 31001, 31001)
    require(failed.returncode != 0, "An existing group must not be renumbered")
    require(
        accounts() == before,
        "The refused configuration changed numeric account identities",
    )

    failed = run("fixture_new", "fixture_new", 31001, 31000)
    require(failed.returncode != 0, "A group ID owned by another group must be refused")
    require(accounts() == before, "Synthetic database fixture check failed")

    subprocess.run(
        [
            "useradd",
            "--uid",
            "31002",
            "--gid",
            "fixture_existing",
            "--no-create-home",
            "fixture_other",
        ],
        check=True,
    )
    before = accounts()
    failed = run("fixture_new", "fixture_new", 31002, 31001)
    require(
        failed.returncode != 0, "A user ID owned by another account must be refused"
    )
    require(
        accounts() == before, "UID collision must be caught before creating its group"
    )

    passed = run("fixture_new", "fixture_new", 31001, 31001)
    require(passed.returncode == 0, passed.stdout + passed.stderr)
    before = accounts()
    repeated = run("fixture_new", "fixture_new", 31001, 31001)
    require(repeated.returncode == 0, repeated.stdout + repeated.stderr)
    require(
        "changed=0" in repeated.stdout and accounts() == before,
        "Synthetic database fixture check failed",
    )
    require(
        grp.getgrnam("fixture_existing").gr_gid == 31000,
        "Synthetic database fixture check failed",
    )
    print(
        "Database account guards passed: no existing group renumber, foreign UID/GID holds, exact creation and no-change repeat"
    )

    package_tasks = TASKS.with_name("database-package-account.yml")
    playbook.write_text(
        json.dumps(
            [
                {
                    "hosts": "all",
                    "connection": "local",
                    "gather_facts": False,
                    "tasks": [{"ansible.builtin.import_tasks": str(package_tasks)}],
                }
            ]
        )
    )
    package_app = {
        "kind": "mariadb",
        "database": {"account_mode": "package", "user": "mysql", "group": "mysql"},
    }
    receipt = Path("/etc/homelab-database-account.json")
    require(
        not receipt.exists(),
        "The fresh account fixture already has a package-account receipt",
    )

    def run_package(after=False, app=None):
        variables.write_text(
            json.dumps(
                {"app": app or package_app, "database_account_after_packages": after}
            )
        )
        return subprocess.run(command, capture_output=True, text=True, timeout=60)

    before = accounts()
    initial = run_package()
    require(initial.returncode == 0, initial.stdout + initial.stderr)
    require(
        accounts() == before and not receipt.exists(),
        "Pre-package check must not create an account or receipt",
    )

    # Simulate vendor account creation only; this fixture does not install
    # packages, restore databases or qualify native service behavior.
    subprocess.run(["groupadd", "--gid", "31011", "mysql"], check=True)
    subprocess.run(
        ["useradd", "--uid", "31010", "--gid", "mysql", "--no-create-home", "mysql"],
        check=True,
    )
    before = accounts()
    installed = run_package(after=True)
    require(installed.returncode == 0, installed.stdout + installed.stderr)
    expected = {
        "account_mode": "package",
        "kind": "mariadb",
        "user": "mysql",
        "group": "mysql",
        "uid": 31010,
        "gid": 31011,
    }
    require(
        json.loads(receipt.read_text()) == expected,
        "Actual package IDs were not recorded",
    )
    require(
        receipt.stat().st_uid == 0 and receipt.stat().st_mode & 0o777 == 0o600,
        "Package identity receipt must remain root-only",
    )
    require(
        accounts() == before, "Reading package-created IDs must not mutate accounts"
    )
    for after in [False, True]:
        repeated = run_package(after=after)
        require(repeated.returncode == 0, repeated.stdout + repeated.stderr)
        require(
            "changed=0" in repeated.stdout and accounts() == before,
            "Package-account repeat must make no changes",
        )

    for field, value in [("uid", 999), ("gid", 999)]:
        invalid = dict(
            package_app, database=dict(package_app["database"], **{field: value})
        )
        failed = run_package(app=invalid)
        require(
            failed.returncode != 0 and accounts() == before,
            "Package mode must not silently ignore fixed IDs",
        )
    for invalid in [
        dict(package_app, kind="postgresql"),
        dict(package_app, new_target=False),
        dict(package_app, new_target=True),
        dict(package_app, capture={"path": "must-not-read"}),
        dict(package_app, database=dict(package_app["database"], user="fixture_other")),
    ]:
        failed = run_package(app=invalid)
        require(
            failed.returncode != 0 and accounts() == before,
            "Invalid package-account scope must be refused",
        )

    saved_receipt = receipt.read_bytes()
    receipt.unlink()
    failed = run_package()
    require(
        failed.returncode != 0 and accounts() == before and not receipt.exists(),
        "An unrecorded existing account must not be adopted before package changes",
    )
    receipt.write_bytes(saved_receipt)
    receipt.chmod(0o600)
    subprocess.run(["usermod", "--uid", "31012", "mysql"], check=True)
    before = accounts()
    for after in [False, True]:
        failed = run_package(after=after)
        require(
            failed.returncode != 0
            and accounts() == before
            and receipt.read_bytes() == saved_receipt,
            "Drift must be refused before and after packages without renumbering or replacing the receipt",
        )
    require(
        pwd.getpwnam("mysql").pw_uid == 31012,
        "Refusing drift must not repair the account",
    )
    subprocess.run(["usermod", "--uid", "31010", "mysql"], check=True)
    subprocess.run(["groupmod", "--gid", "31013", "mysql"], check=True)
    subprocess.run(["usermod", "--gid", "31013", "mysql"], check=True)
    before = accounts()
    for after in [False, True]:
        failed = run_package(after=after)
        require(
            failed.returncode != 0
            and accounts() == before
            and receipt.read_bytes() == saved_receipt,
            "Coherent group-ID drift must be refused without renumbering or replacing the receipt",
        )
    require(
        grp.getgrnam("mysql").gr_gid == 31013,
        "Refusing drift must not repair the group",
    )
    print(
        "Package-created MariaDB account passed: actual IDs recorded, no-change repeat, scope and fixed-ID rejection, unrecorded-account/drift holds"
    )
