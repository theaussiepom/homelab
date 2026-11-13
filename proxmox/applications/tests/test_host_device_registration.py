"""Exercise registration assertions and Jinja with local Ansible only."""

import copy
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import yaml

BASE = Path(__file__).resolve().parents[2] / "bootstrap/ansible"
ANSIBLE = str(Path(sys.executable).with_name("ansible-playbook"))
if not Path(ANSIBLE).exists():
    ANSIBLE = shutil.which("ansible-playbook")


def run_play(play, inventory, root, *, connection=None):
    argv = [ANSIBLE, "-i", str(inventory)]
    if connection:
        argv.extend(["-c", connection])
    return subprocess.run(
        [*argv, str(play)],
        capture_output=True,
        text=True,
        env=dict(
            os.environ,
            ANSIBLE_LOCAL_TEMP=str(root / "ansible"),
            ANSIBLE_REMOTE_TEMP=str(root / "remote-tmp"),
        ),
        timeout=60,
    )


@unittest.skipUnless(
    ANSIBLE, "The registered-capability fixture requires pinned Ansible"
)
class RegistrationTests(unittest.TestCase):
    def test_firewall_backup_is_valid_json_and_preserves_its_first_capture(self):
        tasks = yaml.safe_load((BASE / "host-device-firewall.yml").read_text())
        task = copy.deepcopy(
            next(
                t
                for t in tasks
                if t["name"] == "Preserve the original firewall scope privately"
            )
        )
        original = [{"type": "in", "source": "198.18.25.11/32", "action": "ACCEPT"}]
        raw = json.dumps(original, indent=2)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / "before.json"
            task["ansible.builtin.copy"]["dest"] = str(backup)
            for key in ("owner", "group"):
                task["ansible.builtin.copy"].pop(key)
            task["register"] = "saved"
            play = root / "backup.json"
            play.write_text(
                json.dumps(
                    [
                        {
                            "hosts": "localhost",
                            "gather_facts": False,
                            "vars": {
                                "ansible_python_interpreter": sys.executable,
                                "device_firewall_read": {"stdout": raw},
                            },
                            "tasks": [
                                task,
                                {"ansible.builtin.assert": {"that": ["saved.changed"]}},
                                dict(
                                    task,
                                    vars={"device_firewall_read": {"stdout": "[]"}},
                                ),
                                {
                                    "ansible.builtin.assert": {
                                        "that": ["not saved.changed"]
                                    }
                                },
                            ],
                        }
                    ]
                )
            )
            result = run_play(play, "localhost,", root, connection="local")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(backup.read_bytes(), raw.encode() + b"\n")
            self.assertEqual(json.loads(backup.read_bytes()), original)

    def test_registered_host_trust_has_a_real_newline_and_openssh_accepts_it(self):
        plays = yaml.safe_load((BASE / "host-device.yml").read_text())
        trust = plays[2]
        public = (BASE.parents[1] / "iso/config/fixture-ssh.pub").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            known_hosts = root / "known_hosts"
            inventory = root / "inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "all": {
                            "children": {
                                "pve": {
                                    "hosts": {
                                        "pve": {
                                            "ansible_host": "198.18.25.10",
                                            "host_device_server_key": {
                                                "content": base64.b64encode(
                                                    public
                                                ).decode()
                                            },
                                        }
                                    }
                                },
                                "deploy": {
                                    "hosts": {
                                        "deploy": {
                                            "ansible_connection": "local",
                                            "ansible_python_interpreter": sys.executable,
                                        }
                                    }
                                },
                            }
                        }
                    }
                )
            )
            copy_task = copy.deepcopy(
                next(
                    t
                    for t in trust["tasks"]
                    if t["name"] == "Save only the absent pinned host key"
                )
            )
            copy_task["ansible.builtin.copy"].update(dest=str(known_hosts))
            for key in ("owner", "group"):
                copy_task["ansible.builtin.copy"].pop(key)
            copy_task["register"] = "saved_trust"
            guard = copy.deepcopy(
                next(
                    t
                    for t in trust["tasks"]
                    if t["name"] == "Refuse changed host trust"
                )
            )
            play = root / "trust.json"
            play.write_text(
                json.dumps(
                    [
                        {
                            "hosts": "deploy",
                            "gather_facts": False,
                            "vars": trust["vars"],
                            "tasks": [
                                copy_task,
                                {
                                    "ansible.builtin.assert": {
                                        "that": ["saved_trust.changed"]
                                    }
                                },
                                copy_task,
                                {
                                    "ansible.builtin.assert": {
                                        "that": ["not saved_trust.changed"]
                                    }
                                },
                                {
                                    "ansible.builtin.slurp": {"src": str(known_hosts)},
                                    "register": "host_device_prior_trust",
                                },
                                dict(
                                    guard,
                                    vars={
                                        "host_device_known": {
                                            "stat": {
                                                "exists": True,
                                                "isreg": True,
                                                "pw_name": "homelab-runner",
                                                "mode": "0600",
                                            }
                                        }
                                    },
                                ),
                            ],
                        }
                    ]
                )
            )
            result = run_play(play, inventory, root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            expected = b"198.18.25.10 " + b" ".join(public.split()[:2]) + b"\n"
            self.assertEqual(known_hosts.read_bytes(), expected)
            self.assertEqual(known_hosts.stat().st_mode & 0o777, 0o600)
            parsed = subprocess.run(
                ["ssh-keygen", "-lf", str(known_hosts)], capture_output=True, text=True
            )
            self.assertEqual(parsed.returncode, 0, parsed.stderr)

    def test_only_bounded_firewall_rules_and_matching_key_authority_are_accepted(self):
        plays = yaml.safe_load((BASE / "host-device.yml").read_text())
        firewall = yaml.safe_load((BASE / "host-device-firewall.yml").read_text())
        guard = next(
            t
            for t in firewall
            if t["name"] == "Preserve duplicate or changed firewall ownership"
        )
        tasks = []
        expected = {
            "type": "in",
            "action": "ACCEPT",
            "proto": "tcp",
            "dport": "22",
            "source": "198.18.25.11/32",
            "dest": "198.18.25.10/32",
            "enable": 1,
        }
        scenarios = [([], True), ([expected], True), ([expected, expected], False)]
        scenarios += [
            ([dict(expected, **change)], False)
            for change in (
                {"source": "198.18.25.0/24"},
                {"dest": "198.18.25.0/24"},
                {"action": "DROP"},
                {"proto": "udp"},
                {"enable": 0},
                {"iface": "eth0"},
            )
        ]
        for index, (rows, accepted) in enumerate(scenarios):
            variables = {
                "device_firewall_owned": rows,
                "device_firewall": {
                    "direction": "in",
                    "source": expected["source"],
                    "destination": expected["dest"],
                },
            }
            task = copy.deepcopy(guard)
            if accepted:
                tasks.append(dict(task, vars=variables))
            else:
                tasks.append(
                    {
                        "name": "Reject changed rule " + str(index),
                        "vars": variables,
                        "block": [
                            task,
                            {
                                "name": "Unexpected acceptance",
                                "ansible.builtin.fail": {
                                    "msg": "Changed capability firewall ownership was accepted"
                                },
                            },
                        ],
                        "rescue": [
                            {
                                "ansible.builtin.assert": {
                                    "that": [
                                        "ansible_failed_task.name == 'Preserve duplicate or changed firewall ownership'"
                                    ]
                                }
                            }
                        ],
                    }
                )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.json"
            policy.write_text(
                json.dumps({"schema": "homelab-host-device-v1", "vmid": 209})
            )
            inventory = root / "inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "all": {
                            "children": {
                                "pve": {
                                    "hosts": {
                                        "pve": {
                                            "ansible_connection": "local",
                                            "ansible_host": "198.18.25.10",
                                            "ansible_python_interpreter": sys.executable,
                                        }
                                    }
                                },
                                "deploy": {
                                    "hosts": {
                                        "deploy": {
                                            "ansible_connection": "local",
                                            "ansible_host": "198.18.25.11",
                                            "host_device_public_key": "ssh-ed25519 synthetic",
                                        }
                                    }
                                },
                            }
                        }
                    }
                )
            )
            variables = dict(plays[1]["vars"], host_device_policy_file=str(policy))
            # Check the exact forced-command authorization after real Jinja rendering.
            expected_line = 'restrict,from="198.18.25.11",command="/usr/bin/python3 -I /usr/local/libexec/homelab-host-device.py --policy /etc/homelab-host-devices/209.json" ssh-ed25519 synthetic'
            variables["expected_line"] = expected_line
            authority = next(
                t
                for t in plays[1]["tasks"]
                if t["name"] == "Refuse an existing key with different host authority"
            )
            for content, accepted in [
                ("", True),
                (expected_line + "\n", True),
                ("ssh-ed25519 synthetic\n", False),
                (
                    expected_line.replace(
                        "ssh-ed25519 synthetic", "ssh-ed25519 different"
                    )
                    + "\n",
                    False,
                ),
            ]:
                variables_for_case = {
                    "host_device_authorizations": {
                        "content": base64.b64encode(content.encode()).decode()
                    }
                }
                task = copy.deepcopy(authority)
                task.pop("no_log", None)
                if accepted:
                    tasks.append(dict(task, vars=variables_for_case))
                else:
                    tasks.append(
                        {
                            "vars": variables_for_case,
                            "block": [
                                task,
                                {
                                    "name": "Unexpected key acceptance",
                                    "ansible.builtin.fail": {
                                        "msg": "Key authority drift was accepted"
                                    },
                                },
                            ],
                            "rescue": [
                                {
                                    "ansible.builtin.assert": {
                                        "that": [
                                            "ansible_failed_task.name == 'Refuse an existing key with different host authority'"
                                        ]
                                    }
                                }
                            ],
                        }
                    )
            tasks.append(
                {
                    "ansible.builtin.assert": {
                        "that": ["device_key_line == expected_line"]
                    }
                }
            )
            play = root / "assert-only.json"
            play.write_text(
                json.dumps(
                    [
                        {
                            "hosts": "pve",
                            "gather_facts": False,
                            "vars": variables,
                            "tasks": tasks,
                        }
                    ]
                )
            )
            result = run_play(play, inventory, root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("changed=0", result.stdout)
            self.assertFalse(
                any(
                    "ansible.builtin.shell" in task
                    for play in plays
                    for task in play["tasks"]
                )
            )
