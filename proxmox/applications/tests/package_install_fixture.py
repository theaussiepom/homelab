"""Real Ansible APT task against a stale, local synthetic index; Docker only.

No network, deployment input, vendor package, service or host device is used.
APT_CONFIG isolates sources/cache; only a disposable synthetic package enters
this container's dpkg database. The production task supplies every install guard.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

import yaml

SOURCE = Path(__file__).resolve().parents[1]
PACKAGE = 'homelab-cache-fixture'


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True, **kwargs)


def package(repo, version, events):
    tree = repo / ('build-' + version)
    control = tree / 'DEBIAN'
    control.mkdir(parents=True)
    (control / 'control').write_text(
        f'Package: {PACKAGE}\nVersion: {version}\nArchitecture: all\n'
        'Maintainer: Synthetic Fixture <fixture@example.invalid>\n'
        'Description: Offline exact-package cache regression\n')
    hook = control / 'postinst'
    hook.write_text('#!/bin/sh\nset -eu\n'
        'decision=0\nif test -x /usr/sbin/policy-rc.d; then\n'
        '  decision=0; /usr/sbin/policy-rc.d synthetic-fixture start || decision=$?\nfi\n'
        f'test "$decision" -eq 101 || {{ echo START_ATTEMPT >> {events}; exit 1; }}\n'
        f'echo installed-{version}-without-start >> {events}\n')
    hook.chmod(0o755)
    path = repo / (PACKAGE + '_' + version + '_all.deb')
    run(['dpkg-deb', '--build', str(tree), str(path)])
    return path


def publish(repo, path, version, stamp):
    raw = path.read_bytes()
    index = repo / 'Packages'
    index.write_text(f'Package: {PACKAGE}\nVersion: {version}\nArchitecture: all\n'
        f'Maintainer: Synthetic Fixture <fixture@example.invalid>\n'
        f'Filename: ./{path.name}\nSize: {len(raw)}\n'
        f'SHA256: {hashlib.sha256(raw).hexdigest()}\n'
        'Description: Offline exact-package cache regression\n\n')
    os.utime(index, (stamp, stamp))


def main():
    """Prove stale-cache refresh, exact installs and no-start guards offline."""
    if not Path('/.dockerenv').exists() or os.geteuid() != 0:
        raise SystemExit('Run only in the disposable offline application Docker fixture')
    # Use the real OS bindings, as the target's apt module does.
    run(['/usr/bin/python3', '-c', 'import apt'])
    tasks = [copy.deepcopy(task) for task in yaml.safe_load((SOURCE / 'ansible/tasks/packages-install.yml').read_text())
             if 'ansible.builtin.apt' in task]
    assert len(tasks) == 2, 'Exercise both production index refresh and exact-install tasks'
    policy = Path('/usr/sbin/policy-rc.d')
    original_policy = (policy.read_bytes(), policy.stat().st_mode & 0o777) if policy.exists() else None
    with tempfile.TemporaryDirectory(prefix='ordinary-apt-') as temporary:
        root = Path(temporary); root.chmod(0o755)
        repo = root / 'repo'; repo.mkdir(mode=0o755)
        for directory in ('lists/partial', 'archives/partial', 'sourceparts'):
            (root / directory).mkdir(parents=True)
        events = root / 'package-events'
        apt = root / 'apt.conf'
        sources = root / 'sources.list'
        sources.write_text(f'deb [trusted=yes] file:{repo} ./\n')
        apt.write_text(f'Dir::Etc::sourcelist "{sources}";\n'
            f'Dir::Etc::sourceparts "{root / "sourceparts"}";\n'
            f'Dir::State::lists "{root / "lists"}";\n'
            f'Dir::Cache::archives "{root / "archives"}";\n'
            f'Dir::Cache::pkgcache "{root / "pkgcache.bin"}";\n'
            f'Dir::Cache::srcpkgcache "{root / "srcpkgcache.bin"}";\n'
            'Acquire::Languages "none";\n')
        env = dict(os.environ, APT_CONFIG=str(apt), DEBIAN_FRONTEND='noninteractive')
        old = package(repo, '1.0', events); selected = package(repo, '2.0', events)
        publish(repo, old, '1.0', time.time() - 120)
        run(['apt-get', 'update'], env=env)
        # The source now publishes 2.0, but the guest cache still knows only 1.0.
        publish(repo, selected, '2.0', time.time())
        policy_before = run(['apt-cache', 'policy', PACKAGE], env=env).stdout
        assert '1.0' in policy_before and '2.0' not in policy_before, policy_before
        stale = subprocess.run(['apt-get', '--simulate', 'install', PACKAGE + '=2.0'],
                               env=env, capture_output=True, text=True)
        assert stale.returncode != 0, 'The precondition must really have an unavailable cached pin'
        playbook = root / 'playbook.json'
        variables = root / 'vars.json'
        playbook.write_text(json.dumps([{'hosts':'all', 'connection':'local', 'gather_facts':False,
            'environment':{'APT_CONFIG':str(apt), 'DEBIAN_FRONTEND':'noninteractive'},
            'tasks':tasks}]))
        def install(version):
            variables.write_text(json.dumps({'app':{'packages':[PACKAGE + '=' + version]}}))
            return subprocess.run(['ansible-playbook', '-i', 'localhost,', str(playbook),
                '-e', '@' + str(variables), '-e', 'ansible_python_interpreter=/usr/bin/python3'],
                env=env, capture_output=True, text=True, timeout=120)
        try:
            # Remove Docker's existing deny-start policy so success proves the
            # production task's policy_rc_d guard, not the image's default.
            policy.unlink(missing_ok=True)
            result = install('2.0')
            assert result.returncode == 0, result.stdout + result.stderr
            version = run(['dpkg-query', '-W', '-f=${Version}', PACKAGE]).stdout
            assert version == '2.0', version
            assert events.read_text().splitlines() == ['installed-2.0-without-start']
            assert not policy.exists(), 'Ansible must restore the absent original policy'
            repeated = install('2.0')
            assert repeated.returncode == 0, repeated.stdout + repeated.stderr
            assert events.read_text().splitlines() == ['installed-2.0-without-start'], 'No reinstall/start on repeat'
            missing = install('9.0')
            assert missing.returncode != 0, 'A missing exact pin must not fall back to the candidate'
            assert run(['dpkg-query', '-W', '-f=${Version}', PACKAGE]).stdout == '2.0'
            assert events.read_text().splitlines() == ['installed-2.0-without-start']
            print('Ordinary APT: stale index refused selected pin; real production task refreshed and installed exact2.0; vendor start blocked; repeat retained; missing pin refused')
        finally:
            subprocess.run(['dpkg', '--purge', PACKAGE], capture_output=True, text=True)
            if original_policy:
                policy.write_bytes(original_policy[0]); policy.chmod(original_policy[1])
            else:
                policy.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
