"""Actual Ansible checks reject installed-helper/settings drift without writes.

Run only inside the disposable offline source-tools container.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    if os.geteuid() != 0 or not Path('/.dockerenv').is_file():
        raise SystemExit('Use the disposable offline source-tools container')
    source = Path(__file__).resolve().parents[1]
    installed = Path('/opt/homelab-app/ingress-browser')
    installed.mkdir(parents=True, mode=0o700)
    names = ['component_browser.py', 'ingress_browser.py', 'component_image.py']
    settings = {'fixture': 'exact synthetic packet'}
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp); (root/'ansible').mkdir()
        for name in names:
            shutil.copyfile(source/name, root/name)
            shutil.copyfile(source/name, installed/name)
            (installed/name).chmod(0o600)
        selected = installed/'settings.json'; selected.write_text(json.dumps(settings)); selected.chmod(0o600)
        playbook = root/'ansible/check.yml'
        playbook.write_text(json.dumps([{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
            'vars': {'browser_settings': settings}, 'tasks': [{'ansible.builtin.include_tasks':
                str(source/'ansible/component-browser-verify.yml')}]}]))
        environment = os.environ.copy()
        environment.update(ANSIBLE_LOCAL_TEMP=str(root/'local'), ANSIBLE_REMOTE_TEMP=str(root/'remote'))

        def check(passes):
            result = subprocess.run(['ansible-playbook','-i','localhost,',str(playbook)],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
            if (result.returncode == 0) != passes:
                raise AssertionError(result.stdout[-3000:])

        check(True)
        target = installed/names[0]; original = target.read_bytes()
        target.write_bytes(original + b'\n# unexpected installed drift\n')
        check(False)
        assert target.read_bytes() == original + b'\n# unexpected installed drift\n'
        target.write_bytes(original)
        selected.write_text('{"fixture":"different packet"}')
        check(False)
        assert json.loads(selected.read_bytes()) != settings
        selected.write_text(json.dumps(settings))
        target.unlink(); target.symlink_to(root/names[0])
        check(False)
        assert target.is_symlink()
    print('Browser Ansible verification: exact helpers/settings passed; changed source, packet and symlink refused without repair')


if __name__ == '__main__':
    main()
