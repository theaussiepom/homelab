"""Exercise actual agent admission tasks as root in a disposable container only."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import yaml


def main():
    assert Path('/.dockerenv').is_file() and os.geteuid()==0
    source=Path(__file__).resolve().parents[1]/'ansible/tasks/monitoring-agent.yml'
    tasks=yaml.safe_load(source.read_text())
    names=[t['name'] for t in tasks]
    assert names.index('Record an interrupted first installation before package changes') < names.index('Download the exact Agent 2 package into private guest storage')
    assert names.index('Record successful agent ownership without storing a key in the receipt') < names.index('Complete the owned first agent installation') == len(names)-1
    assert next(t for t in tasks if t['name']=='Install the retained individual PSK once')['no_log'] is True
    selected=copy.deepcopy(tasks[:names.index('Download the exact Agent 2 package into private guest storage')])
    # Read/validate real ownership only; no package, group, key, directory or
    # service mutation is allowed in this fixture's extracted playbook.
    selected=[t for t in selected if not any(k in t for k in ('ansible.builtin.file','ansible.builtin.copy'))]
    assert all(set(t)&{'ansible.builtin.stat','ansible.builtin.assert','ansible.builtin.slurp'} for t in selected)
    owner={'hostname':'fixture-216','psk_identity':'fixture-216','version':'fixture-version'}
    for case in ('first','retained','interrupted','foreign','wrong-owner','public-receipt','linked-receipt','linked-config'):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);cfg=root/'agent.conf';receipt=root/'agent.json';hold=root/'AGENT-HOLD'
            if case!='first':cfg.write_text('synthetic owned configuration')
            if case in {'retained','wrong-owner','public-receipt','linked-receipt','linked-config'}:
                receipt.write_text(json.dumps(owner if case!='wrong-owner' else dict(owner,hostname='foreign')));receipt.chmod(0o600)
            if case=='interrupted':hold.write_text('preserve this interrupted attempt')
            if case=='public-receipt':receipt.chmod(0o644)
            if case=='linked-receipt':os.link(receipt,root/'extra-name')
            if case=='linked-config':cfg.unlink();cfg.symlink_to(receipt)
            raw=json.dumps(selected).replace('/etc/zabbix/zabbix_agent2.conf',str(cfg)).replace('/var/lib/homelab-monitoring/agent.json',str(receipt)).replace('/var/lib/homelab-monitoring/AGENT-HOLD',str(hold))
            play=root/'play.json';play.write_text(json.dumps([{'hosts':'all','connection':'local','gather_facts':False,
                'vars':{'app':{'monitoring':{'hostname':owner['hostname'],'psk_identity':owner['psk_identity']}},'monitoring_agent_package':{'version':owner['version']}},'tasks':json.loads(raw)}]))
            before={p.name:p.read_bytes() for p in (cfg,receipt,hold) if p.exists()}
            run=subprocess.run([str(Path(sys.executable).with_name('ansible-playbook')),'-i','localhost,',str(play)],capture_output=True,text=True,timeout=45)
            assert (run.returncode==0)==(case in {'first','retained'}),case+': '+run.stdout[-1200:]
            assert before=={p.name:p.read_bytes() for p in (cfg,receipt,hold) if p.exists()}
    print('Agent admission: fresh/retained pass; interrupted, foreign, wrong owner, unsafe mode and links refuse before mutations.')


if __name__=='__main__':main()
