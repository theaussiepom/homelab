"""Pure refusal/admission tests; no Docker endpoint is contacted."""
import os
import json
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import pgadmin_restart_fixture as fixture

HOSTED={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux'}


class RestartAdmissionTests(unittest.TestCase):
    def test_no_opt_in_never_invokes_docker_even_for_cleanup(self):
        with patch.object(fixture.subprocess,'run') as command,patch.object(fixture.subprocess,'Popen') as archive:
            with self.assertRaises(ValueError):fixture.run()
            command.assert_not_called();archive.assert_not_called()

    def test_opt_in_does_not_admit_local_self_hosted_or_non_linux_runner(self):
        for env,platform in [({},'linux'),(dict(HOSTED,RUNNER_ENVIRONMENT='self-hosted'),'linux'),
                             (dict(HOSTED,RUNNER_OS='macOS'),'darwin'),(HOSTED,'darwin')]:
            with self.subTest(env=env,platform=platform),self.assertRaises(ValueError):
                fixture.validate_opt_in(True,env,platform)

    def test_remote_or_ambiguous_environment_is_refused_before_context_or_daemon_access(self):
        for extra in [{'DOCKER_HOST':'ssh://production'},{'DOCKER_HOST':'tcp://127.0.0.1:2375'},
                      {'DOCKER_CONTEXT':'production'},{'DOCKER_CONTEXT':'default','DOCKER_HOST':'ssh://production'},
                      {'DOCKER_CONFIG':'/shared/config'},{'DOCKER_TLS_VERIFY':'1'}]:
            with self.subTest(extra=extra),patch.dict(os.environ,dict(HOSTED,**extra),clear=True),\
                    patch.object(fixture.sys,'platform','linux'),patch.object(fixture.subprocess,'run') as command:
                with self.assertRaises(ValueError):fixture.run(allow_disposable=True)
                command.assert_not_called()

    def test_cached_context_and_effective_endpoint_must_both_be_local_default(self):
        for context,endpoint in [('production',fixture.LOCAL),('default','ssh://production'),
                                 ('default','unix:///shared/docker.sock'),('default','tcp://localhost:2375')]:
            with self.subTest(context=context,endpoint=endpoint),self.assertRaises(ValueError):
                fixture.validate_endpoint(context,endpoint)
        fixture.validate_endpoint('default',fixture.LOCAL)

    def test_cached_remote_context_only_permits_local_context_metadata_read(self):
        result=subprocess.CompletedProcess([],0,stdout='production\n')
        with patch.dict(os.environ,HOSTED,clear=True),patch.object(fixture.sys,'platform','linux'),\
                patch.object(fixture.subprocess,'run',return_value=result) as command:
            with self.assertRaises(ValueError):fixture.run(allow_disposable=True)
            self.assertEqual(command.call_count,1)
            self.assertEqual(command.call_args.args[0],['docker','context','show'])

    def test_local_socket_is_not_enough_when_daemon_identifies_another_host(self):
        good={'Name':'ephemeral-runner','OSType':'linux','DockerRootDir':'/var/lib/docker'}
        for info,mode,uid in [(dict(good,Name='production'),stat.S_IFSOCK,0),
                              (dict(good,OSType='windows'),stat.S_IFSOCK,0),
                              (good,stat.S_IFREG,0),(good,stat.S_IFSOCK,1000)]:
            with self.subTest(info=info,mode=mode,uid=uid),self.assertRaises(ValueError):
                fixture.validate_daemon(info,'ephemeral-runner',mode,uid)
        fixture.validate_opt_in(True,HOSTED,'linux')
        fixture.validate_daemon(good,'ephemeral-runner',stat.S_IFSOCK,0)

    def test_admitted_cycle_receives_fixed_endpoint_private_config_and_clean_environment(self):
        info={'Name':'ephemeral-runner','OSType':'linux','DockerRootDir':'/var/lib/docker'}
        replies=[subprocess.CompletedProcess([],0,stdout=s) for s in
                 ('default\n',json.dumps(fixture.LOCAL),json.dumps(info))]
        original_lstat=os.lstat
        def socket_lstat(path,*args,**kwargs):
            if str(path)=='/var/run/docker.sock':
                return SimpleNamespace(st_mode=stat.S_IFSOCK,st_uid=0)
            return original_lstat(path,*args,**kwargs)
        def check_cycle(prefix,environment):
            self.assertEqual(prefix[:4],['docker','--host',fixture.LOCAL,'--config'])
            self.assertTrue(Path(prefix[4]).is_dir())
            self.assertEqual(stat.S_IMODE(Path(prefix[4]).stat().st_mode),0o700)
            self.assertFalse(any(k.startswith('DOCKER_') for k in environment))
        with patch.dict(os.environ,dict(HOSTED,DOCKER_HOST=fixture.LOCAL,DOCKER_CONTEXT='default',DOCKER_API_VERSION='1.44'),clear=True),\
                patch.object(fixture.sys,'platform','linux'),patch.object(fixture.socket,'gethostname',return_value='ephemeral-runner'),\
                patch.object(fixture.os,'lstat',side_effect=socket_lstat),\
                patch.object(fixture.subprocess,'run',side_effect=replies) as command,\
                patch.object(fixture,'_run_cycle',side_effect=check_cycle) as cycle:
            fixture.run(allow_disposable=True)
            cycle.assert_called_once()
            self.assertEqual(command.call_count,3)
            self.assertEqual(command.call_args.args[0][:3],['docker','--host',fixture.LOCAL])


if __name__=='__main__':unittest.main()
