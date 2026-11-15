"""Restricted attachment refuses fallback/conflicts and preserves the whole guest."""
import copy
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import nfs_host_helper as helper
import nfs_attachments as client


def request(vmid=6100):
    return {'schema':helper.SCHEMA,'node':'pve-lab','vmid':vmid,'hostname':'camera-host',
        'mac':'02:00:00:00:61:00','rootfs':'local-zfs:subvol-'+str(vmid)+'-disk-0,size=16G',
        'mounts':{'mp0':'local-zfs:subvol-'+str(vmid)+'-disk-1,mp=/srv/data,size=16G,backup=1,replicate=1'},
        'mount':{'source':'/mnt/example/recordings','path':'/srv/recordings','slot':1,
                 'filesystem_source':'nas.example.invalid:/export/recordings','filesystem':'nfs4','filesystem_root':'/'}}


class HostFixture:
    def __init__(self,r,started=True):
        self.r=r;self.running=started;self.calls=[];self.fail=None
        self.config={'hostname':r['hostname'],'unprivileged':1,'protection':1,'digest':'a'*40,
            'rootfs':r['rootfs'],'net0':'hwaddr='+r['mac']+',ip=198.18.25.10/24',
            'description':'keep this complete guest',**r['mounts']}
        self.pending=[]
    def __call__(self,args):
        self.calls.append(args)
        if self.fail and self.fail in args:
            raise RuntimeError('synthetic private failure')
        if args[0].endswith('pvesh'):
            return json.dumps(self.pending if args[2].endswith('/pending') else self.config)
        if args[1]=='status':return 'status: running' if self.running else 'status: stopped'
        if args[1]=='shutdown':self.running=False
        if args[1]=='start':self.running=True
        if args[1]=='set':
            flag=args[3][2:];value=args[4]
            self.config[flag]=int(value) if flag=='protection' else value
            self.config['digest']='b'*40
        if args[0].endswith('lxc-info'):return '1234'
        if args[1]=='exec':return json.dumps({'filesystems':[{'source':self.r['mount']['filesystem_source'],
            'fstype':'nfs4','fsroot':'/','target':'/srv/recordings','options':'rw,nosuid'}]})
        return ''


class HostAttachmentTests(unittest.TestCase):
    def run_host(self,r,host,action='attach'):
        with patch.object(helper.socket,'gethostname',return_value='pve-lab'), \
             patch.object(helper,'source',return_value=(123,SimpleNamespace(st_dev=80,st_ino=123))), \
             patch.object(helper.os,'stat',return_value=SimpleNamespace(st_dev=80,st_ino=123)), \
             patch.object(helper.os,'close'):
            return helper.perform(r,action,host)

    def test_any_guest_first_attachment_and_repeat_preserve_every_other_field(self):
        for vmid in (210,6100,900):
            with self.subTest(vmid=vmid):
                r=request(vmid);host=HostFixture(r);before=copy.deepcopy(host.config)
                result=self.run_host(r,host)
                self.assertTrue(result['changed']);self.assertTrue(host.running)
                self.assertEqual({k:v for k,v in host.config.items() if k not in ('digest','mp1')},
                                 {k:v for k,v in before.items() if k!='digest'})
                mutations=len([a for a in host.calls if a[1] in ('shutdown','start','set')])
                self.assertFalse(self.run_host(r,host)['changed'])
                self.assertEqual(len([a for a in host.calls if a[1] in ('shutdown','start','set')]),mutations)
                self.assertEqual(host.config['protection'],1)

    def test_stopped_guest_stays_stopped_and_check_never_mutates(self):
        r=request();host=HostFixture(r,False)
        self.assertFalse(self.run_host(r,host,'check')['changed'])
        self.assertNotIn('mp1',host.config)
        self.assertTrue(self.run_host(r,host)['changed']);self.assertFalse(host.running)
        self.assertFalse(any(a[1] in ('start','shutdown','exec') for a in host.calls))

    def test_conflicts_pending_identity_and_non_nfs_fail_before_mutation(self):
        for change in (
            lambda h:h.config.update(hostname='other'),lambda h:h.config.update(protection=0),
            lambda h:h.config.update(lock='backup'),lambda h:h.config.update(rootfs='other'),
            lambda h:h.config.update(net0='hwaddr=02:00:00:00:00:01'),
            lambda h:h.config.update(mp0='foreign'),lambda h:h.config.update(mp1=None),lambda h:h.config.update(mp1='/mnt/other,mp=/srv/recordings'),
            lambda h:h.config.update(mp2='unrelated'),lambda h:h.pending.append({'key':'rootfs','pending':'other'})):
            r=request();host=HostFixture(r);change(host)
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_host(r,host)
            self.assertFalse(any(a[1] in ('set','start','shutdown') for a in host.calls))
        r=request();r['mount']['path']='/srv/data/overlap'
        with self.assertRaises(ValueError):self.run_host(r,HostFixture(r))
        host=HostFixture(request())
        with patch.object(helper,'source',side_effect=ValueError('local fallback')), \
             self.assertRaises(ValueError):
            helper.perform(request(),'attach',host)

    def test_failed_append_restores_protection_and_does_not_start_or_retry(self):
        r=request();host=HostFixture(r);host.fail='--mp1'
        with self.assertRaises(RuntimeError):self.run_host(r,host)
        self.assertEqual(host.config['protection'],1);self.assertFalse(host.running)
        self.assertEqual(sum('--mp1' in a for a in host.calls),1)
        self.assertNotIn('mp1',host.config)

    def test_invalid_requests_and_commands_have_no_mutation_authority(self):
        mutations=[lambda r:r.update(schema='other'),lambda r:r.update(vmid=True),lambda r:r.update(vmid=99),
            lambda r:r.update(node='x;reboot'),lambda r:r.update(mac='bad'),lambda r:r.update(rootfs=''),
            lambda r:r.update(mounts={}),lambda r:r['mount'].update(extra=True),
            lambda r:r['mount'].update(source='/etc/secret'),lambda r:r['mount'].update(source='/mnt/a/../b'),
            lambda r:r['mount'].update(path='/etc/key'),lambda r:r['mount'].update(slot=True),
            lambda r:r['mount'].update(filesystem='ext4'),lambda r:r['mount'].update(filesystem_source='nas:/x,ro')]
        for mutate in mutations:
            r=request();mutate(r)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):helper.validate(r)
        with self.assertRaises(ValueError):helper.decode('{"same":1,"same":2}')
        with self.assertRaises(ValueError):self.run_host(request(),HostFixture(request()),'shell')
        host=HostFixture(request());host.config['mp1']='/mnt/a,mp=/srv/a,mp=/srv/b'
        with self.assertRaises(ValueError):self.run_host(request(),host)

    def test_source_requires_actual_nfs_and_exact_projection_without_following_symlinks(self):
        selected=request()['mount']
        found={'source':'nas.example.invalid:/export','fstype':'nfs4','fsroot':'/','target':'/mnt/example','options':'rw,nosuid'}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();real=root/'real';real.mkdir();link=root/'link';link.symlink_to(real)
            descriptor=helper.directory(str(real));helper.os.close(descriptor)
            with self.assertRaises(OSError):helper.directory(str(link))
        def execute(args):return json.dumps({'filesystems':[found]})
        with patch.object(helper,'directory',return_value=123),patch.object(helper.os,'close')as close, \
             patch.object(helper,'mount_identity',return_value={k:found[k]for k in ('source','fstype','fsroot','target')}), \
             patch.object(helper.os,'fstatvfs',return_value=SimpleNamespace(f_flag=0)), \
             patch.object(helper.os,'fstat',return_value='identity'):
            self.assertEqual(helper.source(selected,execute),(123,'identity'))
            close.assert_not_called()
            for changed in ({'fstype':'ext4'},{'options':'ro'},{'source':'nas.example.invalid:/foreign'}):
                old=found.copy();found.update(changed)
                with self.subTest(changed=changed),self.assertRaises(ValueError):helper.source(selected,execute)
                found.clear();found.update(old)
            with patch.object(helper.os,'fstatvfs',return_value=SimpleNamespace(f_flag=helper.os.ST_RDONLY)),self.assertRaises(ValueError):
                helper.source(selected,execute)
        for value in ({'filesystems':[]},{'filesystems':[found,found]}):
            with patch.object(helper,'mount_identity',return_value={k:found[k]for k in ('source','fstype','fsroot','target')}),self.assertRaises(ValueError):helper.mount('/mnt/example',lambda args:json.dumps(value),123)

    def test_opened_mount_id_selects_nfs_beneath_the_observed_autofs_overlay(self):
        # Sanitised from the sealed post-CD two-row mount diagnostic/r3 proof.
        rows=[{'source':'systemd-1','fstype':'autofs','fsroot':'/','options':'rw,relatime','target':'/mnt/example'},
              {'source':'nas.example.invalid:/export','fstype':'nfs4','fsroot':'/','options':'rw,nosuid,nodev','target':'/mnt/example'}]
        mountinfo=('160 32 0:76 / /mnt/example rw,relatime - autofs systemd-1 rw\n'
                   '248 160 0:80 / /mnt/example rw,nosuid,nodev - nfs4 nas.example.invalid:/export rw\n')
        def text(path):return 'pos:\t0\nmnt_id:\t248\n' if 'fdinfo'in str(path) else mountinfo
        with patch.object(helper.Path,'read_text',autospec=True,side_effect=text), \
             patch.object(helper.os,'fstat',return_value=SimpleNamespace(st_dev=helper.os.makedev(0,80))):
            found=helper.mount('/mnt/example/recordings',lambda args:json.dumps({'filesystems':rows}),123)
            self.assertEqual(found,rows[1])
            with patch.object(helper.Path,'read_text',side_effect=['mnt_id: 160\n',mountinfo]), \
                 patch.object(helper.os,'fstat',return_value=SimpleNamespace(st_dev=helper.os.makedev(0,76))),self.assertRaises(ValueError):
                helper.mount('/mnt/example',lambda args:json.dumps({'filesystems':rows}),123)
            for info,table in [('mnt_id: 999\n',mountinfo),('missing',mountinfo),('mnt_id: 248\n',mountinfo+mountinfo)]:
                with patch.object(helper.Path,'read_text',side_effect=[info,table]),self.assertRaises(ValueError):helper.mount_identity(123)
            with patch.object(helper.os,'fstat',return_value=SimpleNamespace(st_dev=helper.os.makedev(0,99))),self.assertRaises(ValueError):
                helper.mount_identity(123)

    def test_command_is_bounded_and_shell_free(self):
        with patch.object(helper.subprocess,'check_output',return_value='value')as execute:
            self.assertEqual(helper.command(['/usr/bin/pct','status','6100']),'value')
            self.assertEqual(execute.call_args.kwargs['timeout'],60)
            self.assertNotIn('shell',execute.call_args.kwargs)


class NfsClientTests(unittest.TestCase):
    def test_client_binds_request_helper_and_separate_key_before_accepting_attachment(self):
        import nfs_mounts
        r=request();host=HostFixture(r)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);key=root/'nfs-key';key.write_bytes(b'dedicated');key.chmod(0o600)
            known=root/'hosts';known.write_bytes(b'pinned');known.chmod(0o600)
            cfg={'site':{'node':r['node'],'api_endpoint':'https://198.18.25.1:8006/'},
                'guest':{'vmid':r['vmid'],'hostname':r['hostname'],'recording_mount':r['mount']},
                'app':{'mac':r['mac']},'paths':{'host_nfs_key':str(key),'host_nfs_known_hosts':str(known)}}
            rows=[{'path':'/srv/data','volume':'local-zfs:subvol-6100-disk-1','path_in_datastore':'local-zfs:subvol-6100-disk-1',
                'size':'16G','backup':True,'replicate':True},nfs_mounts.expected(r['mount'])]
            def quiet(argv,env,log,**kwargs):
                selected=helper.decode(kwargs['input_bytes'])
                self.assertEqual(selected,r);self.assertEqual(argv[-1],'attach');self.assertEqual(argv[argv.index('-i')+1],str(key))
                answer={'schema':helper.SCHEMA,'vmid':r['vmid'],'request_sha256':helper.hashlib.sha256(helper.encoded(r)).hexdigest(),
                    'helper_sha256':helper.implementation_digest(),'changed':True}
                log.write_bytes(helper.encoded(answer));log.chmod(0o600)
            with patch.object(client,'quiet',side_effect=quiet):
                self.assertTrue(client.attach(cfg,rows,root,lambda path:host.config))
                with self.assertRaises(ValueError):client.attach(cfg,rows,root,lambda path:host.config)
            (root/'nfs-attachment.json').unlink()
            with patch.object(client,'quiet',side_effect=lambda argv,env,log,**kw:quiet(argv,env,log,**kw)):
                with patch.object(helper,'implementation_digest',side_effect=['a'*64,'b'*64]),self.assertRaises(ValueError):
                    client.attach(cfg,rows,root,lambda path:host.config)



class ForcedCommandTests(unittest.TestCase):
    def test_closed_stdin_lock_and_safe_stdout_for_success_and_refusal(self):
        import sys
        r=request();raw=helper.encoded(r)
        for action,body in (('attach',raw),('version',b''),('attach',b'x'*65537),('attach',b'invalid')):
            with self.subTest(action=action,body_length=len(body)), \
                 patch.object(sys,'argv',['helper']),patch.object(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(body))), \
                 patch.object(sys,'stdout',new_callable=io.StringIO)as out,patch.object(helper.os,'getuid',return_value=0), \
                 patch.dict(helper.os.environ,{'SSH_ORIGINAL_COMMAND':action}), \
                 patch.object(helper.os,'open',return_value=123),patch.object(helper.os,'close'), \
                 patch.object(helper.os,'fstat',return_value=SimpleNamespace(st_mode=0o100600,st_uid=0,st_nlink=1)), \
                 patch.object(helper.fcntl,'flock'),patch.object(helper,'perform',return_value={'status':'passed'}):
                expected=body in (raw,b'')
                self.assertEqual(helper.main(),0 if expected else 1)
                self.assertNotIn('invalid',out.getvalue())
        with patch.object(sys,'argv',['helper']),patch.object(helper.os,'getuid',return_value=1000),patch.object(sys,'stdout',new_callable=io.StringIO):
            self.assertEqual(helper.main(),1)
        with self.assertRaises(RuntimeError):helper.interrupted(helper.signal.SIGHUP,None)
        import runpy
        with patch.object(helper.signal,'signal'),patch.object(sys,'argv',['helper']),patch.dict(helper.os.environ,{'SSH_ORIGINAL_COMMAND':'version'}), \
             patch.object(helper.os,'getuid',return_value=0),patch.object(sys,'stdout',new_callable=io.StringIO),self.assertRaises(SystemExit)as end:
            runpy.run_path(helper.__file__,run_name='__main__')
        self.assertEqual(end.exception.code,0)


if __name__=='__main__':unittest.main()
