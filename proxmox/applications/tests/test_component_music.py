"""App-specific Music contracts; shared service machinery is mocked in units."""
import copy
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
FRAMEWORK=Path(Path(__file__).resolve().parents[3]).resolve()
sys.path.insert(0,str(FRAMEWORK/'proxmox/applications'))

import music_assistant as music
import component_runtime as core
ADDRESS='198.19.100.241'

def descriptor(path='/srv/homelab/data/music-assistant/data'):
 return {'adapter':'music_assistant','lifecycle':'retained','project_name':'homelab-music','identity':{'services':{'music_assistant':'music_assistant'},'networks':{}},'properties':{},'role_addresses':{'web_interface':ADDRESS},
         'storage_paths':{'data':{'target':'/data','kind':'directory','read_only':False,'source':path}},
         'containers':{'music_assistant':{'memory_mib':1536,'cpu_limit':2,'pids_limit':512}},
         'software_selection':{'images':{'music_assistant':{'image':'ghcr.io/music-assistant/server:latest'}}},
         'listeners':{str(port)+'_listener':{'service':'music_assistant','namespace':'host','interface':'web_interface','bind':'interface','protocol':'tcp','port':port,'actual_bind':ADDRESS} for port in (8095,8097)}}

def settings():
 return {'server_id':'synthetic-retained-server','onboard_done':True,'core':{'webserver':{'values':{'bind_ip':ADDRESS}},'streams':{'values':{'bind_ip':ADDRESS,'publish_ip':ADDRESS}}},'providers':{'preserved':{'domain':'spotify','values':{'private':'synthetic-provider-value-never-output'}}}}

def make_data(root):
 (root/'playlists').mkdir();(root/'settings.json').write_text(json.dumps(settings()))
 for name in ('library.db','auth.db'):(root/name).write_bytes(b'SQLite format 3\0synthetic-private-state')
 return {p.name:p.read_bytes() for p in root.iterdir() if p.is_file()}

class ComponentMusicTests(unittest.TestCase):
 def test_app_wires_shared_builder_and_owned_helper_without_duplicating_shared_checks(self):
  app=descriptor('/srv/example/music-data');guest={'timezone':'Etc/UTC'};service={'image':'shared-builder-result'}
  with patch.object(core,'_service',return_value=service) as builder,patch.object(music,'configure_service') as owned:
   result=core._music_assistant(app,guest)
  builder.assert_called_once_with(app,'music_assistant',guest)
  owned.assert_called_once_with(service,ADDRESS,data_root=Path('/srv/example/music-data'))
  self.assertIs(result['music_assistant'],service);self.assertEqual(service['network_mode'],'host')

 def test_component_refuses_unowned_state_listener_or_process_changes_before_shared_builder(self):
  changes=[lambda a:a.update(lifecycle='fresh'),lambda a:a.update(properties={'initialize':True}),
   lambda a:a['role_addresses'].pop('web_interface'),lambda a:a['role_addresses'].update(web_interface='127.0.0.1'),
   lambda a:a.update(storage_paths={}),lambda a:a['storage_paths'].update(extra=a['storage_paths']['data']),
   lambda a:a['storage_paths']['data'].update(target='/foreign'),lambda a:a['storage_paths']['data'].update(kind='file'),
   lambda a:a['storage_paths']['data'].update(read_only=True),lambda a:a['storage_paths']['data'].update(source='relative'),
   lambda a:a['listeners'].pop('8097_listener'),lambda a:a['listeners']['8097_listener'].update(port=8095),
   lambda a:a['listeners']['8097_listener'].update(actual_bind='198.19.100.242'),lambda a:a['listeners']['8097_listener'].update(interface='foreign'),
   lambda a:a['listeners']['8097_listener'].update(protocol='udp'),lambda a:a['listeners']['8097_listener'].update(namespace='app-network'),
   lambda a:a['listeners']['8097_listener'].update(publish={'scope':'guest-loopback','port':8097})]
  changes += [lambda a,k=k:a['containers']['music_assistant'].update({k:False}) for k in ('user','cap_add','read_only','cap_drop','no_new_privileges','tmpfs')]
  for change in changes:
   app=descriptor();change(app)
   with self.subTest(change=repr(change)),patch.object(core,'_service') as builder,patch.object(music,'configure_service') as owned,self.assertRaises((ValueError,KeyError,TypeError)):
    core._music_assistant(app,{})
   builder.assert_not_called();owned.assert_not_called()

 def test_one_real_composition_case_preserves_immutable_music_service_fields(self):
  # Focused integration: real shared builder + candidate owned helper, not mocked.
  baseline=json.loads((HERE/'music-service-baseline.json').read_text())
  address=baseline['healthcheck']['test'][-1]
  import re
  selected=re.search(r'http://([0-9.]+):8095',address).group(1)
  app=descriptor();app['role_addresses']['web_interface']=selected
  for row in app['listeners'].values():row['actual_bind']=selected
  documents=core.compositions({'schema':core.SCHEMA,'guest':{'timezone':baseline['environment']['TZ'],'memory_mib':2048,'os_reserve_mib':256},'applications':{'music':app}})
  self.assertEqual(set(documents),{'homelab-music'})
  value=documents['homelab-music']['services']['music_assistant']
  self.assertEqual(value,baseline)
  self.assertEqual(value['pull_policy'],'always')
  self.assertEqual(value['volumes'][0]['bind'],{'create_host_path':False})

class BoundMusicStateTests(unittest.TestCase):
 def test_bound_readonly_state_and_default_cli_both_keep_all_private_bytes(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();before=make_data(root)
   music.check_bound_directory(str(root),ADDRESS)
   for args in (['--address',ADDRESS],['--address',ADDRESS,'--data-root',str(root)]):
    with patch.object(music,'DATA',root),redirect_stdout(io.StringIO()) as output:self.assertEqual(music.main(args),0)
    self.assertNotIn('synthetic-provider-value',output.getvalue())
   self.assertEqual({p.name:p.read_bytes() for p in root.iterdir() if p.is_file()},before)

 def test_selected_root_is_lexically_bounded_without_controller_filesystem_reads(self):
  bad=['','relative','/','//srv/music','/srv/../music','/srv/./music','/srv//music','/srv/music/','/srv/music\n','/srv/\0music','/'+('x'*4097),'/etc/music','/proc/music','/var/lib/homelab/music']
  for value in bad:
   with self.subTest(path=repr(value)),self.assertRaises((ValueError,TypeError)):music.data_path(value)
  with patch.object(Path,'is_dir',side_effect=AssertionError('renderer must not probe guest storage')):
   self.assertEqual(music.data_path('/srv/example/music'),Path('/srv/example/music'))
  result=music.configure_service({},ADDRESS,data_root='/srv/example/music-$literal')
  self.assertEqual(result['volumes'][0]['source'],'/srv/example/music-$$literal')
  self.assertIn(ADDRESS,result['healthcheck']['test'][-1]);self.assertIn('8097',result['healthcheck']['test'][-1])

 def test_symlink_paths_fixed_filename_escape_and_linked_private_files_refuse(self):
  with tempfile.TemporaryDirectory() as directory:
   parent=Path(directory).resolve();root=parent/'data';root.mkdir();make_data(root)
   alias=parent/'alias';alias.symlink_to(root,target_is_directory=True)
   for value in (str(alias),str(alias/'child')):
    with self.subTest(value=value),self.assertRaises((OSError,ValueError)):music.check_bound_directory(value,ADDRESS)
   fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
   try:
    for value in ('../settings.json','/settings.json','.','',Path('settings.json')):
     with self.subTest(name=str(value)),self.assertRaises(ValueError):music.read_file(value,100,directory_fd=fd)
   finally:os.close(fd)
   original=(root/'settings.json').read_bytes();(root/'settings.json').unlink();(root/'settings.json').symlink_to(parent/'private-token')
   with self.assertRaises((OSError,ValueError)):music.check_bound_directory(str(root),ADDRESS)
   (root/'settings.json').unlink();(root/'settings.json').write_bytes(original)
   os.link(root/'settings.json',root/'second-link')
   with self.assertRaises(ValueError):music.check_bound_directory(str(root),ADDRESS)
   (root/'second-link').unlink()
   for name in ('library.db','auth.db'):
    original=(root/name).read_bytes();os.link(root/name,root/'database-link')
    with self.subTest(database=name),self.assertRaises(ValueError):music.check_bound_directory(str(root),ADDRESS)
    (root/'database-link').unlink();(root/name).unlink();os.mkfifo(root/name)
    with self.subTest(fifo=name),self.assertRaises((OSError,ValueError)):music.check_bound_directory(str(root),ADDRESS)
    (root/name).unlink();(root/name).write_bytes(original)
   (root/'playlists').rmdir();(root/'playlists').symlink_to(parent,target_is_directory=True)
   with self.assertRaises((OSError,ValueError)):music.check_bound_directory(str(root),ADDRESS)

 def test_corrupted_or_foreign_state_never_prints_values_or_rewrites_files(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();original=make_data(root)
   changes=[('settings.json',b'not-json-synthetic-provider-value'),('library.db',b'wrong-header'),('auth.db',b'wrong-header')]
   for name,raw in changes:
    (root/name).write_bytes(raw)
    with redirect_stdout(io.StringIO()) as output:self.assertEqual(music.main(['--address',ADDRESS,'--data-root',str(root)]),1)
    self.assertEqual(output.getvalue(),'Music Assistant startup held; inspect retained state privately\n')
    self.assertEqual((root/name).read_bytes(),raw);(root/name).write_bytes(original[name])
   value=settings();value['core']['streams']['values']['publish_ip']='198.19.100.242';(root/'settings.json').write_text(json.dumps(value))
   with redirect_stdout(io.StringIO()) as output:self.assertEqual(music.main(['--address',ADDRESS,'--data-root',str(root)]),1)
   self.assertNotIn('synthetic-provider-value',output.getvalue())

 def test_root_identity_is_checked_before_private_reads_and_after_completion(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();make_data(root)
   actual_stat=music.os.fstat;root_inode=root.stat().st_ino
   for fail_at in (1,2,3):
    owned={'seen':0}
    def observed(fd):
     info=actual_stat(fd)
     if stat.S_ISDIR(info.st_mode) and info.st_ino==root_inode:
      owned['seen']+=1
      if owned['seen']==fail_at:return SimpleNamespace(st_dev=info.st_dev,st_ino=info.st_ino+1,st_mode=(stat.S_IFREG|0o600) if fail_at==1 else info.st_mode,st_uid=info.st_uid,st_gid=info.st_gid)
     return info
    with self.subTest(phase=fail_at),patch.object(music.os,'fstat',side_effect=observed),self.assertRaisesRegex(ValueError,'directory changed'):
     music.check_bound_directory(str(root),ADDRESS)

 def test_real_ancestor_swap_never_reads_outside_private_state(self):
  for swap_part in ('holder','music'):
   with self.subTest(swap=swap_part),tempfile.TemporaryDirectory() as directory:
    base=Path(directory).resolve();approved=base/'approved';holder=approved/'holder';selected=holder/'music';selected.mkdir(parents=True);make_data(selected)
    outside=base/'outside';foreign=outside/'music';foreign.mkdir(parents=True);make_data(foreign)
    value=settings();value['server_id']='outside-private-marker';(foreign/'settings.json').write_text(json.dumps(value))
    outside_inode=foreign.stat().st_ino;actual_open,actual_read,actual_fstat,actual_symlink=music.os.open,music.read_file,music.os.fstat,Path.is_symlink
    facts={'swapped':False,'outside_read':False,'settings_reads':0}
    def swap():
     holder.rename(approved/'holder-preserved');holder.symlink_to(outside,target_is_directory=True);facts['swapped']=True
    def opened(path,*args,**kwargs):
     if path==swap_part and 'dir_fd'in kwargs and not facts['swapped']:
      swap()
     return actual_open(path,*args,**kwargs)
    def checked(path):
     answer=actual_symlink(path)
     # The old candidate is vulnerable after this exact check. The new one
     # never relies on it and is attacked at its actual openat boundary.
     if path==selected and not facts['swapped']:swap()
     return answer
    def read(path,limit,**kwargs):
     if path=='settings.json':
      facts['settings_reads']+=1;facts['outside_read']|=actual_fstat(kwargs['directory_fd']).st_ino==outside_inode
     raw=actual_read(path,limit,**kwargs)
     if path=='settings.json':facts['outside_read']|=json.loads(raw)['server_id']=='outside-private-marker'
     return raw
    with patch.object(music.os,'open',side_effect=opened),patch.object(music,'read_file',side_effect=read),patch.object(Path,'is_symlink',checked),self.assertRaises((OSError,ValueError)):
     music.check_bound_directory(str(selected),ADDRESS)
    self.assertTrue(facts['swapped']);self.assertFalse(facts['outside_read'])
    self.assertEqual(facts['settings_reads'],0 if swap_part=='holder' else 1)

if __name__=='__main__':unittest.main()
