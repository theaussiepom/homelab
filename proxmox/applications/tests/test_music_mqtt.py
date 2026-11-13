"""Dedicated services preserve credentials/data and refuse unsupported runtime changes."""
import copy
import importlib.util
import io
import json
import os
import runpy
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import music_assistant as music
import mqtt_runtime

HEALTH_PATH = Path(__file__).resolve().parents[1] / 'automation-health.py'
spec = importlib.util.spec_from_file_location('dedicated_mqtt_health', HEALTH_PATH)
health = importlib.util.module_from_spec(spec); spec.loader.exec_module(health)



def settings():
    return {'server_id':'retained-synthetic-id', 'onboard_done':True,
            'core':{'webserver':{'values':{'bind_ip':'198.18.100.241'}},
                    'streams':{'values':{'bind_ip':'198.18.100.241', 'publish_ip':'198.18.100.241'}}},
            'providers':{'original-provider':{'domain':'spotify','values':{'token':'never-output'}}}}


class MusicTests(unittest.TestCase):
    def test_retained_official_2_10_9_providers_remain_readonly_and_closed(self):
        observed=('wikipedia','loudness_analysis','playlist_metadata','itunes_artwork',
                  'radio_playlist','recommendations','sendspin_source',
                  'lastfm_recommendations','ambient_sounds')
        value=settings()
        value['providers'].update({f'retained-{name}':{'domain':name,'enabled':True,
            'values':{'retained_credential':'never-output'}} for name in observed})
        original=copy.deepcopy(value)
        music.validate_settings(value,'198.18.100.241')
        self.assertEqual(value,original)
        for domain in ('unreviewed_custom_provider','filesystem'):
            changed=copy.deepcopy(value)
            changed['providers']['unreviewed']={'domain':domain,'enabled':True}
            with self.subTest(domain=domain),self.assertRaisesRegex(ValueError,'reviewed existing'):
                music.validate_settings(changed,'198.18.100.241')
        changed=copy.deepcopy(value)
        changed['core']['streams']['values']['bind_ip']='198.18.25.31'
        with self.assertRaisesRegex(ValueError,'UI and player listeners'):
            music.validate_settings(changed,'198.18.100.241')

    def test_cli_entry_refuses_unprepared_state_without_printing_values(self):
        with patch('pathlib.Path.is_symlink',return_value=True),patch('sys.argv',['music_assistant.py','--address','198.18.100.241']),patch('sys.stdout',new_callable=io.StringIO) as output:
            with self.assertRaises(SystemExit) as result:runpy.run_path(music.__file__,run_name='__main__')
            self.assertEqual(result.exception.code,1)
            self.assertEqual(output.getvalue(),'Music Assistant startup held; inspect retained state privately\n')


    def test_retained_settings_refuse_fresh_onboarding_wrong_listeners_or_new_capabilities(self):
        original=settings();music.validate_settings(original,'198.18.100.241')
        for transform in [lambda v:None,lambda v:v.update(server_id=None),lambda v:v.update(server_id=''),
                lambda v:v.update(onboard_done=False),
                lambda v:v['core']['webserver']['values'].update(bind_ip='172.20.0.10'),
                lambda v:v['core']['streams']['values'].update(publish_ip='198.18.25.31'),
                lambda v:v.update(providers=[]),lambda v:v.update(providers={}),
                lambda v:v.update(providers={str(i):{'domain':'spotify'}for i in range(129)}),
                lambda v:v.update(providers={'bad':None}),
                lambda v:v.update(providers={'bad':{'domain':'filesystem'}})]:
            value=copy.deepcopy(original);result=transform(value)
            with self.subTest(change=str(transform)),self.assertRaises(ValueError):
                music.validate_settings(None if result is None and value==original else value,'198.18.100.241')
        value=copy.deepcopy(original);value['providers']['disabled']={'domain':'filesystem','enabled':False}
        music.validate_settings(value,'198.18.100.241')

    def test_readonly_data_verification_never_changes_retained_private_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'playlists').mkdir()
            (root/'settings.json').write_text(json.dumps(settings()))
            for name in ('library.db','auth.db'):(root/name).write_bytes(b'SQLite format 3\x00synthetic')
            original={p:p.read_bytes()for p in root.iterdir()if p.is_file()}
            music.check_directory(root,'198.18.100.241')
            for path,raw in original.items():self.assertEqual(path.read_bytes(),raw)
            with patch.object(music,'DATA',root),patch('sys.stdout',new_callable=io.StringIO)as output:
                self.assertEqual(music.main(['--address','198.18.100.241']),0)
                self.assertNotIn('never-output',output.getvalue())
            for name in ('library.db','auth.db'):
                (root/name).write_bytes(b'not SQLite')
                with self.assertRaisesRegex(ValueError,'databases'):music.check_directory(root,'198.18.100.241')
                (root/name).write_bytes(original[root/name])
            (root/'playlists').rmdir()
            with self.assertRaisesRegex(ValueError,'playlists'):music.check_directory(root,'198.18.100.241')
            (root/'playlists').symlink_to(root,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'playlists'):music.check_directory(root,'198.18.100.241')
            with patch.object(music,'DATA',root),patch('sys.stdout',new_callable=io.StringIO)as output:
                self.assertEqual(music.main(['--address','198.18.100.241']),1)
                self.assertNotIn('never-output',output.getvalue())
            with self.assertRaisesRegex(ValueError,'separately prepared'):
                music.check_directory(root/'absent','198.18.100.241')
            link=root/'alias';link.symlink_to(root,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'separately prepared'):music.check_directory(link,'198.18.100.241')

    def test_bounded_state_reader_refuses_links_size_and_races(self):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'state';path.write_bytes(b'private')
            with self.assertRaisesRegex(ValueError,'bounded'):music.read_file(path,1)
            link=path.with_name('hardlink');os.link(path,link)
            with self.assertRaisesRegex(ValueError,'bounded'):music.read_file(path,100)
            link.unlink()
            attributes=dict(st_mode=stat.S_IFREG,st_nlink=1,st_size=7,st_dev=1,st_ino=2,
                            st_uid=0,st_gid=0,st_mtime_ns=3,st_ctime_ns=4,st_atime_ns=5)
            first=SimpleNamespace(**attributes)
            after=SimpleNamespace(**dict(attributes,st_size=8))
            with patch.object(music.os,'fstat',side_effect=[first,after]),self.assertRaisesRegex(ValueError,'changed'):
                music.read_file(path,100)
            with patch.object(music.os,'fstat',return_value=after),self.assertRaisesRegex(ValueError,'changed'):
                music.read_file(path,100)
            not_regular=SimpleNamespace(st_mode=stat.S_IFIFO,st_nlink=1,st_size=7)
            with patch.object(music.os,'fstat',return_value=not_regular),self.assertRaisesRegex(ValueError,'bounded'):
                music.read_file(path,100)

    def test_atime_update_during_read_is_not_a_content_or_identity_change(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'settings';path.write_bytes(b'private')
            fields=dict(st_mode=stat.S_IFREG|0o600,st_nlink=1,st_size=7,st_dev=1,st_ino=2,
                        st_uid=0,st_gid=0,st_mtime_ns=3,st_ctime_ns=4,st_atime_ns=5)
            before=SimpleNamespace(**fields)
            after=SimpleNamespace(**dict(fields,st_atime_ns=6))
            with patch.object(music.os,'fstat',side_effect=[before,after]):
                self.assertEqual(music.read_file(path,100),b'private')
            for field in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'):
                changed=SimpleNamespace(**dict(fields,**{field:fields[field]+1}))
                with self.subTest(field=field),patch.object(music.os,'fstat',side_effect=[before,changed]),self.assertRaisesRegex(ValueError,'changed'):
                    music.read_file(path,100)


class BrokerTests(unittest.TestCase):



    def test_probe_authenticates_one_account_and_rejects_anonymous_without_publishing(self):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'account';path.write_text(json.dumps({'username':'retained','password':'private'}))
            with patch.object(health,'connect',side_effect=[0,5])as connection:
                health.mqtt(path,standalone=True)
                self.assertEqual([c.args for c in connection.call_args_list],[('retained','private'),()])
            for value in (None,{}, {'data':{'entries':[]}}):
                path.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError,'probe account'):health.mqtt(path,standalone=True)
        with patch.object(health,'mqtt')as probe:
            health.probe('mqtt-broker')
            probe.assert_called_once_with(Path(mqtt_runtime.RUNTIME),standalone=True)



if __name__=='__main__':unittest.main()
