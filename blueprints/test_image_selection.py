"""Image component policy keeps declared versions separate from runtime identities."""
import copy
import unittest
import image_selection as images


class ImageSelectionTests(unittest.TestCase):
    def test_registry_tag_digest_and_local_archive_identity_are_exact(self):
        value={'repository':'example/service','tag':'1.2.3','digest':'sha256:'+'1'*64}
        before=copy.deepcopy(value)
        self.assertEqual(images.image(value),{'image':'example/service:1.2.3@sha256:'+'1'*64})
        value['tag']=None
        self.assertEqual(images.image(value),{'image':'example/service@sha256:'+'1'*64})
        local={'local_id':'sha256:'+'a'*64,'archive':'/var/lib/example/custom.tar','archive_sha256':'b'*64}
        self.assertEqual(images.image(local),{'image':local['local_id'],'archive':local['archive'],
                                            'archive_sha256':local['archive_sha256']})
        self.assertEqual(before['tag'],'1.2.3')

    def test_only_two_declared_policy_exceptions_allow_latest(self):
        for repository in ('ghcr.io/bitwarden/lite','ghcr.io/music-assistant/server'):
            self.assertEqual(images.image({'repository':repository,'tag':'latest','digest':None}),
                             {'image':repository+':latest'})
        for repository in ('example/latest','ghcr.io/music-assistant/other'):
            with self.subTest(repository=repository),self.assertRaises(ValueError):
                images.image({'repository':repository,'tag':'latest','digest':None})

    def test_wrong_types_missing_unknown_and_unsafe_registry_fields_refuse(self):
        good={'repository':'example/service','tag':'1','digest':'sha256:'+'1'*64}
        for value in (None,[],True,'image',{},dict(good,extra=True),
            {k:v for k,v in good.items()if k!='tag'},dict(good,repository=1),dict(good,repository='--option'),
            dict(good,repository='user@registry/service'),dict(good,tag=[]),dict(good,tag='bad tag'),
            dict(good,digest=None),dict(good,digest='latest'),dict(good,digest='sha256:'+'A'*64)):
            with self.subTest(value=value),self.assertRaises(ValueError):images.image(value)

    def test_local_archive_requires_the_closed_absolute_hashed_record(self):
        good={'local_id':'sha256:'+'a'*64,'archive':'/var/lib/example/custom.tar','archive_sha256':'b'*64}
        for change in ({'local_id':None},{'archive':None},{'archive_sha256':None},
                       {'local_id':'tag:latest'},{'archive':'relative.tar'},{'archive_sha256':'x'*64}):
            with self.subTest(change=change),self.assertRaises(ValueError):images.image(dict(good,**change))


if __name__=='__main__':unittest.main()
