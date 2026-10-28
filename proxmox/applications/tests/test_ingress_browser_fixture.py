"""An unmatched 404 cannot establish that the file provider has loaded."""
import unittest
from unittest.mock import patch

import ingress_browser_fixture as fixture


class ReadinessTests(unittest.TestCase):
    def test_existing_route_must_load_before_missing_host_is_checked(self):
        loaded=0;seen=[]
        def request(path,headers=None,host=fixture.HOST,peer='127.0.0.1'):
            nonlocal loaded
            seen.append((path,host))
            if host=='other.example.invalid':
                loaded+=1
                return (200 if loaded>=3 else 404),{},b''
            return 404,{},b''
        with patch.object(fixture,'request',side_effect=request),patch.object(fixture.time,'sleep'):
            fixture.check('before')
        self.assertEqual(seen[:3],[('/existing','other.example.invalid')]*3)
        self.assertEqual(seen[-1],('/',fixture.HOST))

    def test_file_provider_never_loading_is_a_bounded_failure(self):
        with patch.object(fixture,'request',return_value=(404,{},b'')) as request,patch.object(fixture.time,'sleep'):
            with self.assertRaisesRegex(RuntimeError,'exceeded'):fixture.check('before')
        self.assertEqual(request.call_count,40)
