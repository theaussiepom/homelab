import json
import os
from pathlib import Path
import tempfile
import unittest
import yaml
from render_private_yaml import dotenv, render, read_regular, write_new


class PrivateRenderTest(unittest.TestCase):
    def test_yaml_metacharacters_are_data(self):
        value = "'\nother: malicious\n$(touch /tmp/not-executed) ${UNCHANGED}"
        result = render("url: !env HOMELAB_URL\n", {"HOMELAB_URL": value})
        self.assertEqual(yaml.safe_load(result), {"url": value})

    def test_missing_or_empty_fails(self):
        for env in ({}, {"HOMELAB_URL": ""}):
            with self.assertRaises(ValueError):
                render("url: !env HOMELAB_URL\n", env)

    def test_unknown_yaml_tag_is_not_executed(self):
        with self.assertRaises(ValueError):
            render("!!python/object/apply:os.system ['echo unsafe']", {})

    def test_dotenv_literals_no_expansion(self):
        value = "${TOKEN} $(command) 'quoted'"
        self.assertEqual(dotenv("HOMELAB_VALUE="+json.dumps(value)), {"HOMELAB_VALUE": value})

    def test_dotenv_single_quote(self):
        self.assertEqual(dotenv("HOMELAB_VALUE='literal value'"), {"HOMELAB_VALUE": "literal value"})

    def test_dotenv_duplicate_refused(self):
        with self.assertRaises(ValueError):
            dotenv("HOMELAB_X=a\nHOMELAB_X=b")

    def test_dotenv_nonstring_refused(self):
        with self.assertRaises(ValueError):
            dotenv('OTHER_VALUE="value"')

    def test_output_is_private_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp, "out.yaml")
            write_new(p, "value")
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_new(p, "replacement")
            self.assertEqual(p.read_text(), "value")

    def test_output_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp, "out.yaml")
            p.symlink_to(Path(tmp, "target"))
            with self.assertRaises(OSError):
                write_new(p, "value")
            self.assertFalse(Path(tmp, "target").exists())

    def test_input_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp, "source"); f.write_text("value")
            p = Path(tmp, "link"); p.symlink_to(f)
            with self.assertRaises(OSError):
                read_regular(p)

    def test_read_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp, "values.env"); p.write_text("HOMELAB_X=x")
            p.chmod(0o644)
            with self.assertRaises(ValueError):
                read_regular(p, private=True)

    def test_types_preserved(self):
        result = render("enabled: true\nport: 443\nurl: !env HOMELAB_URL\n",
                        {"HOMELAB_URL": "https://example.invalid"})
        self.assertEqual(yaml.safe_load(result), {
            "enabled": True, "port": 443, "url": "https://example.invalid"})


if __name__ == "__main__":
    unittest.main()
