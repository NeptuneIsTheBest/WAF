import importlib.util
import json
from pathlib import Path
import tarfile
import unittest


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


packager = load("package-release")
checker = load("check-publication")


class PublicationTests(unittest.TestCase):
    def test_dependency_metadata_is_allowlisted_recursively(self):
        raw = json.dumps({"Path": "example.org/module", "Version": "v1.0.0", "Sum": "h1:example", "Dir": "/private/cache", "GoMod": "/private/cache/go.mod", "Replace": {"Dir": "/private/source"}})
        modules = packager.dependency_manifest(raw + "\n" + json.dumps({"Path": "waf", "Main": True, "Dir": "/private/source"}))
        self.assertEqual(modules, [{"Path": "example.org/module", "Version": "v1.0.0", "Sum": "h1:example"}, {"Path": "waf"}])

    def test_archive_metadata_is_normalized(self):
        member = tarfile.TarInfo("package/waf")
        member.uid, member.gid, member.mtime = 501, 20, 123456789
        member.uname, member.gname = "local-account", "local-group"
        member.pax_headers = {"comment": "local-machine"}
        result = packager.normalized_member(member)
        self.assertEqual((result.uid, result.gid, result.mtime, result.uname, result.gname, result.pax_headers), (0, 0, 0, "", "", {}))
        self.assertEqual(result.mode, 0o755)
        member.type = tarfile.SYMTYPE
        with self.assertRaises(ValueError):
            packager.normalized_member(member)

    def test_private_content_is_rejected_without_echoing_values(self):
        secret = b"ghp_" + b"a" * 36
        issues = checker.check_content("config.txt", secret)
        self.assertTrue(issues)
        self.assertNotIn(secret.decode(), "\n".join(issues))
        self.assertTrue(checker.check_content("master.key", b"anything"))
        self.assertTrue(checker.check_content("config.json", b"/" + b"Users/fixture/project/"))
        # CRS contains this relative attack-detection path in its embedded data.
        self.assertEqual(checker.check_content("waf", b"usr/home/user/lighttpd"), [])
        self.assertEqual(checker.check_content("waf.example.json", b'{"acme_email":"operator@example.com"}'), [])

    def test_raw_go_list_output_cannot_be_published(self):
        self.assertTrue(checker.check_content("dependencies.json", b'{"Path":"waf","Dir":"/private/source"}'))
        self.assertTrue(checker.check_content("dependencies.json", b'[{"Path":"waf","Dir":"/private/source"}]'))
        self.assertEqual(checker.check_content("dependencies.json", b'[{"Path":"waf"}]'), [])


if __name__ == "__main__":
    unittest.main()
