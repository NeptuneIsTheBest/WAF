"""Exercise install refusal, package verification and readiness without root."""
import hashlib
import io
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="waf-installer-test-")
        self.directory = Path(self.temp.name)
        self.environment = dict(os.environ, WAF_TEST_DIRECTORY=str(self.directory))

    def tearDown(self):
        self.temp.cleanup()

    def run_shell(self, script):
        prefix = f"source {shlex.quote(str(ROOT / 'scripts/install.sh'))}\n"
        # macOS lacks sha256sum; use its bundled SHA-256 implementation locally.
        if sys.platform == "darwin" or not shutil.which("sha256sum"):
            prefix += 'sha256sum() { shasum -a 256 "$@"; }\n'
        result = subprocess.run(["bash", "-c", prefix + script], env=self.environment, capture_output=True, text=True)
        return result

    def assert_failure(self, script, message):
        result = self.run_shell(script)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)
        return result

    def test_platform_matrix(self):
        for distro, version in (("ubuntu", "22.04"), ("ubuntu", "24.04"), ("debian", "12"), ("debian", "13")):
            for arch, expected in (("x86_64", "amd64"), ("aarch64", "arm64")):
                result = self.run_shell(f'select_platform Linux {arch} {distro} {version}; echo "$WAF_ARCH"')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)

    def test_unsupported_platforms(self):
        for args in ("Darwin arm64 ubuntu 24.04", "Linux riscv64 debian 12", "Linux amd64 debian 11", "Linux amd64 ubuntu 20.04", "Linux amd64 alpine 3.20", "Linux amd64 debian unknown"):
            self.assertNotEqual(self.run_shell("select_platform " + args).returncode, 0, args)

    def test_argument_validation(self):
        result = self.run_shell('parse_args --version v0.1.0 --domain admin.example.com --email operator@example.com; echo "$WAF_VERSION $WAF_DOMAIN $WAF_EMAIL"')
        self.assertEqual(result.stdout.strip(), "0.1.0 admin.example.com operator@example.com")
        for args in ("--unknown", "--version", "--version ../../etc/passwd", "--version --domain", "--version v1.0.0/other"):
            self.assertNotEqual(self.run_shell("parse_args " + args).returncode, 0)

    def test_prompt_rejects_invalid_domain_before_initialization(self):
        for domain in ("localhost", "127.0.0.1", "https://admin.example.com", "admin.example.com.", "a..example.com", "-bad.example.com"):
            script = f'exec 3<>/dev/null; WAF_DOMAIN={shlex.quote(domain)}; WAF_EMAIL=operator@example.com; prompt_settings'
            self.assertNotEqual(self.run_shell(script).returncode, 0, domain)
        result = self.run_shell('exec 3<>/dev/null; WAF_DOMAIN=Admin.Example.com; WAF_EMAIL=operator@example.com; prompt_settings; echo "$WAF_DOMAIN"')
        self.assertEqual(result.stdout.strip(), "admin.example.com")

    def test_existing_data_and_dangling_symlinks_are_preserved(self):
        existing = self.directory / "state"
        existing.mkdir()
        (existing / "sentinel").write_text("keep")
        script = 'WAF_INSTALL_PATHS=("$WAF_TEST_DIRECTORY/state"); check_existing'
        self.assert_failure(script, "保留现有安装")
        self.assertEqual((existing / "sentinel").read_text(), "keep")
        link = self.directory / "link"
        link.symlink_to(self.directory / "missing")
        self.assert_failure('WAF_INSTALL_PATHS=("$WAF_TEST_DIRECTORY/link"); check_existing', "保留现有安装")

    def test_existing_account_and_service_are_rejected(self):
        self.assert_failure('WAF_INSTALL_PATHS=("$WAF_TEST_DIRECTORY/absent"); getent() { return 0; }; check_existing', "用户或组已存在")
        self.assert_failure('WAF_INSTALL_PATHS=("$WAF_TEST_DIRECTORY/absent"); getent() { return 2; }; systemctl() { return 0; }; check_existing', "waf.service 已存在")

    def test_busy_ports_are_rejected(self):
        self.assert_failure("ss() { echo 'LISTEN 0 128 0.0.0.0:443'; }; check_ports", "端口被占用")

    def checksum_fixture(self):
        asset = "waf_0.1.0_linux_amd64.tar.gz"
        (self.directory / asset).write_bytes(b"a verified package")
        digest = hashlib.sha256((self.directory / asset).read_bytes()).hexdigest()
        (self.directory / "SHA256SUMS").write_text(f"{digest}  {asset}\n")
        return asset

    def test_checksum_success_tamper_missing_and_duplicate(self):
        asset = self.checksum_fixture()
        script = f'WAF_TEMP="$WAF_TEST_DIRECTORY"; WAF_ASSET={asset}; verify_checksum'
        result = self.run_shell(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.directory / asset).write_bytes(b"tampered")
        self.assert_failure(script, "SHA-256 校验失败")
        self.checksum_fixture()
        manifest = self.directory / "SHA256SUMS"
        manifest.write_text(manifest.read_text() * 2)
        self.assert_failure(script, "唯一有效")
        manifest.write_text("")
        self.assert_failure(script, "唯一有效")

    def make_archive(self, member_name, member_type=tarfile.REGTYPE):
        archive = self.directory / "package.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            member = tarfile.TarInfo(member_name)
            member.type = member_type
            if member_type == tarfile.REGTYPE:
                member.size = 4
                output.addfile(member, io.BytesIO(b"test"))
            else:
                member.linkname = "/etc/passwd"
                output.addfile(member)

    def test_archive_path_and_link_rejection(self):
        script = 'WAF_TEMP="$WAF_TEST_DIRECTORY"; WAF_PACKAGE=waf_0.1.0_linux_amd64; WAF_ASSET=package.tar.gz; validate_archive'
        self.make_archive("waf_0.1.0_linux_amd64/waf")
        self.assertEqual(self.run_shell(script).returncode, 0)
        for name, kind in (("another-package/waf", tarfile.REGTYPE), ("waf_0.1.0_linux_amd64/../../escape", tarfile.REGTYPE), ("waf_0.1.0_linux_amd64/waf", tarfile.SYMTYPE), ("waf_0.1.0_linux_amd64/waf", tarfile.LNKTYPE)):
            self.make_archive(name, kind)
            self.assertNotEqual(self.run_shell(script).returncode, 0, name)

    def test_download_failure_stops_before_installation(self):
        result = self.run_shell('WAF_TEMP="$WAF_TEST_DIRECTORY"; WAF_VERSION=0.1.0; WAF_ARCH=amd64; download() { return 22; }; fetch_release; touch "$WAF_TEST_DIRECTORY/installed"')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.directory / "installed").exists())

    def test_latest_version_is_resolved_once_and_package_is_verified(self):
        upstream = self.directory / "upstream"
        upstream.mkdir()
        (self.directory / "work").mkdir()
        name = "waf_1.2.3_linux_amd64"
        asset = upstream / (name + ".tar.gz")
        files = {"waf": b"#!/bin/sh\nprintf 'waf 1.2.3 (fixture), OWASP CRS fixture\\n'\n", "deploy/waf.service": b"fixture", "docs/OPERATIONS.md": b"fixture"}
        with tarfile.open(asset, "w:gz") as archive:
            for relative, content in files.items():
                member = tarfile.TarInfo(name + "/" + relative)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        (upstream / "SHA256SUMS").write_text(f"{hashlib.sha256(asset.read_bytes()).hexdigest()}  {asset.name}\n")
        script = '''
WAF_TEMP="$WAF_TEST_DIRECTORY/work"
WAF_ARCH=amd64
download() {
  printf '%s\\n' "$1" >> "$WAF_TEST_DIRECTORY/urls"
  if [[ "$1" == */releases/latest ]]; then
    printf '{"tag_name":"v1.2.3"}' > "$2"
  else
    cp "$WAF_TEST_DIRECTORY/upstream/${1##*/}" "$2"
  fi
}
fetch_release
test -x "$WAF_PACKAGE_DIR/waf"
'''
        result = self.run_shell(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        urls = (self.directory / "urls").read_text().splitlines()
        self.assertEqual(len(urls), 3)
        self.assertTrue(urls[0].endswith("/releases/latest"))
        self.assertTrue(all("/releases/download/v1.2.3/" in url for url in urls[1:]))

    def test_no_secret_or_enrollment_output_on_stdout(self):
        # Only the CLI is replaced; initialize_waf must route its output to fd 3.
        script = '''
exec 3>"$WAF_TEST_DIRECTORY/terminal"
WAF_DOMAIN=admin.example.com
WAF_EMAIL=operator@example.com
/usr/local/bin/waf() { printf 'enrollment-fixture'; }
initialize_waf
'''
        result = self.run_shell(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual((self.directory / "terminal").read_text(), "enrollment-fixture")

    def test_service_failure_and_certificate_timeout(self):
        self.assert_failure('systemctl() { return 1; }; WAF_WAIT_SECONDS=1; wait_ready', "服务启动失败")
        self.assert_failure('systemctl() { return 0; }; curl() { return 0; }; check_console() { return 1; }; sleep() { SECONDS=$((SECONDS+2)); }; WAF_WAIT_SECONDS=1; wait_ready', "HTTPS 尚未就绪")
        self.assert_failure('systemctl() { return 0; }; curl() { return 1; }; check_console() { return 0; }; sleep() { SECONDS=$((SECONDS+2)); }; WAF_WAIT_SECONDS=1; wait_ready', "HTTPS 尚未就绪")
        result = self.run_shell('systemctl() { return 0; }; curl() { return 0; }; check_console() { return 0; }; wait_ready')
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
