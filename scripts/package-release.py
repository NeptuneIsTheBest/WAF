#!/usr/bin/env python3
"""Build release archives from an explicit allowlist, without machine metadata."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
PUBLIC_FILES = (
    "README.md",
    "deploy/waf.service",
    "deploy/waf.example.json",
    "deploy/prometheus.yml",
    "deploy/alerts.yml",
    "docs/OPERATIONS.md",
    "docs/ARCHITECTURE.md",
    "docs/BENCHMARK.md",
    "docs/screenshots/overview.png",
    "docs/screenshots/mobile.png",
)


def dependency_manifest(raw):
    decoder = json.JSONDecoder()
    dependencies = []
    while raw.strip():
        item, end = decoder.raw_decode(raw.lstrip())
        raw = raw.lstrip()[end:]
        dependencies.append({key: item[key] for key in ("Path", "Version", "Sum", "GoVersion", "Indirect") if key in item})
    return sorted(dependencies, key=lambda item: item["Path"])


def normalized_member(member):
    if not (member.isfile() or member.isdir()):
        raise ValueError("release archives must contain only regular files and directories")
    member.uid = member.gid = member.mtime = 0
    member.uname = member.gname = ""
    member.pax_headers = {}
    member.mode = 0o755 if member.isdir() or Path(member.name).name in ("waf", "install.sh") else 0o644
    return member


def build(version):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?", version):
        raise ValueError("invalid release version")
    os.chdir(ROOT)
    revision = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], capture_output=True, text=True)
    commit = revision.stdout.strip() if revision.returncode == 0 else "unknown"
    if not re.fullmatch(r"[0-9a-f]{7,40}|unknown", commit):
        raise ValueError("invalid commit")
    modules = subprocess.check_output(["go", "list", "-m", "-json", "all"], text=True)
    dependencies = json.dumps(dependency_manifest(modules), indent=2) + "\n"
    with tempfile.TemporaryDirectory(prefix="waf-release-") as temporary:
        stage = Path(temporary)
        artifacts = stage / "artifacts"
        artifacts.mkdir()
        shutil.copyfile(ROOT / "scripts/install.sh", artifacts / "install.sh")
        (artifacts / "install.sh").chmod(0o755)
        for arch in ("amd64", "arm64"):
            name = f"waf_{version}_linux_{arch}"
            package = stage / name
            package.mkdir()
            env = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH=arch)
            subprocess.run([
                "go", "build", "-trimpath", "-buildvcs=false", "-ldflags",
                f"-s -w -X main.version={version} -X main.commit={commit}",
                "-o", str(package / "waf"), "./cmd/waf",
            ], env=env, check=True)
            for relative in PUBLIC_FILES:
                source = ROOT / relative
                if source.is_symlink():
                    raise ValueError(f"unexpected symlink: {relative}")
                destination = package / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            shutil.copyfile(ROOT / "scripts/install.sh", package / "install.sh")
            shutil.copyfile(ROOT / "web/package-lock.json", package / "frontend-dependencies-lock.json")
            (package / "dependencies.json").write_text(dependencies)
            target = artifacts / f"{name}.tar.gz"
            with target.open("wb") as output:
                with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                        archive.add(package, arcname=name, filter=normalized_member)
        files = sorted(artifacts.iterdir())
        (artifacts / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files
        ))
        subprocess.run([sys.executable, "scripts/check-publication.py", "--release", str(artifacts)], check=True)
        output = ROOT / "release"
        if output.exists():
            shutil.rmtree(output)
        shutil.copytree(artifacts, output)
    print(f"Release v{version}: release/")


if __name__ == "__main__":
    build(sys.argv[1])
