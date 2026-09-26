#!/usr/bin/env python3
"""Reject private build paths, credential files, and unsafe release contents."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parent.parent
PATTERNS = {
    "personal filesystem path": re.compile(rb"(?<![A-Za-z0-9_])/(?:Users|home)/[A-Za-z0-9_.-]+/"),
    "local build cache": re.compile(rb"/(?:private/)?var/folders/[A-Za-z0-9_/.-]+"),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "GitHub credential": re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "credential in URL": re.compile(rb"https?://[^\s/:\"'<>]+:[^\s/@\"'<>]+@"),
}
PRIVATE_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3", ".age", ".log"}
RELEASE_FILES = {
    "waf", "install.sh", "README.md", "dependencies.json", "frontend-dependencies-lock.json",
    "deploy/waf.service", "deploy/waf.example.json", "deploy/prometheus.yml", "deploy/alerts.yml",
    "docs/OPERATIONS.md", "docs/ARCHITECTURE.md", "docs/BENCHMARK.md",
    "docs/screenshots/overview.png", "docs/screenshots/mobile.png",
}


def check_content(name, data):
    issues = []
    for label, pattern in PATTERNS.items():
        if pattern.search(data):
            issues.append(f"{name}: {label}")
    path = PurePosixPath(name)
    if path.suffix in PRIVATE_SUFFIXES or (path.name.startswith(".env") and path.name != ".env.example"):
        issues.append(f"{name}: private runtime file")
    if path.name == "dependencies.json":
        try:
            modules = json.loads(data)
            allowed = {"Path", "Version", "Sum", "GoVersion", "Indirect"}
            if not isinstance(modules, list) or any(not isinstance(item, dict) or not set(item) <= allowed for item in modules):
                issues.append(f"{name}: unexpected dependency metadata")
        except (ValueError, TypeError):
            issues.append(f"{name}: invalid dependency manifest")
    return issues


def check_source():
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    issues = []
    for name in filter(None, names):
        path = ROOT / name
        if path.is_symlink():
            issues.append(f"{name}: unexpected symlink")
        elif path.is_file():
            issues.extend(check_content(name, path.read_bytes()))
        if any(part in {"node_modules", "test-results", "playwright-report", "validation", "bin", "release", ".idea", ".DS_Store"} for part in PurePosixPath(name).parts):
            issues.append(f"{name}: local artifact in source tree")
    return issues


def check_release(directory):
    issues = []
    manifest = directory / "SHA256SUMS"
    expected = {}
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match[2] in expected:
            issues.append("SHA256SUMS: invalid or duplicate entry")
            continue
        expected[match[2]] = match[1]
    actual = {p.name for p in directory.iterdir() if p.name != "SHA256SUMS"}
    if actual != set(expected):
        issues.append("SHA256SUMS: release inventory mismatch")
    if len(actual) != 3 or "install.sh" not in actual:
        issues.append("release must contain installer and exactly two architecture archives")
    versions = set()
    architectures = set()
    for name in sorted(actual):
        path = directory / name
        if not path.is_file() or path.is_symlink():
            issues.append(f"{name}: unexpected release entry")
            continue
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected.get(name):
            issues.append(f"{name}: SHA-256 mismatch")
        if name == "install.sh":
            issues.extend(check_content(name, data))
            continue
        match = re.fullmatch(r"waf_(.+)_linux_(amd64|arm64)\.tar\.gz", name)
        if not match:
            issues.append(f"{name}: unexpected asset")
            continue
        versions.add(match[1]); architectures.add(match[2])
        prefix = name.removesuffix(".tar.gz")
        found = set()
        with tarfile.open(path) as archive:
            for member in archive.getmembers():
                member_path = PurePosixPath(member.name)
                if member_path.is_absolute() or ".." in member_path.parts or member_path.parts[0] != prefix:
                    issues.append(f"{name}: unsafe archive path")
                    continue
                if member.uid or member.gid or member.uname or member.gname or member.pax_headers or member.mtime:
                    issues.append(f"{name}/{member.name}: machine metadata")
                if member.isdir():
                    continue
                if not member.isfile():
                    issues.append(f"{name}: non-regular archive entry")
                    continue
                relative = member_path.relative_to(prefix).as_posix()
                if relative not in RELEASE_FILES or relative in found:
                    issues.append(f"{name}/{relative}: unexpected or duplicate file")
                found.add(relative)
                issues.extend(check_content(relative, archive.extractfile(member).read()))
            if found != RELEASE_FILES:
                issues.append(f"{name}: package inventory mismatch")
    if len(versions) != 1 or architectures != {"amd64", "arm64"}:
        issues.append("release versions or architectures are inconsistent")
    return issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", action="store_true", help="inspect all Git-tracked files")
    parser.add_argument("--release", type=Path, help="inspect release files and archive contents")
    args = parser.parse_args()
    if not args.source and args.release is None:
        parser.error("choose --source and/or --release")
    issues = check_source() if args.source else []
    if args.release is not None:
        issues.extend(check_release(args.release))
    if issues:
        print("Publication checks failed (values redacted):", file=sys.stderr)
        for issue in issues:
            print(f"- {issue}", file=sys.stderr)
        return 1
    print("Publication checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
