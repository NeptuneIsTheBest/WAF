#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
WAF_VERSION="${1:-0.1.0}"
if [[ ! "$WAF_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]; then
  printf '%s\n' 'Version must be a semantic version without a path.' >&2
  exit 1
fi
python3 scripts/package-release.py "$WAF_VERSION"
