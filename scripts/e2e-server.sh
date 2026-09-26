#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
WAF_TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waf-e2e.XXXXXX")"
WAF_TEST_PID=""
WAF_ORIGIN_PID=""
cleanup() {
  if [ -n "$WAF_TEST_PID" ]; then kill "$WAF_TEST_PID" 2>/dev/null || true; wait "$WAF_TEST_PID" 2>/dev/null || true; fi
  if [ -n "$WAF_ORIGIN_PID" ]; then kill "$WAF_ORIGIN_PID" 2>/dev/null || true; wait "$WAF_ORIGIN_PID" 2>/dev/null || true; fi
  rm -rf "$WAF_TEST_DIR"
}
trap cleanup EXIT INT TERM
printf '%s' 'browser-test-password' > "$WAF_TEST_DIR/password"
chmod 600 "$WAF_TEST_DIR/password"
./bin/waf init --development --config "$WAF_TEST_DIR/waf.json" --data-dir "$WAF_TEST_DIR/data" --password-file "$WAF_TEST_DIR/password" > "$WAF_TEST_DIR/enrollment"
python3 - "$WAF_TEST_DIR/waf.json" <<'PY'
import json, sys
p = sys.argv[1]
with open(p) as f: config = json.load(f)
config['http_listen'] = '127.0.0.1:18080'
config['ops_listen'] = '127.0.0.1:19090'
with open(p, 'w') as f: json.dump(config, f)
PY
./bin/waforigin --listen 127.0.0.1:18081 &
WAF_ORIGIN_PID=$!
./bin/waf serve --config "$WAF_TEST_DIR/waf.json" &
WAF_TEST_PID=$!
wait "$WAF_TEST_PID"
