#!/usr/bin/env bash
# Disposable CI only. Run the real installer and package, with local downloads
# and loopback development initialization instead of contacting a production CA.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "${CI:-}" != true || "$EUID" != 0 || ! -d /run/systemd/system ]]; then
  printf '%s\n' 'Run only as root in a disposable systemd CI machine with CI=true.' >&2
  exit 1
fi
WAF_SMOKE_RELEASE="$(realpath "${1:-release}")"
# shellcheck source=scripts/install.sh
source scripts/install.sh
check_existing
WAF_SMOKE_DIR="$(mktemp -d)"
chmod 0700 "$WAF_SMOKE_DIR"
cleanup() {
  local status=$?
  trap - EXIT
  if ((status)); then journalctl -u waf.service -n 60 --no-pager || true; fi
  systemctl disable --now waf.service 2>/dev/null || true
  rm -f /etc/systemd/system/waf.service /usr/local/bin/waf /run/waf-install.lock
  rm -rf /etc/waf /var/lib/waf /usr/local/share/waf "$WAF_SMOKE_DIR"
  systemctl daemon-reload
  userdel waf 2>/dev/null || true
  groupdel waf 2>/dev/null || true
  exit "$status"
}
trap cleanup EXIT
printf '%s' 'ci-disposable-password' > "$WAF_SMOKE_DIR/password"
chmod 0600 "$WAF_SMOKE_DIR/password"
WAF_SMOKE_VERSION="$(sed -nE 's/^[a-f0-9]+  waf_(.+)_linux_amd64.tar.gz$/\1/p' "$WAF_SMOKE_RELEASE/SHA256SUMS")"
valid_version "$WAF_SMOKE_VERSION"

open_terminal() { exec 3<>"$WAF_SMOKE_DIR/enrollment"; }
prompt_settings() { WAF_DOMAIN=admin.localhost; WAF_EMAIL=operator@example.com; }
download() { cp "$WAF_SMOKE_RELEASE/${1##*/}" "$2"; }
initialize_waf() {
  /usr/local/bin/waf init --development --config /etc/waf/waf.json --data-dir /var/lib/waf \
    --password-file "$WAF_SMOKE_DIR/password" >&3
  python3 - <<'PY'
import json
from pathlib import Path
p = Path('/etc/waf/waf.json')
config = json.loads(p.read_text())
config['http_listen'] = '127.0.0.1:80'
p.write_text(json.dumps(config))
PY
}
check_console() { curl --noproxy '*' --fail --silent -H 'Host: admin.localhost' http://127.0.0.1/ -o /dev/null; }

# Package integrity failure must not create a user, binary or state.
(
  WAF_TEMP="$(mktemp -d)"
  trap installer_cleanup EXIT
  select_platform Linux "$(uname -m)" debian 12
  WAF_VERSION="$WAF_SMOKE_VERSION"
  download() {
    cp "$WAF_SMOKE_RELEASE/${1##*/}" "$2"
    if [[ "$2" == *.tar.gz ]]; then printf 'corruption' >> "$2"; fi
  }
  set +e
  (set -e; fetch_release) > "$WAF_SMOKE_DIR/checksum-output" 2>&1
  WAF_SMOKE_STATUS=$?
  set -e
  [[ "$WAF_SMOKE_STATUS" != 0 ]]
)
check_existing

(main --version "$WAF_SMOKE_VERSION")
systemctl is-enabled --quiet waf.service
systemctl is-active --quiet waf.service
test "$(stat -c '%U:%G:%a' /etc/waf)" = root:waf:750
test "$(stat -c '%U:%G:%a' /etc/waf/waf.json)" = root:waf:640
test "$(stat -c '%U:%G:%a' /etc/waf/master.key)" = root:root:600
test "$(stat -c '%U:%G:%a' /var/lib/waf)" = waf:waf:700
WAF_SMOKE_KEY_SUM="$(sha256sum /etc/waf/master.key)"
WAF_SMOKE_CONFIG_SUM="$(sha256sum /etc/waf/waf.json)"
set +e
(set -e; main --version "$WAF_SMOKE_VERSION") > "$WAF_SMOKE_DIR/reinstall-output" 2>&1
WAF_SMOKE_STATUS=$?
set -e
test "$WAF_SMOKE_STATUS" != 0
test "$(sha256sum /etc/waf/master.key)" = "$WAF_SMOKE_KEY_SUM"
test "$(sha256sum /etc/waf/waf.json)" = "$WAF_SMOKE_CONFIG_SUM"
systemctl restart waf.service
curl --noproxy '*' --fail --retry 20 --retry-connrefused --retry-delay 1 http://127.0.0.1:9090/readyz
check_console
systemctl stop waf.service
test "$(systemctl show waf.service -p Result --value)" = success
printf '%s\n' 'Installer, credentials, permissions, restart and repeat-install checks passed.'
