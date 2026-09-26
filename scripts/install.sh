#!/usr/bin/env bash
# Download a verified release and initialize a single systemd-managed WAF node.
set -euo pipefail
set +x
export LC_ALL=C

WAF_REPOSITORY=NeptuneIsTheBest/WAF
WAF_VERSION=""
WAF_DOMAIN=""
WAF_EMAIL=""
WAF_ARCH=""
WAF_TEMP=""
WAF_WAIT_SECONDS=300
WAF_INSTALL_PATHS=(/usr/local/bin/waf /etc/waf /var/lib/waf /usr/local/share/waf /etc/systemd/system/waf.service)

die() { printf 'WAF: %s\n' "$*" >&2; exit 1; }
info() { printf 'WAF: %s\n' "$*"; }

usage() {
  cat <<'EOF'
用法：sudo bash install.sh [--version v0.1.0] [--domain admin.example.com] [--email operator@example.com]

支持 Ubuntu 22.04+ / Debian 12+，amd64 / arm64，systemd 247+。
默认安装最新正式版本；域名和邮箱可在安装时输入。
管理员密码、Cloudflare Token 通过隐藏的终端提示输入。
需要可交互终端；已存在安装、配置、数据或 waf 账号时退出。
EOF
}

valid_version() { [[ "$1" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]; }

parse_args() {
  while (($#)); do
    case "$1" in
      --version|--domain|--email)
        [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || die "$1 缺少参数"
        case "$1" in
          --version) valid_version "$2" || die '版本格式应为 v0.1.0'; WAF_VERSION="${2#v}" ;;
          --domain) WAF_DOMAIN="$2" ;;
          --email) WAF_EMAIL="$2" ;;
        esac
        shift 2 ;;
      --help|-h) usage; exit 0 ;;
      *) die "未知参数：$1" ;;
    esac
  done
}

select_platform() {
  local kernel="$1" machine="$2" distro="$3" version="$4" major
  [[ "$kernel" == Linux ]] || die '仅支持 Linux'
  case "$machine" in
    x86_64|amd64) WAF_ARCH=amd64 ;;
    aarch64|arm64) WAF_ARCH=arm64 ;;
    *) die "不支持的架构：$machine" ;;
  esac
  [[ "$version" =~ ^[0-9]+(\.[0-9]+)*$ ]] || die '无法识别系统版本'
  major="${version%%.*}"
  case "$distro" in
    ubuntu) ((major >= 22)) || die '需要 Ubuntu 22.04 或更新版本' ;;
    debian) ((major >= 12)) || die '需要 Debian 12 或更新版本' ;;
    *) die "不支持的系统：$distro（支持 Ubuntu / Debian）" ;;
  esac
}

check_environment() {
  [[ "$EUID" == 0 ]] || die '请使用 sudo bash install.sh 或以 root 执行'
  [[ -r /etc/os-release ]] || die '缺少 /etc/os-release'
  # shellcheck disable=SC1091
  . /etc/os-release
  select_platform "$(uname -s)" "$(uname -m)" "${ID:-}" "${VERSION_ID:-}"
  command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] || die '需要正在运行的 systemd'
  local systemd_version
  systemd_version="$(systemctl --version | awk 'NR == 1 {print $2}')"
  [[ "$systemd_version" =~ ^[0-9]+$ ]] || die '无法读取 systemd 版本'
  ((systemd_version >= 247)) || die '需要 systemd 247 或更新版本'
}

check_existing() {
  local target
  for target in "${WAF_INSTALL_PATHS[@]}"; do
    [[ ! -e "$target" && ! -L "$target" ]] || die "已存在 $target，保留现有安装；升级请参阅运维文档"
  done
  if getent passwd waf >/dev/null || getent group waf >/dev/null; then
    die 'waf 用户或组已存在，保留现有账号，请先检查已有安装'
  fi
  if systemctl cat waf.service >/dev/null 2>&1; then
    die 'waf.service 已存在，保留现有服务'
  fi
}

install_dependencies() {
  local entry tool package
  local -a missing=()
  for entry in curl:curl jq:jq tar:tar gzip:gzip sha256sum:coreutils ss:iproute2 flock:util-linux useradd:passwd; do
    tool="${entry%%:*}"; package="${entry#*:}"
    if ! command -v "$tool" >/dev/null; then missing+=("$package"); fi
  done
  if [[ ! -s /etc/ssl/certs/ca-certificates.crt ]]; then missing+=(ca-certificates); fi
  if ((${#missing[@]})); then
    info '安装必要的系统工具'
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
  fi
}

check_ports() {
  local occupied
  occupied="$(ss -H -ltn '( sport = :80 or sport = :443 or sport = :9090 )')"
  [[ -z "$occupied" ]] || die '80、443 或 9090 端口被占用，请先调整现有服务'
}

open_terminal() {
  if ! { exec 3<>/dev/tty; } 2>/dev/null; then die '需要交互终端，请下载脚本后在 SSH 终端中运行'; fi
}

prompt_settings() {
  if [[ -z "$WAF_DOMAIN" ]]; then
    printf '管理后台域名（例如 admin.example.com）：' >&3
    IFS= read -r WAF_DOMAIN <&3 || die '输入已取消'
  fi
  WAF_DOMAIN="$(printf '%s' "$WAF_DOMAIN" | tr '[:upper:]' '[:lower:]')"
  [[ ${#WAF_DOMAIN} -le 253 && "$WAF_DOMAIN" == *.* && "$WAF_DOMAIN" != *..* && ! "$WAF_DOMAIN" =~ ^[0-9.]+$ ]] || die '请输入有效的管理域名'
  local label
  local -a labels
  IFS=. read -r -a labels <<< "$WAF_DOMAIN"
  [[ "$WAF_DOMAIN" != *. ]] || die '管理域名末尾不能有点'
  for label in "${labels[@]}"; do
    [[ ${#label} -le 63 && "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || die '管理域名格式无效（国际域名请使用 Punycode）'
  done
  if [[ -z "$WAF_EMAIL" ]]; then
    printf 'ACME 证书通知邮箱：' >&3
    IFS= read -r WAF_EMAIL <&3 || die '输入已取消'
  fi
  [[ "$WAF_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || die '邮箱格式无效'
  printf '\n请准备管理员密码（至少 12 字节）及 Cloudflare Token（Zone:DNS:Edit 和 Zone:Read）。\n初始化将接受 ACME CA 的订户条款。请保存稍后显示的 TOTP 密钥和恢复码。\n\n' >&3
}

download() {
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 300 --retry 3 --output "$2" "$1"
}

verify_checksum() {
  local checksum
  checksum="$(awk -v asset="$WAF_ASSET" 'NF == 2 && $2 == asset {if (length($1) != 64 || $1 ~ /[^a-fA-F0-9]/) exit 1; print; count++} END {if (count != 1) exit 1}' "$WAF_TEMP/SHA256SUMS")" || die '校验清单中缺少唯一有效的安装包记录'
  if ! (cd "$WAF_TEMP" && printf '%s\n' "$checksum" | sha256sum --check --status); then die 'SHA-256 校验失败，未安装任何 WAF 文件'; fi
}

validate_archive() {
  local entry
  tar -tzf "$WAF_TEMP/$WAF_ASSET" > "$WAF_TEMP/members"
  while IFS= read -r entry; do
    case "$entry" in
      "$WAF_PACKAGE"|"$WAF_PACKAGE/"*) ;;
      *) die '安装包包含非预期路径' ;;
    esac
    case "/$entry/" in */../*|*/./*) die '安装包包含不安全路径' ;; esac
  done < "$WAF_TEMP/members"
  LC_ALL=C tar -tvzf "$WAF_TEMP/$WAF_ASSET" > "$WAF_TEMP/member-types"
  while IFS= read -r entry; do
    case "${entry:0:1}" in -|d) ;; *) die '安装包包含链接或特殊文件' ;; esac
  done < "$WAF_TEMP/member-types"
}

fetch_release() {
  if [[ -z "$WAF_VERSION" ]]; then
    download "https://api.github.com/repos/$WAF_REPOSITORY/releases/latest" "$WAF_TEMP/release.json"
    local tag
    tag="$(jq -er '.tag_name | select(type == "string")' "$WAF_TEMP/release.json")" || die '无法读取最新版本'
    valid_version "$tag" || die '发布版本格式无效'
    WAF_VERSION="${tag#v}"
  fi
  WAF_PACKAGE="waf_${WAF_VERSION}_linux_${WAF_ARCH}"
  WAF_ASSET="$WAF_PACKAGE.tar.gz"
  local base="https://github.com/$WAF_REPOSITORY/releases/download/v$WAF_VERSION"
  info "下载 v$WAF_VERSION（$WAF_ARCH）"
  download "$base/SHA256SUMS" "$WAF_TEMP/SHA256SUMS"
  download "$base/$WAF_ASSET" "$WAF_TEMP/$WAF_ASSET"
  verify_checksum
  validate_archive
  mkdir "$WAF_TEMP/unpacked"
  tar -xzf "$WAF_TEMP/$WAF_ASSET" -C "$WAF_TEMP/unpacked" --no-same-owner --no-same-permissions
  WAF_PACKAGE_DIR="$WAF_TEMP/unpacked/$WAF_PACKAGE"
  [[ -f "$WAF_PACKAGE_DIR/waf" && -f "$WAF_PACKAGE_DIR/deploy/waf.service" && -f "$WAF_PACKAGE_DIR/docs/OPERATIONS.md" ]] || die '安装包缺少必要文件'
  chmod 0755 "$WAF_PACKAGE_DIR/waf"
  local binary_version
  binary_version="$("$WAF_PACKAGE_DIR/waf" version)"
  [[ "$binary_version" == "waf $WAF_VERSION ("* ]] || die '二进制版本与发布版本不匹配'
}

initialize_waf() {
  /usr/local/bin/waf init --config /etc/waf/waf.json --data-dir /var/lib/waf \
    --domain "$WAF_DOMAIN" --email "$WAF_EMAIL" <&3 >&3
}

install_waf() {
  useradd --system --user-group --no-create-home --home-dir /var/lib/waf --shell /usr/sbin/nologin waf
  install -m 0755 "$WAF_PACKAGE_DIR/waf" /usr/local/bin/waf
  install -d -m 0750 -o root -g waf /etc/waf
  install -d -m 0700 -o waf -g waf /var/lib/waf
  install -d -m 0755 /usr/local/share/waf
  cp -R "$WAF_PACKAGE_DIR/docs" /usr/local/share/waf/
  chmod -R a+rX /usr/local/share/waf/docs
  initialize_waf
  /usr/local/bin/waf check --config /etc/waf/waf.json
  chown root:waf /etc/waf/waf.json
  chmod 0640 /etc/waf/waf.json
  chown root:root /etc/waf/master.key
  chmod 0600 /etc/waf/master.key
  chown -R waf:waf /var/lib/waf
  install -m 0644 "$WAF_PACKAGE_DIR/deploy/waf.service" /etc/systemd/system/waf.service
  systemd-analyze verify /etc/systemd/system/waf.service
  systemctl daemon-reload
  systemctl enable --now waf.service
}

check_console() {
  curl --noproxy '*' --fail --silent --connect-timeout 2 --max-time 5 \
    --resolve "$WAF_DOMAIN:443:127.0.0.1" "https://$WAF_DOMAIN/" --output /dev/null
}

wait_ready() {
  local deadline=$((SECONDS + WAF_WAIT_SECONDS))
  info '等待服务及 HTTPS 证书就绪（最长 5 分钟）'
  while ((SECONDS < deadline)); do
    systemctl is-active --quiet waf.service || die '服务启动失败；运行 sudo journalctl -u waf -n 80 排查'
    if curl --noproxy '*' --fail --silent --connect-timeout 2 --max-time 3 http://127.0.0.1:9090/readyz >/dev/null && check_console; then
      return 0
    fi
    sleep 2
  done
  die '服务已安装，HTTPS 尚未就绪。配置和数据已保留；检查 Cloudflare 权限、DNS 与出站网络，再运行 sudo waf doctor 和 sudo journalctl -u waf -n 80'
}

installer_cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$WAF_TEMP" ]]; then rm -rf -- "$WAF_TEMP"; fi
  if ((status != 0)); then
    printf '%s\n' '安装未完成，已保留现有系统文件和配置；请按上方错误处理，勿删除主密钥或数据。' >&2
  fi
  exit "$status"
}

main() {
  parse_args "$@"
  umask 077
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  check_environment
  check_existing
  open_terminal
  prompt_settings
  install_dependencies
  exec 4>/run/waf-install.lock
  flock -n 4 || die '另一个 WAF 安装进程正在运行'
  check_existing
  check_ports
  WAF_TEMP="$(mktemp -d /tmp/waf-install.XXXXXXXX)"
  trap installer_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  fetch_release
  install_waf
  wait_ready
  info "安装完成：v$WAF_VERSION"
  info "管理后台：https://$WAF_DOMAIN/  用户名：admin（密码 + TOTP 登录）"
  info '已设置开机自启。查看状态：sudo systemctl status waf'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
