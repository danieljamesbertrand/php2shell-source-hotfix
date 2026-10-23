#!/usr/bin/env bash
# php2shell-hotfix.sh — remediate CVE-2026-109618 / CVE-2026-109619 (PHP2Shell)
# Prefer distro packages; fall back to building a fixed upstream PHP from source.
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
LOG="${LOG:-/tmp/php2shell-hotfix.log}"

# Fixed upstream floors per minor branch (PHP project, 2026-10-21)
FIXED_82="8.2.35"
FIXED_83="8.3.36"
FIXED_84="8.4.27"
FIXED_85="8.5.12"

CHECK_ONLY=0
FORCE_SOURCE=0
KEEP_CLOSED=0
NO_FIREWALL=0
OVERRIDE_VERSION=""
PREFIX_OVERRIDE=""

log() { echo "[$(date -Is)] $*" | tee -a "$LOG"; }
die() { log "ERROR: $*"; exit 1; }
need_root() { [[ "$(id -u)" -eq 0 ]] || die "Run as root (sudo $SCRIPT_NAME ...)"; }

usage() {
  cat <<EOF
$SCRIPT_NAME — fix PHP2Shell (CVE-2026-109618, CVE-2026-109619)

Usage: sudo $SCRIPT_NAME [options]

  --check              Report status only
  --force-source       Build from php.net even if apt has a fix
  --php-version X.Y.Z  Target fixed version (default: newest fixed for installed major.minor)
  --keep-closed        Leave UFW 80/443 denied after success
  --no-firewall        Do not modify UFW
  --prefix DIR         Install prefix (default: /usr/local/php-VERSION)
  -h, --help           Show help

See README.md for CVE details and references.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) CHECK_ONLY=1 ;;
    --force-source) FORCE_SOURCE=1 ;;
    --keep-closed) KEEP_CLOSED=1 ;;
    --no-firewall) NO_FIREWALL=1 ;;
    --php-version) OVERRIDE_VERSION="${2:-}"; shift ;;
    --prefix) PREFIX_OVERRIDE="${2:-}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (try --help)" ;;
  esac
  shift
done

version_ge() {
  # return 0 if $1 >= $2 (semver X.Y.Z)
  printf '%s\n%s\n' "$2" "$1" | sort -V | head -1 | grep -qx "$2"
}

fixed_for_series() {
  case "$1" in
    8.2) echo "$FIXED_82" ;;
    8.3) echo "$FIXED_83" ;;
    8.4) echo "$FIXED_84" ;;
    8.5) echo "$FIXED_85" ;;
    *) echo "" ;;
  esac
}

current_php_version() {
  if command -v php >/dev/null 2>&1; then
    php -r 'echo PHP_VERSION;' 2>/dev/null || true
  fi
}

series_of() {
  # 8.4.5 -> 8.4
  echo "$1" | awk -F. '{print $1"."$2}'
}

is_patched() {
  local ver="$1"
  local series floor
  series="$(series_of "$ver")"
  floor="$(fixed_for_series "$series")"
  [[ -n "$floor" ]] || return 1
  version_ge "$ver" "$floor"
}

detect_sapi() {
  if [[ -f /etc/apache2/mods-enabled/php*.load ]] || ls /etc/apache2/mods-enabled/php*.load >/dev/null 2>&1; then
    echo "apache2"
  elif systemctl is-active --quiet php*-fpm 2>/dev/null || systemctl list-units --type=service --state=running 2>/dev/null | grep -q 'php.*fpm'; then
    echo "fpm"
  else
    echo "cli"
  fi
}

ufw_deny_http() {
  [[ "$NO_FIREWALL" -eq 1 ]] && return 0
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | grep -qi 'Status: active' || return 0
  log "UFW: inserting deny for public 80/443 during remediation"
  ufw insert 1 deny 80/tcp comment 'php2shell-hotfix temp' 2>/dev/null || ufw deny 80/tcp comment 'php2shell-hotfix temp' || true
  ufw insert 1 deny 443/tcp comment 'php2shell-hotfix temp' 2>/dev/null || ufw deny 443/tcp comment 'php2shell-hotfix temp' || true
}

ufw_allow_http() {
  [[ "$NO_FIREWALL" -eq 1 || "$KEEP_CLOSED" -eq 1 ]] && {
    log "UFW: leaving 80/443 as-is (no-firewall or keep-closed)"
    return 0
  }
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | grep -qi 'Status: active' || return 0
  log "UFW: removing temp deny rules and allowing 80/443"
  # Delete numbered deny rules that match our comment or plain deny 80/443
  local n
  mapfile -t nums < <(ufw status numbered 2>/dev/null | grep -E 'DENY.*(80|443)' | sed -E 's/^\[([[:space:]]*[0-9]+)\].*/\1/' | tr -d ' ' | sort -nr)
  for n in "${nums[@]:-}"; do
    [[ -n "${n:-}" ]] || continue
    yes | ufw delete "$n" >/dev/null 2>&1 || true
  done
  ufw allow 80/tcp comment 'HTTP after php2shell-hotfix' >/dev/null 2>&1 || true
  ufw allow 443/tcp comment 'HTTPS after php2shell-hotfix' >/dev/null 2>&1 || true
  ufw reload >/dev/null 2>&1 || true
}

try_apt_fix() {
  command -v apt-get >/dev/null 2>&1 || return 1
  export DEBIAN_FRONTEND=noninteractive
  log "Checking apt for fixed PHP packages..."
  apt-get update -y >>"$LOG" 2>&1 || true

  local pkgs=()
  mapfile -t pkgs < <(dpkg-query -W -f='${Package}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null | grep -E '^php[0-9]|^libapache2-mod-php' || true)
  if [[ ${#pkgs[@]} -eq 0 ]]; then
    log "No php packages found via dpkg"
    return 1
  fi

  apt-get install -y --only-upgrade "${pkgs[@]}" >>"$LOG" 2>&1 || apt-get install -y "${pkgs[@]}" >>"$LOG" 2>&1 || true

  local ver
  ver="$(current_php_version)"
  if [[ -n "$ver" ]] && is_patched "$ver"; then
    log "apt path succeeded: PHP $ver is patched"
    # Restart services
    systemctl try-restart apache2 2>/dev/null || true
    systemctl try-restart 'php*-fpm' 2>/dev/null || true
    return 0
  fi
  log "apt did not yield a fixed PHP (now: ${ver:-unknown})"
  return 1
}

install_build_deps() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >>"$LOG" 2>&1
  apt-get install -y --no-install-recommends \
    build-essential autoconf bison re2c pkg-config \
    libxml2-dev libsqlite3-dev libssl-dev libcurl4-openssl-dev \
    libpng-dev libjpeg-dev libfreetype6-dev libwebp-dev \
    libonig-dev libzip-dev libxslt1-dev libsodium-dev \
    zlib1g-dev libreadline-dev libffi-dev \
    apache2-dev curl ca-certificates xz-utils \
    >>"$LOG" 2>&1
}

build_from_source() {
  local ver="$1"
  local prefix="${PREFIX_OVERRIDE:-/usr/local/php-${ver}}"
  local src_dir="/usr/src/php-${ver}"
  local build_dir="/usr/src/php-${ver}-build"
  local tarball="php-${ver}.tar.xz"
  local url="https://www.php.net/distributions/${tarball}"

  log "Building PHP ${ver} from source → ${prefix}"
  mkdir -p /usr/src
  cd /usr/src
  if [[ ! -f "$tarball" ]]; then
    curl -fsSL -o "$tarball" "$url" || die "Failed to download $url"
  fi
  rm -rf "$src_dir" "$build_dir"
  tar -xf "$tarball"
  mkdir -p "$build_dir"
  cd "$build_dir"

  # PHP 7.4+ uses --enable-gd (not --with-gd)
  "${src_dir}/configure" \
    --prefix="$prefix" \
    --with-config-file-path=/etc/php/"$(series_of "$ver")"/cli \
    --with-config-file-scan-dir=/etc/php/"$(series_of "$ver")"/cli/conf.d \
    --enable-option-checking=fatal \
    --with-apxs2=/usr/bin/apxs \
    --enable-bcmath \
    --enable-calendar \
    --enable-exif \
    --enable-ftp \
    --enable-mbstring \
    --enable-pcntl \
    --enable-shmop \
    --enable-sockets \
    --enable-sysvmsg \
    --enable-sysvsem \
    --enable-sysvshm \
    --with-curl \
    --with-ffi \
    --enable-gd \
    --with-freetype \
    --with-jpeg \
    --with-webp \
    --with-gettext \
    --with-mysqli=mysqlnd \
    --with-pdo-mysql=mysqlnd \
    --with-openssl \
    --with-readline \
    --with-sodium \
    --with-xsl \
    --with-zip \
    --with-zlib \
    --enable-opcache \
    --disable-phpdbg \
    --disable-cgi \
    >>"$LOG" 2>&1

  local jobs=1
  # Use more parallelism only when RAM looks comfortable
  local mem_kb
  mem_kb="$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  if [[ "${mem_kb:-0}" -gt 3000000 ]]; then
    jobs="$(nproc 2>/dev/null || echo 2)"
  fi
  log "make -j${jobs}"
  make -j"${jobs}" >>"$LOG" 2>&1
  make install >>"$LOG" 2>&1

  install_binaries "$ver" "$prefix"
  fix_ubuntu_confd "$ver" "$prefix"
}

install_binaries() {
  local ver="$1"
  local prefix="$2"
  local series
  series="$(series_of "$ver")"

  # Locate built Apache module
  local new_mod=""
  for cand in \
    "${prefix}/lib/libphp.so" \
    /usr/lib/apache2/modules/libphp.so \
    /usr/lib/apache2/modules/libphp"${series}".so
  do
    if [[ -f "$cand" ]]; then
      new_mod="$cand"
      [[ "$cand" == "${prefix}"/* ]] && break
    fi
  done
  if [[ -z "$new_mod" ]]; then
    new_mod="$(find "$prefix" /usr/lib/apache2/modules -name 'libphp*.so' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2- || true)"
  fi
  [[ -n "$new_mod" && -f "$new_mod" ]] || die "Could not find built libphp module"

  local dest="/usr/lib/apache2/modules/libphp${series}.so"
  if [[ -f "$dest" && ! -f "${dest}.distro" ]]; then
    cp -a "$dest" "${dest}.distro"
  fi
  cp -a "$new_mod" "$dest"

  # Prefer phpX.Y module; disable generic php.load from apxs if present
  if [[ -e /etc/apache2/mods-enabled/php.load ]]; then
    a2dismod -f php >/dev/null 2>&1 || rm -f /etc/apache2/mods-enabled/php.load /etc/apache2/mods-enabled/php.conf
  fi

  local load="/etc/apache2/mods-available/php${series}.load"
  cat > "$load" <<EOF
# Conflicts: php5
# Depends: mpm_prefork
# Installed by php2shell-hotfix (${ver})
LoadModule php_module ${dest}
EOF
  local conf="/etc/apache2/mods-available/php${series}.conf"
  if [[ -f "$conf" ]] && ! grep -q 'PHPIniDir' "$conf"; then
    printf '\n# php2shell-hotfix\nPHPIniDir /etc/php/%s/apache2\n' "$series" >> "$conf"
  fi
  a2enmod "php${series}" >/dev/null 2>&1 || true

  # CLI
  if [[ -f /usr/bin/php && ! -f /usr/bin/php.distro ]]; then
    cp -a /usr/bin/php /usr/bin/php.distro
  fi
  if [[ -f "/usr/bin/php${series}" && ! -f "/usr/bin/php${series}.distro" ]]; then
    cp -a "/usr/bin/php${series}" "/usr/bin/php${series}.distro"
  fi
  cp -a "${prefix}/bin/php" /usr/bin/php
  cp -a "${prefix}/bin/php" "/usr/bin/php${series}"
  cp -a "${prefix}/bin/php" "/usr/local/bin/php-${ver}"
}

fix_ubuntu_confd() {
  local ver="$1"
  local prefix="$2"
  local series
  series="$(series_of "$ver")"
  local extdir
  extdir="$(find "${prefix}/lib/php/extensions" -type d -name 'no-debug-*' 2>/dev/null | head -1 || true)"

  for sapidir in cli apache2; do
    local confd="/etc/php/${series}/${sapidir}/conf.d"
    [[ -d "$confd" ]] || continue
    mkdir -p "${confd}.disabled-for-custom-php"
    local f base
    for f in "$confd"/*; do
      [[ -e "$f" ]] || continue
      base="$(basename "$f")"
      if [[ "$base" == *opcache* && -n "$extdir" && -f "${extdir}/opcache.so" ]]; then
        cat > "$f" <<EOF
; php2shell-hotfix custom build ${ver}
zend_extension=${extdir}/opcache.so
EOF
        continue
      fi
      if grep -Eq '^\s*(extension|zend_extension)\s*=' "$f" 2>/dev/null; then
        mv -f "$f" "${confd}.disabled-for-custom-php/${base}"
      fi
    done
  done
}

verify_install() {
  local expect="$1"
  local got
  got="$(php -r 'echo PHP_VERSION;' 2>/dev/null || true)"
  [[ "$got" == "$expect" ]] || die "Expected PHP ${expect}, got ${got:-none}"
  if command -v apache2ctl >/dev/null 2>&1; then
    apache2ctl configtest >>"$LOG" 2>&1 || die "apache2ctl configtest failed"
    systemctl restart apache2
    systemctl is-active --quiet apache2 || die "apache2 failed to start"
  fi
  log "Verified PHP ${got} (CLI); modules:"
  php -m >>"$LOG" 2>&1 || true
}

# --- main ---
: >"$LOG"
need_root

CUR="$(current_php_version)"
[[ -n "$CUR" ]] || die "php not found in PATH"
SERIES="$(series_of "$CUR")"
TARGET="$(fixed_for_series "$SERIES")"
[[ -n "$TARGET" ]] || die "Unsupported PHP series ${SERIES}. Supported: 8.2–8.5"
if [[ -n "$OVERRIDE_VERSION" ]]; then
  TARGET="$OVERRIDE_VERSION"
fi

SAPI="$(detect_sapi)"
log "Host: $(hostname) | PHP ${CUR} | series ${SERIES} | SAPI ${SAPI}"
log "Target fixed version: ${TARGET}"
log "CVEs: CVE-2026-109618, CVE-2026-109619 (PHP2Shell)"

if is_patched "$CUR"; then
  log "Already patched (>= ${TARGET} for ${SERIES}). Nothing to do."
  exit 0
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  log "VULNERABLE: ${CUR} < ${TARGET}"
  log "Remediation: sudo $SCRIPT_NAME"
  exit 2
fi

if [[ "$SAPI" == "fpm" ]]; then
  log "WARNING: PHP-FPM detected. This script replaces CLI + Apache mod_php."
  log "WARNING: After source build you must point FPM at ${PREFIX_OVERRIDE:-/usr/local/php-${TARGET}}/sbin/php-fpm manually (not automated)."
fi

ufw_deny_http
systemctl stop apache2 2>/dev/null || true

if [[ "$FORCE_SOURCE" -eq 0 ]]; then
  if try_apt_fix; then
    ufw_allow_http
    log "SUCCESS via apt"
    exit 0
  fi
else
  log "Skipping apt (--force-source)"
fi

command -v apt-get >/dev/null 2>&1 || die "Source build path currently supports Debian/Ubuntu (apt)"
install_build_deps
build_from_source "$TARGET"
verify_install "$TARGET"
ufw_allow_http

log "SUCCESS: PHP ${TARGET} installed from source"
log "Backups: /usr/bin/php.distro and /usr/lib/apache2/modules/libphp*.so.distro (if present)"
log "Log: ${LOG}"
echo "OK PHP ${TARGET}"
