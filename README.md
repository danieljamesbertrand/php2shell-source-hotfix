# php2shell-source-hotfix

Emergency remediation for **PHP2Shell** when your Linux distro has **no apt/yum package yet**.

## What this fixes

| ID | Nickname | Summary | Severity |
|----|----------|---------|----------|
| [CVE-2026-109618](https://ubuntu.com/blog/php2shell-vulnerability-fixes-available) | PHP2Shell (OOM path) | Out-of-memory corruption during request handling can lead to **unauthenticated remote code execution** | Critical (CVSS v4 ≈ 9.2) |
| [CVE-2026-109619](https://ubuntu.com/blog/php2shell-vulnerability-fixes-available) | PHP2Shell (stale state) | Stale global / use-after-free across requests in the same worker → **unauthenticated RCE** | Critical (CVSS v4 ≈ 9.2) |

Upstream fixed versions (PHP project, 2026-10-21):

| Branch | Fixed release |
|--------|----------------|
| PHP 8.5 | **8.5.12** |
| PHP 8.4 | **8.4.27** |
| PHP 8.3 | **8.3.36** |
| PHP 8.2 | **8.2.35** |

Ubuntu published fixes for several LTS / interim releases via **USN-8948-1**, but **not every interim Ubuntu release gets a package at the same time** (e.g. Plucky 25.04 was left without a `php8.4` security update while Jammy/Noble/Resolute already had one). This repo is for that gap.

**Official references**

- Ubuntu: https://ubuntu.com/blog/php2shell-vulnerability-fixes-available  
- Ubuntu security notice: https://ubuntu.com/security/notices/USN-8948-1  
- PHP downloads: https://www.php.net/downloads.php  

## What the script does

1. Detects installed PHP major/minor (`php -v`).
2. **Prefers distro packages** — if `apt` already offers a fixed version, it installs that and exits.
3. Otherwise **builds the matching fixed upstream release from source** (official `php.net` tarball).
4. Installs under `/usr/local/php-<version>`, replaces Apache `libphp*.so` + CLI `/usr/bin/php` (with `*.distro` backups).
5. Disables Ubuntu `conf.d` `extension=*.so` stubs that break a static/custom build (keeps OPcache as a shared Zend extension when present).
6. Optionally keeps **UFW deny on 80/443** until verify succeeds, then reopens.

Designed for **Ubuntu/Debian + Apache mod_php** (the common small-VPS layout). PHP-FPM is detected and warned; full FPM wiring is not automated yet.

## Requirements

- Root (or passwordless/`sudo`)
- ~2–4 GB free disk for a source build
- Build toolchain (installed automatically on Debian/Ubuntu)
- Network access to `php.net` and your package mirrors
- Low-RAM hosts: script uses `make -j1` and expects swap

## Quick start

```bash
# Review first — this replaces system PHP binaries
curl -fsSL https://raw.githubusercontent.com/danieljamesbertrand/php2shell-source-hotfix/main/bin/php2shell-hotfix.sh -o php2shell-hotfix.sh
chmod +x php2shell-hotfix.sh
sudo ./php2shell-hotfix.sh --check          # report only
sudo ./php2shell-hotfix.sh                  # apt if possible, else source build
sudo ./php2shell-hotfix.sh --keep-closed    # leave UFW 80/443 denied after install
```

Or clone:

```bash
git clone https://github.com/danieljamesbertrand/php2shell-source-hotfix.git
cd php2shell-source-hotfix
sudo ./bin/php2shell-hotfix.sh
```

## Options

| Flag | Meaning |
|------|---------|
| `--check` | Print current version / vulnerability status; do not change the system |
| `--force-source` | Skip apt even if a fixed package exists |
| `--php-version X.Y.Z` | Override target (must be a fixed release) |
| `--keep-closed` | Do not reopen UFW 80/443 after success |
| `--no-firewall` | Do not touch UFW at all |
| `--prefix DIR` | Install prefix (default `/usr/local/php-<ver>`) |
| `-h`, `--help` | Help |

## Aftercare

- Confirm: `php -v` and a local `curl http://127.0.0.1/` smoke test.
- This is a **custom build**. Later `apt upgrade` will **not** replace it with security updates. When your distro ships a fixed package, restore `*.distro` backups or reinstall `php*` packages and remove `/usr/local/php-*`.
- Temporary mitigations (if you cannot patch yet) are documented by vendors: lower `post_max_size`, `memory_limit` admin locks, disable `session.upload_progress` — **patching is the real fix**.

## License

MIT. Use at your own risk; test on a staging host when you can. Not affiliated with the PHP Group or Canonical.
