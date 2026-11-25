#!/usr/bin/env bash
# =============================================================================
#  ZNAS Portal — Quick Installer for Debian / Ubuntu
#  Script version 1.5
#  https://github.com/macgaver/zfsnas-chezmoi
#
#  Usage (run as root or with sudo):
#    sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/macgaver/zfsnas-chezmoi/main/zfsnas-quickinstall-for-debian.sh)"
#
#  NOTE: do NOT use "sudo bash <(curl …)". Process substitution opens an fd in
#  your shell which the bash forked by sudo cannot access, yielding the
#  confusing error: bash: /dev/fd/63: No such file or directory.
# =============================================================================
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}▶${RESET}  $*"; }
success() { echo -e "${GREEN}✓${RESET}  $*"; }
warn()    { echo -e "${YELLOW}⚠${RESET}  $*"; }
fatal()   { echo -e "${RED}✗  ERROR: $*${RESET}" >&2; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}$*${RESET}"; echo -e "${CYAN}$(printf '─%.0s' {1..60})${RESET}"; }

# ── Constants ─────────────────────────────────────────────────────────────────
ZFSNAS_USER="zfsnas"
ZFSNAS_HOME="/home/zfsnas"   # user home (shell, .bashrc, .profile)
ZFSNAS_OPT="/opt/zfsnas"     # binary + config live here
ZFSNAS_BIN="${ZFSNAS_OPT}/zfsnas"
ZFSNAS_CONFIG="${ZFSNAS_OPT}/config"
SUDOERS_FILE="/etc/sudoers.d/zfsnas"
UNIT_FILE="/etc/systemd/system/zfsnas.service"
GITHUB_REPO="macgaver/zfsnas-chezmoi"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
ZFS_NEEDS_MOK=false          # set when Secure Boot refuses the freshly built ZFS module

# ── Preflight ─────────────────────────────────────────────────────────────────
header "ZNAS Portal — Quick Installer"

if [[ $EUID -ne 0 ]]; then
  # $0 is unhelpful here when invoked via "bash -c <script>" (it's "bash") or
  # via process substitution (it's "/dev/fd/63"). Print the canonical
  # one-liner instead so users can copy/paste it directly.
  echo -e "${RED}✗  ERROR: This script must be run as root.${RESET}" >&2
  echo -e "${YELLOW}  Use the recommended one-liner:${RESET}" >&2
  echo -e "  ${BOLD}sudo bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/macgaver/zfsnas-chezmoi/main/zfsnas-quickinstall-for-debian.sh)\"${RESET}" >&2
  exit 1
fi

# Detect Debian/Ubuntu
if ! command -v apt-get &>/dev/null; then
  fatal "apt-get not found. This script requires Debian or Ubuntu."
fi

DISTRO=$(grep -oP '(?<=^ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "unknown")
info "Detected distribution: ${DISTRO}"

# ── ZFS kernel check ──────────────────────────────────────────────────────────
header "Checking ZFS availability"

if zpool status &>/dev/null; then
  success "ZFS is available (zpool status OK)"
else
  warn "ZFS does not appear to be available on this system (zpool status failed)."
  echo
  echo -e "  ZNAS Portal requires ZFS to manage pools and datasets."
  echo -e "  The installer can set it up for you now:"
  echo
  if [[ "${DISTRO}" == "debian" ]]; then
    echo -e "    • Ensure ${BOLD}contrib${RESET} is enabled in /etc/apt/sources.list"
  fi
  [[ "${DISTRO}" == "debian" ]] && echo -e "    • Install the kernel headers, so the ZFS module can be built for this and future kernels"
  echo -e "    • Install zfsutils-linux"
  echo -e "    • Load the ZFS kernel module"
  echo
  read -r -p "  Install ZFS now? [y/N] " _ZFS_ANSWER
  case "${_ZFS_ANSWER}" in
    [yY]|[yY][eE][sS])
      echo
      info "Proceeding with ZFS installation…"

      # ── Ensure contrib is in sources (Debian only) ──────────────────────────
      if [[ "${DISTRO}" == "debian" ]]; then
        # Debian 13+ uses DEB822 format (.sources files with "Components:" lines).
        # Older Debian / Ubuntu use the traditional one-liner format in sources.list
        # and .list files.  We handle both.

        # Check if contrib is already present anywhere.
        _contrib_found=false
        # DEB822 format: "Components: main contrib …"
        if grep -rqE '^\s*Components:.*\bcontrib\b' /etc/apt/sources.list.d/ 2>/dev/null; then
          _contrib_found=true
        fi
        # Traditional format: "deb … contrib"
        if grep -rqE '^\s*(deb|deb-src)\b.*\bcontrib\b' \
             /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
          _contrib_found=true
        fi

        if [[ "${_contrib_found}" == "true" ]]; then
          success "contrib is already enabled in apt sources"
        else
          warn "contrib component not found — adding it to apt sources"
          _patched=false

          # ── DEB822 .sources files (Debian 13+) ───────────────────────────
          for _sf in /etc/apt/sources.list.d/*.sources; do
            [[ -f "${_sf}" ]] || continue
            # Append "contrib" to every "Components:" line that does not already have it
            sed -i '/^Components:/{/\bcontrib\b/!s/$/ contrib/}' "${_sf}"
            _patched=true
            info "  Updated: ${_sf}"
          done

          # ── Traditional one-liner format ──────────────────────────────────
          for _lf in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
            [[ -f "${_lf}" ]] || continue
            if grep -qE '^\s*(deb|deb-src)\b' "${_lf}" 2>/dev/null; then
              sed -i -E '/^\s*(deb|deb-src)\b/{/\bcontrib\b/!s/$/ contrib/}' "${_lf}"
              _patched=true
              info "  Updated: ${_lf}"
            fi
          done

          if [[ "${_patched}" == "true" ]]; then
            success "contrib added to apt sources"
          else
            warn "Could not locate any apt source files to patch — you may need to add 'contrib' manually."
          fi
        fi
      fi

      # ── Update package index ────────────────────────────────────────────────
      info "Updating package index…"
      apt-get update -qq

      _KVER=$(uname -r)

      # ── Install kernel headers (Debian: the ZFS module is built by DKMS) ────
      # Ubuntu ships the ZFS module with its kernels, so it needs no headers.
      # Debian builds it with DKMS against the headers of each kernel: install
      # the running kernel's headers AND the headers metapackage of its flavour
      # (linux-headers-amd64, -cloud-amd64, -rt-amd64…). The metapackage pulls
      # the headers of every future kernel, so DKMS rebuilds ZFS on each kernel
      # update. Without it, the first kernel update leaves the next boot with
      # no ZFS module and no pools.
      if [[ "${DISTRO}" == "debian" ]]; then
        _HDR_PKGS=("linux-headers-${_KVER}")
        # 6.12.57+deb13-amd64 → amd64 · 6.12.57+deb13-cloud-amd64 → cloud-amd64 · 6.1.0-28-amd64 → amd64
        _FLAVOUR=$(sed -E 's/^[0-9.]+(\+deb[0-9]+)?(-[0-9]+)?-//' <<<"${_KVER}")
        if apt-cache show "linux-headers-${_FLAVOUR}" &>/dev/null; then
          _HDR_PKGS+=("linux-headers-${_FLAVOUR}")
        fi
        info "Installing kernel headers: ${_HDR_PKGS[*]}…"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "${_HDR_PKGS[@]}" || \
          warn "Could not install ${_HDR_PKGS[*]} — the ZFS module build may fail. Continuing anyway."
      fi

      # ── Install zfsutils-linux ──────────────────────────────────────────────
      # noninteractive: zfs-dkms otherwise stops on a full-screen licence notice.
      info "Installing zfsutils-linux (on Debian the ZFS module is compiled now: this takes a few minutes)…"
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q zfsutils-linux
      success "zfsutils-linux installed"

      # ── Load the ZFS kernel module ──────────────────────────────────────────
      info "Loading ZFS kernel module (modprobe zfs)…"
      if _MODPROBE_ERR=$(modprobe zfs 2>&1); then
        success "ZFS kernel module loaded"
      elif grep -q 'Key was rejected' <<<"${_MODPROBE_ERR}"; then
        # Secure Boot only loads modules signed with a key the firmware trusts.
        # DKMS signed ZFS with its own key: the firmware must be told to trust
        # it (MOK enrolment), which takes a reboot and a confirmation on the
        # server's screen.
        ZFS_NEEDS_MOK=true
        _MOK_PUB=/var/lib/dkms/mok.pub
        warn "Secure Boot is on, and it refuses the ZFS module until its signing key is enrolled."
        if [[ -f "${_MOK_PUB}" ]]; then
          command -v mokutil &>/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q mokutil
          if mokutil --test-key "${_MOK_PUB}" 2>/dev/null | grep -q 'already enrolled'; then
            warn "The key is already enrolled: reboot the server to load ZFS."
          else
            echo
            echo -e "  To trust the key, choose a ${BOLD}one-time password${RESET} now. You will type it"
            echo -e "  once more on the server's screen after the reboot."
            echo
            if mokutil --import "${_MOK_PUB}"; then
              success "Signing key queued for enrolment"
            else
              warn "Key enrolment was not queued. Run it later with:  mokutil --import ${_MOK_PUB}"
            fi
          fi
        else
          warn "DKMS signing key ${_MOK_PUB} not found: enrol your module signing key with mokutil, or turn Secure Boot off."
        fi
      else
        warn "modprobe zfs failed: ${_MODPROBE_ERR}"
        warn "The installation goes on; ZFS is needed before pools can be used."
      fi
      ;;
    *)
      echo
      info "Skipping ZFS installation. Exiting."
      exit 0
      ;;
  esac
fi

# ── Dependencies ──────────────────────────────────────────────────────────────
header "Checking and installing dependencies"

apt-get update -qq

# Map: "command" → "package(s) to install"
# Only tools actually invoked by the portal binary are listed here.
declare -A REQUIRED_CMDS=(
  [curl]="curl"
  [sudo]="sudo"
  [lsblk]="util-linux"
  [blkid]="util-linux"
  [wipefs]="util-linux"
  [sgdisk]="gdisk"
  [partprobe]="parted"
  [smartctl]="smartmontools"
  [nvme]="nvme-cli"
  [udevadm]="udev"
  [timedatectl]="systemd"
  [exportfs]="nfs-kernel-server"
  [smbpasswd]="samba"
)

PKGS_TO_INSTALL=()
for _cmd in "${!REQUIRED_CMDS[@]}"; do
  if ! command -v "${_cmd}" &>/dev/null; then
    _pkg="${REQUIRED_CMDS[$_cmd]}"
    warn "Missing command '${_cmd}' — will install package '${_pkg}'"
    PKGS_TO_INSTALL+=("${_pkg}")
  fi
done

# Deduplicate and install
if [[ ${#PKGS_TO_INSTALL[@]} -gt 0 ]]; then
  # Sort + unique
  mapfile -t PKGS_TO_INSTALL < <(printf '%s\n' "${PKGS_TO_INSTALL[@]}" | sort -u)
  info "Installing missing packages: ${PKGS_TO_INSTALL[*]}"
  apt-get install -y -q --no-install-recommends "${PKGS_TO_INSTALL[@]}"
fi

# Always ensure ca-certificates and bash are present
apt-get install -y -q --no-install-recommends ca-certificates bash &>/dev/null

success "All dependencies satisfied"

# ── Create zfsnas user ────────────────────────────────────────────────────────
header "Creating system user"

if id "${ZFSNAS_USER}" &>/dev/null; then
  warn "User '${ZFSNAS_USER}' already exists — skipping creation"
else
  useradd \
    --system \
    --shell /bin/bash \
    --home-dir "${ZFSNAS_HOME}" \
    --create-home \
    "${ZFSNAS_USER}"
  success "User '${ZFSNAS_USER}' created with home ${ZFSNAS_HOME}"
fi

# Ensure home directory and /opt/zfsnas (binary + config) exist with correct permissions
mkdir -p "${ZFSNAS_HOME}" "${ZFSNAS_OPT}" "${ZFSNAS_CONFIG}"
chown -R "${ZFSNAS_USER}:${ZFSNAS_USER}" "${ZFSNAS_HOME}" "${ZFSNAS_OPT}"

# ── Write .bashrc ─────────────────────────────────────────────────────────────
header "Configuring shell"

cat > "${ZFSNAS_HOME}/.bashrc" << 'BASHRC'
# ~/.bashrc — zfsnas user

# Only run in interactive shells
[[ $- != *i* ]] && return

# ── Prompt ────────────────────────────────────────────────────────────────────
_CYAN='\[\e[0;36m\]'
_GREEN='\[\e[0;32m\]'
_YELLOW='\[\e[1;33m\]'
_RESET='\[\e[0m\]'
PS1="${_CYAN}\u${_RESET}@${_GREEN}\h${_RESET}:${_YELLOW}\w${_RESET}\$ "
unset _CYAN _GREEN _YELLOW _RESET

# ── History ───────────────────────────────────────────────────────────────────
HISTSIZE=5000
HISTFILESIZE=10000
HISTCONTROL=ignoreboth:erasedups
shopt -s histappend
PROMPT_COMMAND='history -a'

# ── Environment ───────────────────────────────────────────────────────────────
export EDITOR=nano
export PAGER=less
export LESS='-R --quit-if-one-screen'

# ── Aliases ───────────────────────────────────────────────────────────────────
alias ls='ls --color=auto'
alias ll='ls -lhF'
alias la='ls -lhAF'
alias grep='grep --color=auto'
alias ..='cd ..'
alias ...='cd ../..'

alias zfsnas-log='journalctl -u zfsnas -f'
alias zfsnas-status='systemctl status zfsnas'
alias zfsnas-restart='sudo systemctl restart zfsnas'

# ── ZFS shortcuts ─────────────────────────────────────────────────────────────
alias zlist='sudo zfs list'
alias zplist='sudo zpool list'
alias zpstatus='sudo zpool status'
BASHRC

chown "${ZFSNAS_USER}:${ZFSNAS_USER}" "${ZFSNAS_HOME}/.bashrc"
success ".bashrc written to ${ZFSNAS_HOME}"

# Also write .profile so login shells source .bashrc
cat > "${ZFSNAS_HOME}/.profile" << 'PROFILE'
# ~/.profile
[[ -f ~/.bashrc ]] && . ~/.bashrc
PROFILE
chown "${ZFSNAS_USER}:${ZFSNAS_USER}" "${ZFSNAS_HOME}/.profile"

# ── Sudoers ───────────────────────────────────────────────────────────────────
header "Configuring sudo access"

cat > "${SUDOERS_FILE}" << SUDOERS
# ZNAS Portal — passwordless sudo required for ZFS, Samba, NFS, SMART, and power commands
${ZFSNAS_USER} ALL=(ALL) NOPASSWD: ALL
SUDOERS
chmod 0440 "${SUDOERS_FILE}"

# Validate the sudoers file
if ! visudo -cf "${SUDOERS_FILE}" &>/dev/null; then
  rm -f "${SUDOERS_FILE}"
  fatal "Sudoers validation failed — file removed"
fi
success "Sudoers configured at ${SUDOERS_FILE}"

# ── Download binary ───────────────────────────────────────────────────────────
header "Downloading ZNAS binary"

info "Fetching latest release from GitHub…"
RELEASE_JSON=$(curl -fsSL "${GITHUB_API}" 2>/dev/null) || fatal "Could not reach GitHub API. Check your internet connection."

# Extract the first .tar.gz or bare binary download URL
DOWNLOAD_URL=$(echo "${RELEASE_JSON}" \
  | grep '"browser_download_url"' \
  | grep -v '\.sha256"\|\.md5"\|\.txt"\|\.sig"' \
  | head -1 \
  | sed 's/.*"browser_download_url": "\(.*\)"/\1/')

if [[ -z "${DOWNLOAD_URL}" ]]; then
  fatal "No binary asset found in the latest release.\nCheck: https://github.com/${GITHUB_REPO}/releases"
fi

info "Downloading: ${DOWNLOAD_URL}"
TMPFILE=$(mktemp /tmp/zfsnas.XXXXXX)
trap 'rm -f "${TMPFILE}"' EXIT

curl -fsSL --progress-bar -o "${TMPFILE}" "${DOWNLOAD_URL}"

# If it's a tar archive, extract the binary
if [[ "$(head -c2 "${TMPFILE}" | od -An -tx1 | tr -d ' ')" == "1f8b" ]]; then
  info "Extracting archive…"
  TMPDIR_EXTRACT=$(mktemp -d /tmp/zfsnas-extract.XXXXXX)
  tar -xzf "${TMPFILE}" -C "${TMPDIR_EXTRACT}"
  # Find the zfsnas binary inside the archive
  EXTRACTED=$(find "${TMPDIR_EXTRACT}" -maxdepth 2 -type f -name 'zfsnas' | head -1)
  if [[ -z "${EXTRACTED}" ]]; then
    rm -rf "${TMPDIR_EXTRACT}"
    fatal "Could not find 'zfsnas' binary inside the archive"
  fi
  cp "${EXTRACTED}" "${ZFSNAS_BIN}"
  rm -rf "${TMPDIR_EXTRACT}"
else
  cp "${TMPFILE}" "${ZFSNAS_BIN}"
fi

chmod 755 "${ZFSNAS_BIN}"
chown "${ZFSNAS_USER}:${ZFSNAS_USER}" "${ZFSNAS_BIN}"
success "Binary installed at ${ZFSNAS_BIN}"

# Print version
BIN_VERSION=$("${ZFSNAS_BIN}" --version 2>/dev/null || true)
[[ -n "${BIN_VERSION}" ]] && info "Version: ${BIN_VERSION}"

# ── Systemd service ───────────────────────────────────────────────────────────
header "Installing systemd service"

cat > "${UNIT_FILE}" << UNIT
[Unit]
Description=ZNAS Management Portal
Documentation=https://github.com/${GITHUB_REPO}
After=network.target

[Service]
Type=simple
User=${ZFSNAS_USER}
Group=${ZFSNAS_USER}
WorkingDirectory=${ZFSNAS_OPT}
ExecStart=${ZFSNAS_BIN}
Restart=on-failure
RestartSec=5

# Give the process time to bind its TLS port on startup
TimeoutStartSec=30

# Harden the service a little (compatible with sudo usage)
NoNewPrivileges=no

# Allow the non-root service account to bind privileged ports (e.g. 443)
# when the "Also bind port 443" option is enabled in Settings. This is the
# single capability needed to bind low ports — nothing else is elevated.
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable zfsnas
systemctl restart zfsnas
success "Service enabled and started"
sync   # flush the binary and unit to disk before anyone reboots or powers off

# ── Detect IP for setup URL ───────────────────────────────────────────────────
SETUP_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1 || echo "YOUR-SERVER-IP")

# ── Done ──────────────────────────────────────────────────────────────────────
echo
echo -e "${GREEN}$(printf '═%.0s' {1..60})${RESET}"
echo -e "${BOLD}${GREEN}  ZNAS Portal installed successfully!${RESET}"
echo -e "${GREEN}$(printf '═%.0s' {1..60})${RESET}"
echo
if [[ "${ZFS_NEEDS_MOK}" == "true" ]]; then
  echo -e "  ${YELLOW}${BOLD}ZFS is installed but not active yet (Secure Boot).${RESET}"
  echo -e "  1. Reboot the server:  ${CYAN}reboot${RESET}"
  echo -e "  2. On the server's screen a blue ${BOLD}MOK management${RESET} menu appears:"
  echo -e "     choose ${BOLD}Enroll MOK${RESET} → ${BOLD}Continue${RESET} → ${BOLD}Yes${RESET}, type the one-time password, then ${BOLD}Reboot${RESET}."
  echo -e "  ZFS then loads at every boot. (Or turn Secure Boot off in the firmware.)"
  echo
fi
echo -e "  ${BOLD}Open your browser and complete setup at:${RESET}"
echo
echo -e "    ${CYAN}${BOLD}https://${SETUP_IP}:8443/setup${RESET}"
echo
echo -e "  ${YELLOW}Note:${RESET} The portal uses a self-signed TLS certificate."
echo -e "  Your browser will show a security warning — this is expected."
echo -e "  Accept the exception and proceed to the setup wizard."
echo
echo -e "  Useful commands:"
echo -e "    ${CYAN}journalctl -u zfsnas -f${RESET}        — live logs"
echo -e "    ${CYAN}systemctl status zfsnas${RESET}        — service status"
echo -e "    ${CYAN}systemctl restart zfsnas${RESET}       — restart"
echo -e "    ${CYAN}su - zfsnas${RESET}                    — switch to service user"
echo
