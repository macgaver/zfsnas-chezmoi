#!/usr/bin/env bash
# =============================================================================
#  ZFS NAS Portal — Quick Installer for Debian / Ubuntu
#  https://github.com/macgaver/zfsnas-chezmoi
#
#  Usage (run as root or with sudo):
#    bash <(curl -fsSL https://raw.githubusercontent.com/macgaver/zfsnas-chezmoi/main/zfsnas-quickinstall-for-debian.sh)
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
ZFSNAS_HOME="/opt/zfsnas"
ZFSNAS_BIN="${ZFSNAS_HOME}/zfsnas"
ZFSNAS_CONFIG="${ZFSNAS_HOME}/config"
SUDOERS_FILE="/etc/sudoers.d/zfsnas"
UNIT_FILE="/etc/systemd/system/zfsnas.service"
GITHUB_REPO="macgaver/zfsnas-chezmoi"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"

# ── Preflight ─────────────────────────────────────────────────────────────────
header "ZFS NAS Portal — Quick Installer"

if [[ $EUID -ne 0 ]]; then
  fatal "This script must be run as root. Try: sudo bash $0"
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
  echo -e "  ZFS NAS Portal requires ZFS to manage pools and datasets."
  echo -e "  The installer can set it up for you now:"
  echo
  if [[ "${DISTRO}" == "debian" ]]; then
    echo -e "    • Ensure ${BOLD}contrib${RESET} is enabled in /etc/apt/sources.list"
  fi
  echo -e "    • Install linux-headers for the current kernel"
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
        _SOURCES_FILE="/etc/apt/sources.list"
        # Check any .list file under sources.list.d as well
        if grep -rqE '^\s*deb\b.*\bcontrib\b' "${_SOURCES_FILE}" /etc/apt/sources.list.d/ 2>/dev/null; then
          success "contrib is already enabled in apt sources"
        else
          warn "contrib component not found — adding it to ${_SOURCES_FILE}"
          # Append contrib to every non-commented deb / deb-src line that lacks it
          sed -i -E '/^\s*(deb|deb-src)\b/{/\bcontrib\b/!s/$/ contrib/}' "${_SOURCES_FILE}"
          success "contrib added to ${_SOURCES_FILE}"
        fi
      fi

      # ── Update package index ────────────────────────────────────────────────
      info "Updating package index…"
      apt-get update -qq

      # ── Install kernel headers ──────────────────────────────────────────────
      _KVER=$(uname -r)
      info "Installing linux-headers-${_KVER}…"
      apt-get install -y -q --no-install-recommends "linux-headers-${_KVER}" || \
        warn "Could not install linux-headers-${_KVER} — ZFS DKMS build may fail. Continuing anyway."

      # ── Install zfsutils-linux ──────────────────────────────────────────────
      info "Installing zfsutils-linux…"
      apt-get install -y -q zfsutils-linux
      success "zfsutils-linux installed"

      # ── Load the ZFS kernel module ──────────────────────────────────────────
      info "Loading ZFS kernel module (modprobe zfs)…"
      if modprobe zfs; then
        success "ZFS kernel module loaded"
      else
        warn "modprobe zfs failed — a reboot may be required to activate the module."
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
header "Installing dependencies"

apt-get update -qq
apt-get install -y -q --no-install-recommends \
  curl \
  ca-certificates \
  sudo \
  bash
success "Base dependencies ready"

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

# Ensure home directory exists with correct permissions
mkdir -p "${ZFSNAS_HOME}" "${ZFSNAS_CONFIG}"
chown -R "${ZFSNAS_USER}:${ZFSNAS_USER}" "${ZFSNAS_HOME}"

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
success ".bashrc written"

# Also write .profile so login shells source .bashrc
cat > "${ZFSNAS_HOME}/.profile" << 'PROFILE'
# ~/.profile
[[ -f ~/.bashrc ]] && . ~/.bashrc
PROFILE
chown "${ZFSNAS_USER}:${ZFSNAS_USER}" "${ZFSNAS_HOME}/.profile"

# ── Sudoers ───────────────────────────────────────────────────────────────────
header "Configuring sudo access"

cat > "${SUDOERS_FILE}" << SUDOERS
# ZFS NAS Portal — passwordless sudo required for ZFS, Samba, NFS, SMART, and power commands
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
header "Downloading ZFS NAS binary"

info "Fetching latest release from GitHub…"
RELEASE_JSON=$(curl -fsSL "${GITHUB_API}" 2>/dev/null) || fatal "Could not reach GitHub API. Check your internet connection."

# Extract the first .tar.gz or bare binary download URL
DOWNLOAD_URL=$(echo "${RELEASE_JSON}" \
  | grep '"browser_download_url"' \
  | grep -v '\.sha256\|\.md5\|\.txt' \
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
if file "${TMPFILE}" | grep -q 'gzip\|tar'; then
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
Description=ZFS NAS Management Portal
Documentation=https://github.com/${GITHUB_REPO}
After=network.target

[Service]
Type=simple
User=${ZFSNAS_USER}
Group=${ZFSNAS_USER}
WorkingDirectory=${ZFSNAS_HOME}
ExecStart=${ZFSNAS_BIN}
Restart=on-failure
RestartSec=5

# Give the process time to bind its TLS port on startup
TimeoutStartSec=30

# Harden the service a little (compatible with sudo usage)
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable zfsnas
systemctl restart zfsnas
success "Service enabled and started"

# ── Detect IP for setup URL ───────────────────────────────────────────────────
SETUP_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1 || echo "YOUR-SERVER-IP")

# ── Done ──────────────────────────────────────────────────────────────────────
echo
echo -e "${GREEN}$(printf '═%.0s' {1..60})${RESET}"
echo -e "${BOLD}${GREEN}  ZFS NAS Portal installed successfully!${RESET}"
echo -e "${GREEN}$(printf '═%.0s' {1..60})${RESET}"
echo
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
