#!/bin/sh
# Install SkillSentry's command, skill-sentry-cli, from a published release.
#
#   sh install.sh                    install the pinned version, then run `skill-sentry-cli setup`
#   sh install.sh --no-setup         install only
#   sh install.sh --upgrade          reinstall the pinned version over an existing install
#   sh install.sh --version 2.1.0rc1 install a different published version
#   sh install.sh --wheel PATH       install a local wheel instead of downloading (no checksum)
#   sh install.sh --dry-run          show what would be done; download and install nothing
#   sh install.sh --uninstall        remove the command; your data is kept
#
# SKILL_SENTRY_RELEASE_URL overrides where the release files are fetched from (mirrors).
# No sudo.  Nothing is installed outside your home directory.  Python 3.11 to 3.13 is required.
# On native Windows, use install.ps1 instead (this script runs in Git Bash or WSL).
set -eu

VERSION="2.1.1rc1"
REPO="EmberPhantom/SkillSentry"
HOME_DIR="${SKILL_SENTRY_HOME:-$HOME/.local/share/skill-sentry-cli}"
BIN_DIR="$HOME/.local/bin"
BASE_URL_OVERRIDE="${SKILL_SENTRY_RELEASE_URL:-}"

run_setup=1
mode=install
dry_run=0
local_wheel=""

usage() {
  cat <<'EOF'
Usage: sh install.sh [options]

  --no-setup            install only; do not run `skill-sentry-cli setup`
  --upgrade             reinstall over an existing install
  --version VERSION     install a published version (for example 2.1.0rc1)
  --wheel PATH          install a local wheel (its checksum is not verified)
  --dry-run             print the steps and the download URL; change nothing
  --uninstall           remove the command; your scan data is kept
  -h, --help            show this help
EOF
}

die() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --no-setup) run_setup=0 ;;
    --upgrade) mode=install ;;
    --uninstall) mode=uninstall ;;
    --dry-run) dry_run=1 ;;
    --version)
      shift
      [ $# -gt 0 ] || die "--version needs a value, for example --version 2.0.0"
      case "$1" in
        *[!0-9A-Za-z.+-]*|"") die "not a version: $1" ;;
      esac
      VERSION="$1"
      ;;
    --wheel) shift; [ $# -gt 0 ] || die "--wheel needs a path"; local_wheel="$1" ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

WHEEL_NAME="skill_sentry_cli-${VERSION}-py3-none-any.whl"
BASE_URL="${BASE_URL_OVERRIDE:-https://github.com/${REPO}/releases/download/v${VERSION}}"

uninstall() {
  if command -v pipx >/dev/null 2>&1 && pipx list --short 2>/dev/null | grep -q '^skill-sentry-cli '; then
    pipx uninstall skill-sentry-cli
  fi
  rm -f "$BIN_DIR/skill-sentry-cli"
  rm -rf "$HOME_DIR"
  printf 'Removed the skill-sentry-cli command.\n'
  printf 'Kept your data: ~/.skillsentry (scan history, reports) and any skillsentry.toml you wrote.\n'
  printf 'Delete those folders yourself if you no longer need them.\n'
}

os_name() {
  case "$(uname -s 2>/dev/null)" in
    Darwin) printf 'macOS' ;;
    Linux)
      if grep -qi microsoft /proc/version 2>/dev/null; then printf 'WSL'; else printf 'Linux'; fi
      ;;
    *) printf 'this system' ;;
  esac
}

python_hint() {
  case "$(os_name)" in
    macOS) printf 'Install it with Homebrew: brew install python@3.12' ;;
    WSL|Linux) printf 'Install it with your package manager, for example: sudo apt install python3.12 python3.12-venv' ;;
    *) printf 'Install Python 3.12 from https://www.python.org/downloads/' ;;
  esac
}

find_python() {
  for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      if "$candidate" -c 'import sys; sys.exit(0 if (3, 11) <= sys.version_info[:2] <= (3, 13) else 1)' 2>/dev/null; then
        command -v "$candidate"
        return 0
      fi
    fi
  done
  return 1
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

fetch_wheel() {
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  if [ -n "$local_wheel" ]; then
    [ -f "$local_wheel" ] || die "no such wheel: $local_wheel"
    cp "$local_wheel" "$tmp/$WHEEL_NAME"
    printf 'Using local wheel (checksum not verified).\n'
  else
    command -v curl >/dev/null 2>&1 || die "curl is required to download the release"
    curl -fsSL -o "$tmp/$WHEEL_NAME" "$BASE_URL/$WHEEL_NAME" || die "could not download $WHEEL_NAME from $BASE_URL"
    curl -fsSL -o "$tmp/SHA256SUMS" "$BASE_URL/SHA256SUMS" || die "could not download SHA256SUMS from $BASE_URL"
    expected="$(grep " ${WHEEL_NAME}\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
    [ -n "$expected" ] || die "$WHEEL_NAME is not listed in SHA256SUMS"
    actual="$(sha256_of "$tmp/$WHEEL_NAME")"
    [ "$expected" = "$actual" ] || die "checksum mismatch for $WHEEL_NAME; the download is not trusted"
    printf 'Checksum verified.\n'
  fi
  WHEEL_PATH="$tmp/$WHEEL_NAME"
}

# Tell the user the exact line to add, for their shell, instead of a generic hint.
path_hint() {
  # The quoted text below is printed for the user to paste, so it must not expand here.
  # shellcheck disable=SC2016
  line='export PATH="$HOME/.local/bin:$PATH"'
  shell_name="$(basename "${SHELL:-sh}")"
  case "$shell_name" in
    zsh) profile="$HOME/.zshrc" ;;
    bash) profile="$HOME/.bashrc (or $HOME/.bash_profile on macOS)" ;;
    fish)
      printf 'Add %s to your PATH by running: fish_add_path %s\n' "$BIN_DIR" "$BIN_DIR"
      return 0
      ;;
    *) profile="your shell's startup file" ;;
  esac
  printf 'Add %s to your PATH: append this line to %s, then open a new terminal:\n  %s\n' \
    "$BIN_DIR" "$profile" "$line"
}

install_command() {
  if [ "$dry_run" -eq 1 ]; then
    printf 'Dry run. Nothing will be downloaded or installed.\n'
    printf '  version:  %s\n' "$VERSION"
    if [ -n "$local_wheel" ]; then
      [ -f "$local_wheel" ] || die "no such wheel: $local_wheel"
      printf '  wheel:    %s (local, checksum not verified)\n' "$local_wheel"
    else
      printf '  download: %s/%s\n' "$BASE_URL" "$WHEEL_NAME"
      printf '  checksum: %s/SHA256SUMS\n' "$BASE_URL"
    fi
    if command -v pipx >/dev/null 2>&1; then
      printf '  install:  pipx install --force <wheel>\n'
    else
      printf '  install:  private venv at %s\n' "$HOME_DIR"
    fi
    return 0
  fi
  fetch_wheel
  python_bin="$(find_python)" || die "Python 3.11 to 3.13 is required on $(os_name). $(python_hint), then run this again"
  if command -v pipx >/dev/null 2>&1; then
    # Pin pipx to the Python we validated; otherwise it may pick a newer, unsupported one.
    pipx install --force --python "$python_bin" "$WHEEL_PATH"
  else
    mkdir -p "$HOME_DIR" "$BIN_DIR"
    "$python_bin" -m venv "$HOME_DIR/venv"
    "$HOME_DIR/venv/bin/python" -m pip install --quiet --upgrade --force-reinstall "$WHEEL_PATH"
    ln -sf "$HOME_DIR/venv/bin/skill-sentry-cli" "$BIN_DIR/skill-sentry-cli"
  fi
  printf 'Installed skill-sentry-cli %s.\n' "$VERSION"
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) path_hint ;;
  esac
}

if [ "$mode" = "uninstall" ]; then
  uninstall
  exit 0
fi

install_command

if [ "$dry_run" -eq 1 ]; then
  exit 0
fi

if [ "$run_setup" -eq 1 ]; then
  if command -v skill-sentry-cli >/dev/null 2>&1; then
    skill-sentry-cli setup || printf 'Setup did not finish. Fix the lines above, then run: skill-sentry-cli setup\n'
  else
    printf 'Open a new terminal, then run: skill-sentry-cli setup\n'
  fi
fi
