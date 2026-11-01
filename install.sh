#!/bin/sh
# Install SkillSentry's command, skill-sentry-cli, from a published release.
#
#   sh install.sh                 install the pinned version, then run `skill-sentry-cli setup`
#   sh install.sh --no-setup      install only
#   sh install.sh --upgrade       reinstall the pinned version over an existing install
#   sh install.sh --uninstall     remove the command; your data is kept
#   sh install.sh --wheel PATH    install a local wheel instead of downloading (no checksum)
#
# SKILL_SENTRY_RELEASE_URL overrides where the release files are fetched from (mirrors).
# No sudo.  Nothing is installed outside your home directory.  Python 3.11 to 3.13 is required.
set -eu

VERSION="2.0.0rc1"
REPO="EmberPhantom/SkillSentry"
HOME_DIR="${SKILL_SENTRY_HOME:-$HOME/.local/share/skill-sentry-cli}"
BIN_DIR="$HOME/.local/bin"
WHEEL_NAME="skill_sentry_cli-${VERSION}-py3-none-any.whl"
BASE_URL="${SKILL_SENTRY_RELEASE_URL:-https://github.com/${REPO}/releases/download/v${VERSION}}"

run_setup=1
mode=install
local_wheel=""

usage() {
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
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
    --wheel) shift; [ $# -gt 0 ] || die "--wheel needs a path"; local_wheel="$1" ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

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
    curl -fsSL -o "$tmp/$WHEEL_NAME" "$BASE_URL/$WHEEL_NAME" || die "could not download $WHEEL_NAME"
    curl -fsSL -o "$tmp/SHA256SUMS" "$BASE_URL/SHA256SUMS" || die "could not download SHA256SUMS"
    expected="$(grep " ${WHEEL_NAME}\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
    [ -n "$expected" ] || die "$WHEEL_NAME is not listed in SHA256SUMS"
    actual="$(sha256_of "$tmp/$WHEEL_NAME")"
    [ "$expected" = "$actual" ] || die "checksum mismatch for $WHEEL_NAME; the download is not trusted"
    printf 'Checksum verified.\n'
  fi
  WHEEL_PATH="$tmp/$WHEEL_NAME"
}

install_command() {
  fetch_wheel
  if command -v pipx >/dev/null 2>&1; then
    pipx install --force "$WHEEL_PATH"
  else
    python_bin="$(find_python)" || die "Python 3.11 to 3.13 is required; install one, then run this again"
    mkdir -p "$HOME_DIR" "$BIN_DIR"
    "$python_bin" -m venv "$HOME_DIR/venv"
    "$HOME_DIR/venv/bin/python" -m pip install --quiet --upgrade --force-reinstall "$WHEEL_PATH"
    ln -sf "$HOME_DIR/venv/bin/skill-sentry-cli" "$BIN_DIR/skill-sentry-cli"
  fi
  printf 'Installed skill-sentry-cli %s.\n' "$VERSION"
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) printf 'Add %s to your PATH, for example: export PATH="$HOME/.local/bin:$PATH"\n' "$BIN_DIR" ;;
  esac
}

if [ "$mode" = "uninstall" ]; then
  uninstall
  exit 0
fi

install_command

if [ "$run_setup" -eq 1 ]; then
  if command -v skill-sentry-cli >/dev/null 2>&1; then
    skill-sentry-cli setup || printf 'Setup did not finish. Fix the lines above, then run: skill-sentry-cli setup\n'
  else
    printf 'Open a new terminal, then run: skill-sentry-cli setup\n'
  fi
fi
