#!/usr/bin/env bash
#
# install.sh — build system-patch and link it into ~/.local/bin.
#
# Links rather than copies, so `git pull && go build` updates the installed
# command without a reinstall step.
#
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${XDG_BIN_HOME:-$HOME/.local/bin}"

info() { printf '\033[1;34m▸\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!\033[0m %s\n' "$*"; }

command -v go >/dev/null || { echo "system-patch: go is required to build" >&2; exit 1; }

info "building"
( cd "$HERE" && go build -trimpath -ldflags='-s -w' -o system-patch . )

mkdir -p "$BIN"
ln -sfn "$HERE/system-patch" "$BIN/system-patch"
ok "linked $BIN/system-patch"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) warn "$BIN is not on PATH" ;;
esac

# Report missing optional tooling rather than failing on it. Each one costs a
# category of information, not correctness, so the right response is to say
# what will be missing and let the user decide.
declare -A opt=(
  [checkupdates]="pacman-contrib — repo updates"
  [paru]="paru — AUR updates"
  [arch-audit]="arch-audit — Security Tracker CVEs"
  [gh]="github-cli — raises the GitHub API rate limit"
  [claude]="claude-code — source analysis with 'a'"
)
missing=()
for cmd in "${!opt[@]}"; do
  command -v "$cmd" >/dev/null || missing+=("  ${opt[$cmd]}")
done
if ((${#missing[@]})); then
  warn "optional tooling not found:"
  printf '%s\n' "${missing[@]}"
fi

ok "run: system-patch"
