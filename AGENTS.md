# AGENTS.md

system-patch is a Go TUI (bubbletea) that lists pending package updates per
package manager and can send a Claude Code agent to analyse one. Linux only.

## Build and test

Go version comes from `go.mod` (currently 1.27).

    go vet ./...
    go build ./...
    go test ./...
    go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

CI (`.github/workflows/ci.yml`) runs the same commands on every pull request.

## Layout

- `main.go` — CLI entry point and subcommands (`list`, `json`, `analyse`, ...)
- `internal/sources/` — package manager detection and update listing
- `internal/agent/` — the analysis brief and the Claude Code process
- `internal/ui/` — the interactive browser
- `internal/render/`, `internal/model/`, `internal/cache/`, `internal/adapters/`
- `install.sh` — local build and symlink into `~/.local/bin`
- `packaging/aur/` — AUR PKGBUILDs

## Do not touch

- `.github/workflows/release.yml` and `.goreleaser.yaml` — tag-triggered
  release that publishes binaries.
- `packaging/aur/` — AUR packaging; `pkgver` and checksums are set at
  release time.
- `demo.tape` — recorded by hand with vhs against a live machine.
