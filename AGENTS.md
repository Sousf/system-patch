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

## Learned by MARSHAL

Facts recorded by MARSHAL from its own runs, reviewed in the pull requests that added them.

- Some tests in `internal/ui` and `internal/sources` call `sources.Host()`, which reads the machine running the tests, so results can differ between an Arch workstation and the Ubuntu CI runner.
- CI installs exactly the Go version in `go.mod`'s `go` line (currently `1.27.0`) with `GOTOOLCHAIN=local`, so `govulncheck` in CI can report standard-library vulnerabilities that a newer local Go patch release doesn't show.
- `go.mod` has a `toolchain` line, and the pinned `actions/setup-go` installs that version (instead of the `go` line's version) when it is present. So CI's Go patch release follows the `toolchain` line, which is currently `go1.27.2`.
- `golang.org/x/net` v0.60.0 requires `golang.org/x/text` ≥ v0.42.0, `golang.org/x/sys` ≥ v0.48.0 and `golang.org/x/term` ≥ v0.46.0, so bumping x/net also bumps those modules.
- The vulnerability workflow in `.github/workflows/ci.yml` runs `govulncheck` after `actions/setup-go` with `go-version-file: go.mod`. A reachable standard-library finding is therefore fixed by raising the `toolchain` line in `go.mod`.
