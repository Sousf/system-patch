# system-patch

A TUI tool that helps you determine whether to install a package update.

```
system-patch 47 updates · 5 flagged

❯ ● google-chrome           │ google-chrome  aur
    151.0.7922.71-1 → 152…  │ 151.0.7922.71-1  →  152.0.7977.64-1
  ● libheif                 │
    1.23.1-4 → 1.23.2-1  …  │ chromereleases.googleblog.com  security
  ● linux                   │ 395 CVEs · 19 Critical · 120 High · 184 Medium
    7.1.9.arch1-2 → 7.1.1…  │
  ● linux-lts               │ ▌ 152.0.7977.64   2026-08-25
    6.18.46-1 → 6.18.48-1…  │   CVE-2026-78891, CVE-2026-78892, … +324 more
  ● openssl                 │   327 security fixes
```

system-patch finds every package manager on the machine and lists what each one
has pending, one tab per manager.

`a` on a row sends an agent to the source of that update: the release page, the
commit range, the PKGBUILD diff. It comes back with the CVEs the update closes,
what the patch notes claim, a read of the diff itself, and a verdict on whether
to install.

## Install

On Arch:

```sh
paru -S system-patch
```

Anywhere else, with Go 1.27+:

```sh
go install github.com/Sousf/system-patch@latest
```

Linux amd64 and arm64 binaries are attached to every release.

From a checkout, `./install.sh` builds and symlinks into `~/.local/bin`, so
`git pull && go build` updates the installed command with no reinstall step.

## Requirements

| Tool                | Provides         | Without it                     |
| ------------------- | ---------------- | ------------------------------ |
| `gh` (optional)     | GitHub API token | 60 req/hour instead of 5000    |
| `claude` (optional) | source analysis  | `a` reports the CLI is missing |

On Arch, three more: `pacman-contrib` for `checkupdates`, without which no repo
updates are listed; `paru` for AUR updates; `arch-audit` for Security Tracker
CVEs, without which repo updates show no advisories.

## Other distributions

Arch is the most complete. Debian, Ubuntu and Fedora list and upgrade, and the
agent gets the right database paths and read-only tools for the system it is
on. openSUSE, Alpine, Void and Gentoo are upgraded but not itemised.

The analysis names the running distribution and never describes a tool or path
it has not confirmed exists. Where the dependency graph cannot be read, the analysis summary will state this is the case.

To read a brief for a system you are not on:

```sh
SYSTEM_PATCH_DISTRO=ubuntu system-patch prompt <pkg>
```

## Usage

```
system-patch                interactive browser
system-patch list           one line per pending update
system-patch json           same data as JSON, for bar modules and scripts
system-patch count          number of flagged updates; exits 1 if any
system-patch notes <pkg>    release notes for one package
system-patch analyse <pkg>  run the source analysis headlessly
system-patch prompt <pkg>   print the agent's brief without running it
```

Keys: `↑↓`/`jk` move, `←→`/`hl` switch manager tab, `space` mark a row and `c`
clear the marks, `a` analyse the source, `A` re-analyse ignoring the stored
answer, `i` install what is selected, `r` reload notes, `R` rescan, `enter`
focus the right pane and `esc` come back, `x` cancel a running agent, `q` quit.

`a` and `i` act on every marked row, or on the row under the cursor when
nothing is marked. Several analyses run at once; the title counts them and each
running row shows a spinner.
Notes are cached under `XDG_CACHE_HOME` keyed by `name@old..new`.

## Maintainer tracking

On the first run of system-patch the tool records who maintains each AUR package. Later
runs compare against that baseline and flag anything that changed hands.

## Agent analysis

`a` launches a Claude Code process and gives it the package identity, both versions, the forge URL, a
diff URL, any tracker CVEs and the provenance history, then asks for: what
changed, why it was pushed, security impact, a supply-chain check of the diff,
regression risk, and a verdict.

`Edit`, `Write`, `sudo` and every package manager on the machine are denied,
`apt` and `dnf` included. It runs in a scratch directory that is deleted
afterwards.

It does get general shell access through Bash for unpacking and grepping
diffs. The containment is the scratch directory and the denied tools.

`system-patch prompt <pkg>` prints the brief without spending a token, so you can
read what is being asked before trusting what comes back.

### Model and cost

Pinned to `claude-sonnet-5`.

Effort is the second dial and scales with what is at stake: `high` for CVEs or
a maintainer change, `medium` for routine bumps.

Analyses are cached by version pair. `A` in the
interface re-runs anyway; `SYSTEM_PATCH_FORCE=1` does the same on the command
line. Override either setting:

```sh
SYSTEM_PATCH_MODEL=claude-opus-5 system-patch analyse foo
SYSTEM_PATCH_EFFORT=max system-patch analyse foo
```

### Reading the result

Every analysis opens the same way:

```
Package name — what it is
  Two or three plain sentences on what the software actually does. Written for
  someone who has never heard of it.

VERDICT: INSTALL NOW
  One sentence of why.

Breaks: NOTHING
```

The **Breaks** line is answered from research data. system-patch reads
the local database first and hands the agent the reverse dependencies, which of
them came from the AUR, and whether the
update moves a library soname:

```
required by:  swayimg
optional for: gdk-pixbuf2 glycin imagemagick
no soname changes: libheif.so=1-64
```

When `libfoo.so=1` becomes `libfoo.so=2`, everything linked against the old one
stops loading until it is rebuilt. A system upgrade rebuilds repository
packages together, so they are fine; **AUR packages are not rebuilt for you**,
which is why the casualties are almost always the foreign ones. system-patch
computes that comparison itself — it is an exact diff of two lists.

The interface pins the verdict above the pane, coloured by urgency, so it stays
visible while you scroll the evidence. Markdown is rendered, furthermore you can also pipe the output to a file to record the markdown data somewhere else:

```sh
system-patch analyse libheif > libheif.md
```

## The full system upgrade row

The first row of the list is an option to do a full system scan.
From the command line: `system-patch analyse system`.

## Installing

`i` installs what you have selected, after showing exactly what it will run.
Mark several rows with space and it installs all of them.

| Selected             | Runs                                     |
| -------------------- | ---------------------------------------- |
| an AUR package       | `paru -S <name>`                         |
| a flatpak ref        | `flatpak update <app>`                   |
| a snap               | `sudo snap refresh <name>`               |
| a repository package | one-package upgrade, per distribution    |
| the system row       | the full upgrade, every manager in order |

The repository row depends on the distribution. Debian runs `apt-get install
--only-upgrade`, Fedora `dnf upgrade <name>`, openSUSE `zypper update <name>`.

Arch has no safe equivalent: fetching a newer repository package means syncing
the database, and installing from a synced database is a partial upgrade. `i`
says so and does nothing. Select the full system upgrade row to take
everything.

## License

MIT. See [LICENSE](LICENSE).
