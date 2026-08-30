package sources

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Sousf/system-patch/internal/model"
)

// Manager is one package manager detected on this machine.
//
// "Full system upgrade" is only an honest phrase if it names everything that
// installs software here, and that set differs per machine. So the registry
// below is a declarative table of managers system-patch knows how to drive, and
// which of them exist is decided at runtime by Detect. Nothing is hardcoded to
// Arch: the same binary on a Debian or Fedora box finds apt or dnf instead,
// and adding another manager is one entry, not a new code path.
//
// Truly open-ended discovery is not possible — you cannot infer how to safely
// update a tool you have never heard of — so the honest design is a wide table
// plus an explicit account of what is left over (see Unmanaged).
type Manager struct {
	// Name as shown to the user.
	Name string
	// Detect reports whether this manager is present and in use here.
	Detect func() bool
	// Upgrade updates everything it owns, without prompting.
	Upgrade []string
	// List returns pending updates. Nil when there is no cheap way to ask,
	// in which case the manager is still upgraded but its contents are not
	// itemised.
	List func() []model.Update
	// Note explains what it covers, and why it is not listed when List is nil.
	Note string
	// Origin is the single origin this manager reports, left empty when it
	// reports more than one. Declared rather than inferred from what happens
	// to be pending: an Arch machine with no AUR updates outstanding today
	// still must not relabel its repository tab.
	Origin model.Origin
	// Verified records whether this entry has been exercised on a real machine.
	// The unverified ones are written from each tool's documented output and
	// parse defensively: a format that does not match yields no rows rather
	// than wrong ones.
	Verified bool
}

// Registry returns every manager this tool can drive, detected or not.
//
// Managers() answers "what is on this machine"; this answers "what does the
// table claim", which is what a test asserting a property of the table needs.
func Registry() []Manager { return registry }

func has(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// HasBin reports whether a command exists on PATH, for callers outside this
// package that need to state a fact about the machine rather than guess at it.
func HasBin(cmd string) bool { return has(cmd) }

func bin(cmd string) func() bool {
	return func() bool { return has(cmd) }
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func dirHasEntries(p string) bool {
	e, err := os.ReadDir(p)
	return err == nil && len(e) > 0
}

func home(rest ...string) string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(append([]string{h}, rest...)...)
}

// simple builds updates from a line-oriented command output.
//
// parse returns name, current, next for one line, or ok=false to skip it.
// Skipping rather than guessing is deliberate: every one of these tools prints
// headers, warnings and progress lines mixed in with data.
func simple(origin model.Origin, out string, parse func(string) (string, string, string, bool)) []model.Update {
	var ups []model.Update
	for _, line := range strings.Split(out, "\n") {
		if name, cur, next, ok := parse(line); ok {
			ups = append(ups, model.Update{
				Name: name, Cur: cur, New: next, Origin: origin,
			})
		}
	}
	return ups
}

// registry is every manager system-patch can drive, in upgrade order: system
// packages first, because everything else may link against them.
var registry = []Manager{
	// ── system package managers ──────────────────────────────────────────
	{
		Name:     "pacman + AUR",
		Detect:   bin("paru"),
		Upgrade:  []string{"paru", "-Syu"},
		List:     func() []model.Update { return append(RepoUpdates(), AURUpdates()...) },
		Note:     "repository and AUR packages, in one transaction",
		Verified: true,
	},
	{
		Name:     "pacman + AUR",
		Detect:   func() bool { return !has("paru") && has("yay") },
		Upgrade:  []string{"yay", "-Syu"},
		List:     func() []model.Update { return append(RepoUpdates(), AURUpdates()...) },
		Note:     "repository and AUR packages, in one transaction",
		Verified: false,
	},
	{
		Name:     "pacman",
		Detect:   func() bool { return has("pacman") && !has("paru") && !has("yay") },
		Upgrade:  []string{"sudo", "pacman", "-Syu"},
		List:     RepoUpdates,
		Origin:   model.Repo,
		Note:     "repository packages only; no AUR helper installed",
		Verified: true,
	},
	{
		Name:    "apt",
		Detect:  func() bool { return has("apt-get") && fileExists("/etc/debian_version") },
		Upgrade: []string{"sudo", "apt-get", "-y", "dist-upgrade"},
		List:    aptUpdates,
		Origin:  model.Repo,
		Note:    "Debian and Ubuntu system packages",
	},
	{
		Name:    "dnf",
		Detect:  bin("dnf"),
		Upgrade: []string{"sudo", "dnf", "-y", "upgrade"},
		List:    dnfUpdates,
		Origin:  model.Repo,
		Note:    "Fedora and RHEL system packages",
	},
	{
		Name:    "zypper",
		Detect:  bin("zypper"),
		Upgrade: []string{"sudo", "zypper", "--non-interactive", "update"},
		Note:    "openSUSE system packages; not listed, no stable machine-readable form",
	},
	{
		Name:    "apk",
		Detect:  func() bool { return has("apk") && fileExists("/etc/alpine-release") },
		Upgrade: []string{"sudo", "apk", "upgrade"},
		Note:    "Alpine system packages",
	},
	{
		Name:    "xbps",
		Detect:  bin("xbps-install"),
		Upgrade: []string{"sudo", "xbps-install", "-Syu"},
		Note:    "Void system packages",
	},
	{
		Name:    "portage",
		Detect:  bin("emerge"),
		Upgrade: []string{"sudo", "emerge", "--update", "--deep", "@world"},
		Note:    "Gentoo world set; this one compiles, so expect it to be slow",
	},
	{
		Name:    "nix",
		Detect:  bin("nix"),
		Upgrade: []string{"nix", "profile", "upgrade", "--all"},
		Note:    "packages in the Nix profile; does not touch a system flake",
	},
	{
		Name:    "homebrew",
		Detect:  bin("brew"),
		Upgrade: []string{"brew", "upgrade"},
		Note:    "Homebrew formulae and casks",
	},

	// ── cross-distro application managers ────────────────────────────────
	{
		Name:     "flatpak",
		Detect:   FlatpakAvailable,
		Upgrade:  []string{"flatpak", "update"},
		List:     FlatpakUpdates,
		Origin:   model.Flatpak,
		Note:     "flatpak apps and runtimes, from their own remotes",
		Verified: true,
	},
	{
		Name:    "snap",
		Detect:  bin("snap"),
		Upgrade: []string{"sudo", "snap", "refresh"},
		List:    snapUpdates,
		Origin:  model.Snap,
		Note:    "snap packages",
	},

	// ── language and tool managers ───────────────────────────────────────
	{
		Name:    "pipx",
		Detect:  bin("pipx"),
		Upgrade: []string{"pipx", "upgrade-all"},
		Note:    "Python applications installed with pipx",
	},
	{
		Name:    "cargo",
		Detect:  bin("cargo-install-update"),
		Upgrade: []string{"cargo", "install-update", "-a"},
		Note:    "binaries from `cargo install`, refreshed by cargo-update",
	},
	{
		Name:    "rustup",
		Detect:  bin("rustup"),
		Upgrade: []string{"rustup", "update"},
		Note:    "Rust toolchains",
	},
	{
		Name:    "mise",
		Detect:  bin("mise"),
		Upgrade: []string{"mise", "upgrade"},
		Note:    "tools managed by mise",
	},

	// ── editor and shell frameworks ──────────────────────────────────────
	{
		// Neovim 0.12's built-in manager. force skips the confirmation buffer,
		// which never appears under --headless and would otherwise hang.
		Name: "neovim (vim.pack)",
		Detect: func() bool {
			return has("nvim") &&
				dirHasEntries(home(".local", "share", "nvim", "site", "pack", "core", "opt"))
		},
		Upgrade: []string{"nvim", "--headless",
			"+lua vim.pack.update(nil, {force=true})", "+qa"},
		Note: "editor plugins; not listed because checking for pending updates " +
			"means a git fetch per plugin",
		Verified: true,
	},
	{
		Name: "neovim (lazy.nvim)",
		Detect: func() bool {
			return has("nvim") && dirHasEntries(home(".local", "share", "nvim", "lazy"))
		},
		Upgrade: []string{"nvim", "--headless", "+Lazy! sync", "+qa"},
		Note:    "editor plugins managed by lazy.nvim",
	},
	{
		Name:     "oh-my-zsh",
		Detect:   func() bool { return fileExists(home(".oh-my-zsh", "tools", "upgrade.sh")) },
		Upgrade:  []string{home(".oh-my-zsh", "tools", "upgrade.sh")},
		Note:     "shell framework and its plugins; the script is non-interactive by default",
		Verified: true,
	},
}

var (
	managersOnce sync.Once
	managersList []Manager
)

// Managers returns the managers actually present here, in upgrade order.
//
// Resolved once per process. Detection shells out — FlatpakAvailable runs
// `flatpak list` — and the interface calls this while rendering, which happens
// on every spinner frame. Re-detecting each time spawned subprocesses faster
// than they could finish and wedged the UI on its loading screen.
func Managers() []Manager {
	managersOnce.Do(func() {
		for _, m := range registry {
			if m.Detect != nil && m.Detect() {
				managersList = append(managersList, m)
			}
		}
	})
	return managersList
}

// ManagerUpdates asks every detected manager that can enumerate for its
// pending set, concurrently.
func ManagerUpdates() []model.Update {
	ms := Managers()
	results := make([][]model.Update, len(ms))
	var wg sync.WaitGroup
	for i, m := range ms {
		if m.List == nil {
			continue
		}
		wg.Add(1)
		go func(i int, list func() []model.Update) {
			defer wg.Done()
			results[i] = list()
		}(i, m.List)
	}
	wg.Wait()

	// Stamped here because this is the last point that knows which manager
	// produced which rows. The enumerators themselves cannot: RepoUpdates and
	// AURUpdates are shared by the three pacman entries, so no List function
	// knows the name of the registry entry that called it.
	var all []model.Update
	for i, r := range results {
		for _, u := range r {
			u.Manager = ms[i].Name
			all = append(all, u)
		}
	}
	return all
}

// ── enumerators for managers not present on the development machine ──────
//
// Each is written from the tool's documented output and parses defensively:
// anything that does not match the expected shape is skipped, so an unexpected
// format produces an empty list rather than invented rows.

// aptUpdates parses `apt list --upgradable`:
//
//	zlib1g/noble 1:1.3.dfsg-3.1 amd64 [upgradable from: 1:1.3.dfsg-3]
func aptUpdates() []model.Update {
	out := run(3*time.Minute, "apt", "list", "--upgradable")
	return simple(model.Repo, out, func(line string) (string, string, string, bool) {
		name, rest, ok := strings.Cut(line, "/")
		if !ok || strings.Contains(name, " ") {
			return "", "", "", false
		}
		f := strings.Fields(rest)
		if len(f) < 2 {
			return "", "", "", false
		}
		cur := "installed"
		if i := strings.Index(line, "upgradable from: "); i >= 0 {
			cur = strings.TrimRight(line[i+len("upgradable from: "):], "]")
		}
		return name, cur, f[1], true
	})
}

// dnfUpdates parses `dnf -q check-update`:
//
//	zlib.x86_64    1.3.1-2.fc41    updates
//
// Exit status 100 means updates are available, which run() already tolerates.
func dnfUpdates() []model.Update {
	out := run(3*time.Minute, "dnf", "-q", "check-update")
	return simple(model.Repo, out, func(line string) (string, string, string, bool) {
		f := strings.Fields(line)
		if len(f) != 3 || !strings.Contains(f[0], ".") || strings.HasSuffix(line, ":") {
			return "", "", "", false
		}
		name, _, _ := strings.Cut(f[0], ".")
		return name, "installed", f[1], true
	})
}

// snapUpdates parses `snap refresh --list`, whose first line is a header.
func snapUpdates() []model.Update {
	out := run(3*time.Minute, "snap", "refresh", "--list")
	return simple(model.Snap, out, func(line string) (string, string, string, bool) {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] == "Name" {
			return "", "", "", false
		}
		return f[0], "installed", f[1], true
	})
}

var (
	unmanagedOnce sync.Once
	unmanagedList []string
)

// Unmanaged names software installed outside any manager that can update it.
//
// Reported rather than fixed. Each was installed by a command that recorded no
// manifest, so there is nothing to re-run. Saying so is more useful than a
// silent gap, because the alternative is believing a full upgrade covered them.
func Unmanaged() []string {
	unmanagedOnce.Do(func() { unmanagedList = scanUnmanaged() })
	return unmanagedList
}

// scanUnmanaged does the work Unmanaged memoises; it runs npm, so it is not
// something to repeat on every frame either.
func scanUnmanaged() []string {
	var out []string
	if dirHasEntries(home("go", "bin")) {
		out = append(out, "~/go/bin — installed by `go install`, which keeps no "+
			"manifest; re-run the original install command to update")
	}
	if dirHasEntries(home(".cargo", "bin")) && !has("cargo-install-update") {
		out = append(out, "~/.cargo/bin — `cargo install` binaries; install "+
			"cargo-update to refresh them in one command")
	}
	if dirHasEntries(home(".nvm", "versions", "node")) {
		out = append(out, "nvm — a Node version manager, not a package manager; "+
			"`nvm install --lts` moves to a newer runtime")
	}
	if dirHasEntries(home(".local", "share", "claude", "versions")) {
		out = append(out, "claude CLI — updates itself")
	}
	if j := npmGlobals(); j != "" {
		out = append(out, j)
	}
	return out
}

// npmGlobals reports globally installed npm packages worth mentioning.
//
// npm and corepack ship with Node itself and move with the runtime, so a
// machine with only those has nothing to update and is not worth a line.
func npmGlobals() string {
	out := run(60*time.Second, "npm", "ls", "-g", "--depth=0", "--json")
	if strings.TrimSpace(out) == "" {
		return ""
	}
	var doc struct {
		Dependencies map[string]any `json:"dependencies"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return ""
	}
	var names []string
	for n := range doc.Dependencies {
		if n == "npm" || n == "corepack" {
			continue
		}
		names = append(names, n)
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return "npm globals (" + strings.Join(names, ", ") +
		") — `npm update -g` refreshes them"
}
